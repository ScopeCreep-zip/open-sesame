//! mDNS query listener with amplification defence.
//!
//! Listens for PTR queries for `_opensesame._udp.local.` on the multicast
//! socket. Responds only to queries from private/link-local addresses.
//! Per-source rate limiting prevents amplification attacks.

use super::announce::{self, SERVICE_TYPE};
use super::packet::{DnsPacket, RecordType};
use super::socket;
use dashmap::DashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

/// Per-source rate limit: max responses per second.
const MAX_RESPONSES_PER_SEC: u32 = 10;

/// Discovered peer from an mDNS announcement.
#[derive(Debug, Clone)]
pub struct MdnsPeer {
    /// X25519 public key hex from TXT record.
    pub pubkey_hex: String,
    /// Installation ID from TXT record.
    pub installation_id: String,
    /// Resolved socket address (IP from A/AAAA + port from SRV).
    pub addr: SocketAddr,
    /// When this peer was last seen.
    pub last_seen: Instant,
}

/// Rate limiter tracking per-source response timestamps.
struct SourceRateLimiter {
    last_response: DashMap<Ipv4Addr, (Instant, u32)>,
}

impl SourceRateLimiter {
    fn new() -> Self {
        Self {
            last_response: DashMap::new(),
        }
    }

    /// Check if we should respond to this source. Returns `true` if allowed.
    fn check(&self, source: Ipv4Addr) -> bool {
        let now = Instant::now();
        let mut entry = self.last_response.entry(source).or_insert((now, 0));
        let (last, count) = entry.value_mut();

        if now.duration_since(*last).as_secs() >= 1 {
            *last = now;
            *count = 1;
            true
        } else if *count < MAX_RESPONSES_PER_SEC {
            *count += 1;
            true
        } else {
            false
        }
    }
}

/// Run the mDNS listener loop.
///
/// Processes incoming mDNS packets on the multicast socket:
/// - PTR queries for `_opensesame._udp.local.` → respond with our records
/// - Announcements from other peers → extract peer info and report via channel
///
/// # Errors
///
/// Returns `std::io::Error` on unrecoverable socket errors.
/// Grouped parameters for the mDNS listen loop.
pub struct MdnsListenConfig {
    /// Our X25519 public key (32 bytes).
    pub our_pubkey: [u8; 32],
    /// Our installation ID string.
    pub our_install_id: String,
    /// Our listen port.
    pub our_port: u16,
    /// Our IPv4 address (for A record responses).
    pub our_ipv4: Option<Ipv4Addr>,
    /// SRV record TTL.
    pub srv_ttl: u32,
    /// PTR record TTL.
    pub ptr_ttl: u32,
}

pub async fn mdns_listen_loop(
    socket: Arc<UdpSocket>,
    config: MdnsListenConfig,
    peer_tx: tokio::sync::mpsc::Sender<MdnsPeer>,
) {
    let MdnsListenConfig {
        our_pubkey,
        our_install_id,
        our_port,
        our_ipv4,
        srv_ttl,
        ptr_ttl,
    } = config;
    let rate_limiter = SourceRateLimiter::new();
    let mut buf = vec![0u8; 1500];

    loop {
        // Non-blocking recv on the multicast socket. The socket is set to
        // non-blocking in mdns::socket::bind_mdns_v4, so WouldBlock is normal.
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "mDNS recv error");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let Some(packet) = DnsPacket::parse(&buf[..len]) else {
            continue;
        };

        // Source address validation (amplification defence).
        let src_ip = match src {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => continue, // IPv6 mDNS handled separately
        };

        if !socket::is_private_v4(&src_ip) {
            tracing::trace!(%src_ip, "mDNS: dropped non-private source");
            continue;
        }

        // Is this a query for our service type?
        let is_our_query = packet.questions.iter().any(|q| {
            q.qtype == RecordType::PTR as u16
                && q.name.trim_end_matches('.') == SERVICE_TYPE.trim_end_matches('.')
        });

        if is_our_query && (packet.flags & 0x8000) == 0 {
            // It's a query (not a response). Rate-limit and respond.
            if rate_limiter.check(src_ip) {
                let response = announce::build_announcement(
                    &our_pubkey,
                    &our_install_id,
                    our_port,
                    our_ipv4,
                    srv_ttl,
                    ptr_ttl,
                );
                if let Err(e) = announce::send_multicast(&socket, &response) {
                    tracing::warn!(error = %e, "mDNS response send failed");
                }
            } else {
                tracing::trace!(%src_ip, "mDNS: rate-limited response");
            }
        }

        // Is this a response containing our service type records?
        if (packet.flags & 0x8000) != 0 {
            // Parse peer info from response records.
            if let Some(peer) = extract_peer(&packet, src) {
                let _ = peer_tx.try_send(peer);
            }
        }
    }
}

/// Extract peer information from an mDNS response packet.
fn extract_peer(packet: &DnsPacket, source: SocketAddr) -> Option<MdnsPeer> {
    let all_records: Vec<_> = packet
        .answers
        .iter()
        .chain(&packet.additional)
        .collect();

    // Find TXT record with pubkey and iid.
    let mut pubkey_hex = None;
    let mut installation_id = None;
    let mut port = None;

    for rr in &all_records {
        if rr.rtype == RecordType::TXT as u16 {
            let pairs = parse_txt_rdata(&rr.rdata);
            for (k, v) in &pairs {
                match k.as_str() {
                    "pubkey" => pubkey_hex = Some(v.clone()),
                    "iid" => installation_id = Some(v.clone()),
                    _ => {}
                }
            }
        }
        if rr.rtype == RecordType::SRV as u16 && rr.rdata.len() >= 6 {
            port = Some(u16::from_be_bytes([rr.rdata[4], rr.rdata[5]]));
        }
    }

    let pubkey = pubkey_hex?;
    let iid = installation_id.unwrap_or_default();
    let port = port.unwrap_or(48627);

    let addr = SocketAddr::new(source.ip(), port);

    Some(MdnsPeer {
        pubkey_hex: pubkey,
        installation_id: iid,
        addr,
        last_seen: Instant::now(),
    })
}

/// Parse TXT record rdata into key-value pairs.
fn parse_txt_rdata(rdata: &[u8]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let len = rdata[offset] as usize;
        offset += 1;
        if offset + len > rdata.len() {
            break;
        }
        if let Ok(entry) = std::str::from_utf8(&rdata[offset..offset + len])
            && let Some((k, v)) = entry.split_once('=')
        {
            pairs.push((k.to_string(), v.to_string()));
        }
        offset += len;
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_txt_rdata_key_value() {
        let mut rdata = Vec::new();
        let entry = b"pubkey=aabbccdd";
        rdata.push(entry.len() as u8);
        rdata.extend_from_slice(entry);
        let entry2 = b"iid=test-id";
        rdata.push(entry2.len() as u8);
        rdata.extend_from_slice(entry2);

        let pairs = parse_txt_rdata(&rdata);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("pubkey".into(), "aabbccdd".into()));
        assert_eq!(pairs[1], ("iid".into(), "test-id".into()));
    }

    #[test]
    fn rate_limiter_allows_burst() {
        let limiter = SourceRateLimiter::new();
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        for _ in 0..MAX_RESPONSES_PER_SEC {
            assert!(limiter.check(ip));
        }
        assert!(!limiter.check(ip));
    }
}
