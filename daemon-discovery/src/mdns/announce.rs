//! mDNS service announcement.
//!
//! Publishes `_opensesame._udp.local.` PTR, SRV, TXT, and A/AAAA records
//! on the multicast group. Instance name is the first 32 hex characters
//! of the X25519 public key (16 bytes, collision probability 1/2^128).
//!
//! Announcement schedule per RFC 6762:
//! 1. Initial: three unsolicited announcements at 0s, 1s, 2s
//! 2. Passive: respond to PTR queries for `_opensesame._udp.local.` only
//! 3. Goodbye: TTL=0 announcement on clean shutdown

use super::packet::{self, DnsPacket};
use super::socket::{MDNS_MULTICAST_V4, MDNS_PORT};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

/// Open Sesame mDNS service type.
pub const SERVICE_TYPE: &str = "_opensesame._udp.local.";

/// Build the instance name from a public key (first 32 hex chars = 16 bytes).
#[must_use]
pub fn instance_name(pubkey: &[u8; 32]) -> String {
    hex::encode(&pubkey[..16])
}

/// Build the full set of announcement records for this instance.
#[must_use]
pub fn build_announcement(
    pubkey: &[u8; 32],
    installation_id: &str,
    port: u16,
    local_ipv4: Option<Ipv4Addr>,
    srv_ttl: u32,
    ptr_ttl: u32,
) -> DnsPacket {
    let inst = instance_name(pubkey);
    let inst_fqdn = format!("{inst}.{SERVICE_TYPE}");
    let host = format!("{inst}.local.");

    let ptr = packet::ptr_record(SERVICE_TYPE, &inst, ptr_ttl);
    let srv = packet::srv_record(&inst_fqdn, &host, port, srv_ttl);
    let txt = packet::txt_record(
        &inst_fqdn,
        &[
            ("pubkey", &hex::encode(pubkey)),
            ("iid", installation_id),
            ("v", "1"),
        ],
        srv_ttl,
    );

    let mut additional = vec![srv, txt];
    if let Some(ip) = local_ipv4 {
        additional.push(packet::a_record(&host, ip, srv_ttl));
    }

    DnsPacket::response(vec![ptr], additional)
}

/// Build a goodbye announcement (TTL=0 on all records).
#[must_use]
pub fn build_goodbye(
    pubkey: &[u8; 32],
    installation_id: &str,
    port: u16,
    local_ipv4: Option<Ipv4Addr>,
) -> DnsPacket {
    build_announcement(pubkey, installation_id, port, local_ipv4, 0, 0)
}

/// Send an mDNS packet to the multicast group.
///
/// # Errors
///
/// Returns `std::io::Error` if the send fails.
pub fn send_multicast(socket: &UdpSocket, packet: &DnsPacket) -> std::io::Result<()> {
    let bytes = packet.serialise();
    let dest = SocketAddrV4::new(MDNS_MULTICAST_V4, MDNS_PORT);
    socket.send_to(&bytes, dest)?;
    Ok(())
}

/// Run the initial announcement schedule: 3 unsolicited announcements
/// at 0s, 1s, 2s intervals.
///
/// # Errors
///
/// Returns `std::io::Error` if any send fails.
pub async fn initial_announce(
    socket: &UdpSocket,
    pubkey: &[u8; 32],
    installation_id: &str,
    port: u16,
    local_ipv4: Option<Ipv4Addr>,
    srv_ttl: u32,
    ptr_ttl: u32,
) -> std::io::Result<()> {
    let packet = build_announcement(pubkey, installation_id, port, local_ipv4, srv_ttl, ptr_ttl);

    send_multicast(socket, &packet)?;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    send_multicast(socket, &packet)?;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    send_multicast(socket, &packet)?;

    tracing::info!(
        instance = %instance_name(pubkey),
        "mDNS initial announcement complete (3 packets)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_name_length() {
        let pubkey = [0xAA; 32];
        let name = instance_name(&pubkey);
        assert_eq!(name.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn instance_name_deterministic() {
        let pubkey = [0xBB; 32];
        assert_eq!(instance_name(&pubkey), instance_name(&pubkey));
    }

    #[test]
    fn announcement_has_ptr_and_additional() {
        let pubkey = [0xCC; 32];
        let packet = build_announcement(
            &pubkey,
            "test-install",
            48627,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            120,
            4500,
        );
        assert_eq!(packet.answers.len(), 1); // PTR
        assert_eq!(packet.additional.len(), 3); // SRV + TXT + A
    }

    #[test]
    fn goodbye_has_zero_ttl() {
        let pubkey = [0xDD; 32];
        let packet = build_goodbye(&pubkey, "test", 48627, None);
        assert_eq!(packet.answers[0].ttl, 0);
    }
}
