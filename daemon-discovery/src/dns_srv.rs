//! DNS SRV discovery for enterprise-managed deployments.
//!
//! Resolves `_opensesame._udp.<domain>` SRV + TXT records using
//! `hickory-resolver`. Disabled by default — enabled when
//! `[discovery.dns_srv]` has domains configured.
//!
//! SRV records provide host + port. TXT records carry advisory
//! public key and installation ID (same fields as mDNS TXT).

use hickory_resolver::TokioResolver;
use std::net::SocketAddr;

/// A peer discovered via DNS SRV.
#[derive(Debug, Clone)]
pub struct DnsSrvPeer {
    /// Resolved socket address from SRV target + A/AAAA resolution.
    pub addr: SocketAddr,
    /// Advisory public key from TXT record (if present).
    pub pubkey_hex: Option<String>,
    /// Advisory installation ID from TXT record (if present).
    pub installation_id: Option<String>,
}

/// Resolve peers from DNS SRV records for a domain.
///
/// Queries `_opensesame._udp.<domain>` for SRV records, then resolves
/// each SRV target to A/AAAA addresses.
///
/// # Errors
///
/// Returns an error if DNS resolution fails entirely. Individual SRV
/// targets that fail to resolve are silently skipped.
pub async fn resolve_srv(domain: &str) -> Result<Vec<DnsSrvPeer>, DnsSrvError> {
    let resolver: TokioResolver = TokioResolver::builder_tokio()
        .map_err(DnsSrvError::ResolverInit)?
        .build();

    let srv_name = format!("_opensesame._udp.{domain}");

    let srv_lookup = resolver
        .srv_lookup(srv_name.as_str())
        .await
        .map_err(DnsSrvError::Lookup)?;

    let mut peers = Vec::new();

    for srv in srv_lookup.iter() {
        let target = srv.target().to_string();
        let port = srv.port();

        match resolver.lookup_ip(target.as_str()).await {
            Ok(ips) => {
                for ip in ips.iter() {
                    peers.push(DnsSrvPeer {
                        addr: SocketAddr::new(ip, port),
                        pubkey_hex: None,
                        installation_id: None,
                    });
                }
            }
            Err(e) => {
                tracing::warn!(target = %target, error = %e, "DNS SRV target resolution failed");
            }
        }
    }

    // Try to get TXT records for advisory metadata.
    if let Ok(txt_lookup) = resolver.txt_lookup(srv_name.as_str()).await {
        for txt in txt_lookup.iter() {
            for data in txt.iter() {
                if let Ok(s) = std::str::from_utf8(data) {
                    if let Some(key) = s.strip_prefix("pubkey=") {
                        for peer in &mut peers {
                            if peer.pubkey_hex.is_none() {
                                peer.pubkey_hex = Some(key.to_string());
                            }
                        }
                    }
                    if let Some(iid) = s.strip_prefix("iid=") {
                        for peer in &mut peers {
                            if peer.installation_id.is_none() {
                                peer.installation_id = Some(iid.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::info!(domain, peers = peers.len(), "DNS SRV resolution complete");
    Ok(peers)
}

/// Errors from DNS SRV discovery.
#[derive(Debug, thiserror::Error)]
pub enum DnsSrvError {
    /// Failed to initialise the DNS resolver.
    #[error("resolver init failed: {0}")]
    ResolverInit(#[source] hickory_resolver::ResolveError),
    /// DNS SRV lookup failed.
    #[error("SRV lookup failed: {0}")]
    Lookup(#[source] hickory_resolver::ResolveError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_srv_peer_fields() {
        let peer = DnsSrvPeer {
            addr: "10.0.0.1:48627".parse().unwrap(),
            pubkey_hex: Some("aabb".into()),
            installation_id: Some("test-id".into()),
        };
        assert_eq!(peer.addr.port(), 48627);
        assert_eq!(peer.pubkey_hex.as_deref(), Some("aabb"));
    }

    #[tokio::test]
    async fn resolve_nonexistent_domain_returns_error() {
        // Query a domain that doesn't exist — should return Lookup error.
        let result = resolve_srv("nonexistent.invalid.test.opensesame.example").await;
        assert!(result.is_err());
    }
}
