//! mDNS multicast socket configuration.
//!
//! Binds to `224.0.0.251:5353` (IPv4 mDNS multicast group) with
//! `SO_REUSEADDR` + `SO_REUSEPORT` for Avahi coexistence.
//! TTL set to 255 per RFC 6762.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};

/// mDNS multicast group address.
pub const MDNS_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// mDNS port.
pub const MDNS_PORT: u16 = 5353;

/// Bind an mDNS-compatible UDP socket.
///
/// - `SO_REUSEADDR` + `SO_REUSEPORT`: coexist with Avahi on the same port
/// - Joins the `224.0.0.251` multicast group on all interfaces
/// - TTL = 255 (required by RFC 6762)
/// - Non-blocking for Tokio integration
///
/// # Errors
///
/// Returns `std::io::Error` if socket creation, bind, or multicast join fails.
pub fn bind_mdns_socket() -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;

    socket.set_nonblocking(true)?;
    socket.set_multicast_ttl_v4(255)?;
    socket.set_multicast_loop_v4(true)?;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&addr.into())?;

    socket.join_multicast_v4(&MDNS_MULTICAST_V4, &Ipv4Addr::UNSPECIFIED)?;

    Ok(socket.into())
}

/// Check if an address is link-local (amplification defence).
///
/// mDNS responses must only be sent to link-local sources per RFC 6762.
/// Non-link-local queries are silently dropped.
#[must_use]
pub fn is_link_local_v4(ip: &Ipv4Addr) -> bool {
    // 169.254.0.0/16
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

/// Check if an IPv4 address is on the local network (private ranges).
///
/// For mDNS, we accept queries from private networks (RFC 1918) since
/// mDNS is link-local by multicast scope — the 224.0.0.251 group does
/// not cross L3 boundaries. Strict link-local (169.254/16) would reject
/// too many valid LAN queries.
#[must_use]
pub fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    octets[0] == 10
    // 172.16.0.0/12
    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
    // 192.168.0.0/16
    || (octets[0] == 192 && octets[1] == 168)
    // 169.254.0.0/16 (link-local)
    || (octets[0] == 169 && octets[1] == 254)
    // 127.0.0.0/8 (loopback)
    || octets[0] == 127
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_detection() {
        assert!(is_link_local_v4(&Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_link_local_v4(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn private_range_detection() {
        assert!(is_private_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_private_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    }
}
