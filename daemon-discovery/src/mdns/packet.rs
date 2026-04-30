//! Minimal DNS packet serialiser/parser for mDNS.
//!
//! Implements only the subset of RFC 1035/6762 needed for service
//! announcement and query: A, AAAA, SRV, TXT, PTR record types.
//! No compression pointer support (mDNS packets are small enough
//! to fit uncompressed within a single UDP datagram).

/// DNS record types we handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    PTR = 12,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
}

impl RecordType {
    #[allow(dead_code)] // Used by future mDNS response parsing when handling unknown record types
    fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::A),
            12 => Some(Self::PTR),
            16 => Some(Self::TXT),
            28 => Some(Self::AAAA),
            33 => Some(Self::SRV),
            _ => None,
        }
    }
}

/// DNS class (IN = 1, with mDNS cache-flush bit 0x8001).
const CLASS_IN: u16 = 1;
const CLASS_IN_FLUSH: u16 = 0x8001;

/// A parsed DNS question.
#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A parsed DNS resource record.
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// A parsed DNS packet (query or response).
#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl DnsPacket {
    /// Parse a DNS packet from bytes.
    ///
    /// Returns `None` if the packet is too short or malformed.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qd_count = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let ns_count = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]) as usize;

        let mut offset = 12;

        let mut questions = Vec::with_capacity(qd_count);
        for _ in 0..qd_count {
            let (name, new_offset) = read_name(buf, offset)?;
            offset = new_offset;
            if offset + 4 > buf.len() {
                return None;
            }
            let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(answer_count);
        for _ in 0..answer_count {
            let (rr, new_offset) = read_rr(buf, offset)?;
            offset = new_offset;
            answers.push(rr);
        }

        let mut authority = Vec::with_capacity(ns_count);
        for _ in 0..ns_count {
            let (rr, new_offset) = read_rr(buf, offset)?;
            offset = new_offset;
            authority.push(rr);
        }

        let mut additional = Vec::with_capacity(additional_count);
        for _ in 0..additional_count {
            let (rr, new_offset) = read_rr(buf, offset)?;
            offset = new_offset;
            additional.push(rr);
        }

        Some(DnsPacket {
            id,
            flags,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Serialise the packet to bytes.
    #[must_use]
    pub fn serialise(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        {
            buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
            buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
            buf.extend_from_slice(&(self.authority.len() as u16).to_be_bytes());
            buf.extend_from_slice(&(self.additional.len() as u16).to_be_bytes());
        }

        for q in &self.questions {
            write_name(&mut buf, &q.name);
            buf.extend_from_slice(&q.qtype.to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }

        for rr in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            write_rr(&mut buf, rr);
        }

        buf
    }

    /// Build an mDNS query for a service type.
    #[must_use]
    pub fn query(service_type: &str) -> Self {
        DnsPacket {
            id: 0,
            flags: 0, // Standard query
            questions: vec![Question {
                name: service_type.to_string(),
                qtype: RecordType::PTR as u16,
                qclass: CLASS_IN,
            }],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Build an mDNS response with the given answer records.
    #[must_use]
    pub fn response(answers: Vec<ResourceRecord>, additional: Vec<ResourceRecord>) -> Self {
        DnsPacket {
            id: 0,
            flags: 0x8400, // Response, Authoritative
            questions: Vec::new(),
            answers,
            authority: Vec::new(),
            additional,
        }
    }
}

/// Build a PTR record: `_opensesame._udp.local. → <instance>._opensesame._udp.local.`
#[must_use]
pub fn ptr_record(service_type: &str, instance_name: &str, ttl: u32) -> ResourceRecord {
    let target = format!("{instance_name}.{service_type}");
    let mut rdata = Vec::new();
    write_name(&mut rdata, &target);
    ResourceRecord {
        name: service_type.to_string(),
        rtype: RecordType::PTR as u16,
        rclass: CLASS_IN,
        ttl,
        rdata,
    }
}

/// Build an SRV record: `<instance>._opensesame._udp.local. → host:port`
#[must_use]
pub fn srv_record(instance_fqdn: &str, host: &str, port: u16, ttl: u32) -> ResourceRecord {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&0u16.to_be_bytes()); // priority
    rdata.extend_from_slice(&0u16.to_be_bytes()); // weight
    rdata.extend_from_slice(&port.to_be_bytes());
    write_name(&mut rdata, host);
    ResourceRecord {
        name: instance_fqdn.to_string(),
        rtype: RecordType::SRV as u16,
        rclass: CLASS_IN_FLUSH,
        ttl,
        rdata,
    }
}

/// Build a TXT record with key-value pairs.
#[must_use]
pub fn txt_record(name: &str, pairs: &[(&str, &str)], ttl: u32) -> ResourceRecord {
    let mut rdata = Vec::new();
    for (k, v) in pairs {
        let entry = format!("{k}={v}");
        #[allow(clippy::cast_possible_truncation)]
        rdata.push(entry.len() as u8);
        rdata.extend_from_slice(entry.as_bytes());
    }
    ResourceRecord {
        name: name.to_string(),
        rtype: RecordType::TXT as u16,
        rclass: CLASS_IN_FLUSH,
        ttl,
        rdata,
    }
}

/// Build an A record (IPv4).
#[must_use]
pub fn a_record(name: &str, ip: std::net::Ipv4Addr, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        rtype: RecordType::A as u16,
        rclass: CLASS_IN_FLUSH,
        ttl,
        rdata: ip.octets().to_vec(),
    }
}

/// Build an AAAA record (IPv6).
#[must_use]
pub fn aaaa_record(name: &str, ip: std::net::Ipv6Addr, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: name.to_string(),
        rtype: RecordType::AAAA as u16,
        rclass: CLASS_IN_FLUSH,
        ttl,
        rdata: ip.octets().to_vec(),
    }
}

// -- Wire format helpers --

fn write_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        #[allow(clippy::cast_possible_truncation)]
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // Root label
}

fn read_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;

    loop {
        if offset >= buf.len() {
            return None;
        }
        let len = buf[offset] as usize;

        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Compression pointer (RFC 1035 §4.1.4)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | (buf[offset + 1] as usize);
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }

        offset += 1;
        if offset + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    if !jumped {
        return_offset = offset + 1;
    }

    Some((labels.join("."), return_offset))
}

fn read_rr(buf: &[u8], offset: usize) -> Option<(ResourceRecord, usize)> {
    let (name, mut off) = read_name(buf, offset)?;
    if off + 10 > buf.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let rclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
    let ttl = u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
    let rdlength = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
    off += 10;
    if off + rdlength > buf.len() {
        return None;
    }
    let rdata = buf[off..off + rdlength].to_vec();
    off += rdlength;

    Some((
        ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        off,
    ))
}

fn write_rr(buf: &mut Vec<u8>, rr: &ResourceRecord) {
    write_name(buf, &rr.name);
    buf.extend_from_slice(&rr.rtype.to_be_bytes());
    buf.extend_from_slice(&rr.rclass.to_be_bytes());
    buf.extend_from_slice(&rr.ttl.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    buf.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rr.rdata);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip() {
        let query = DnsPacket::query("_opensesame._udp.local.");
        let bytes = query.serialise();
        let parsed = DnsPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "_opensesame._udp.local");
        assert_eq!(parsed.questions[0].qtype, RecordType::PTR as u16);
    }

    #[test]
    fn response_with_records_round_trip() {
        let ptr = ptr_record("_opensesame._udp.local.", "abcdef01", 4500);
        let srv = srv_record(
            "abcdef01._opensesame._udp.local.",
            "abcdef01.local.",
            48627,
            120,
        );
        let txt = txt_record(
            "abcdef01._opensesame._udp.local.",
            &[("pubkey", "aabbccdd"), ("iid", "550e8400"), ("v", "1")],
            120,
        );
        let a = a_record("abcdef01.local.", "192.168.1.10".parse().unwrap(), 120);

        let response = DnsPacket::response(vec![ptr], vec![srv, txt, a]);
        let bytes = response.serialise();
        let parsed = DnsPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.flags & 0x8000, 0x8000); // Response bit
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.additional.len(), 3);
        assert_eq!(parsed.answers[0].rtype, RecordType::PTR as u16);
    }

    #[test]
    fn too_short_returns_none() {
        assert!(DnsPacket::parse(&[0u8; 5]).is_none());
    }

    #[test]
    fn srv_record_port() {
        let srv = srv_record("test.local.", "host.local.", 48627, 120);
        // Port is at bytes 4-5 of rdata (after priority and weight).
        let port = u16::from_be_bytes([srv.rdata[4], srv.rdata[5]]);
        assert_eq!(port, 48627);
    }

    #[test]
    fn txt_record_key_value() {
        let txt = txt_record("test.local.", &[("key", "val")], 120);
        // First byte is length, then "key=val".
        assert_eq!(txt.rdata[0], 7); // "key=val".len()
        assert_eq!(&txt.rdata[1..8], b"key=val");
    }

    #[test]
    fn a_record_ip() {
        let a = a_record("test.local.", "10.0.0.1".parse().unwrap(), 120);
        assert_eq!(a.rdata, vec![10, 0, 0, 1]);
    }

    #[test]
    fn aaaa_record_ip() {
        let aaaa = aaaa_record("test.local.", "::1".parse().unwrap(), 120);
        assert_eq!(aaaa.rdata.len(), 16);
        assert_eq!(aaaa.rdata[15], 1);
    }
}
