//! Fake-IP DNS server for heimdall.
//!
//! For each A query the server allocates a unique IP from a configured
//! pool (default `198.19.0.0/16`) and returns it as a synthetic answer.
//! The relay later reverses `fake_ip → hostname` and uses SOCKS5
//! ATYP=0x03 (domain name) so the upstream proxy resolves and connects
//! on our behalf.
//!
//! Why fake-IP at all? eBPF connect4 only sees IPs — the original
//! hostname is gone by the time `connect()` fires. Allocating a unique
//! fake IP per hostname lets us recover the hostname at relay time.
//!
//! AAAA queries are answered with NOERROR + 0 records (forces the
//! resolver to fall back to A). All other types get the same empty
//! NOERROR — keeps things minimal.
//!
//! The pool is recycled wrap-around. Eviction is implicit: the next
//! allocation that hits a slot already in use overwrites it. With a
//! /16 (65 K addresses) and short TTL (30 s) this is fine for the
//! foreseeable load.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{rdata::A, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const FAKE_IP_TTL_SEC: u32 = 30;

pub struct DnsResolver {
    /// Pool base in network byte order.
    fake_base_be: u32,
    /// Number of usable IPs in the pool. We skip offset 0 (network)
    /// and the broadcast — but for /15+ ranges we just skip 0.
    fake_size: u32,
    /// Next offset to allocate (mod fake_size).
    next_offset: AtomicU32,

    /// fake_ip (network byte order u32) → hostname.
    by_ip: RwLock<HashMap<u32, String>>,
    /// hostname → fake_ip (network byte order u32).
    by_name: RwLock<HashMap<String, u32>>,
}

impl DnsResolver {
    /// `fake_cidr` is the IPv4 CIDR to draw fake IPs from, e.g. `198.19.0.0/16`.
    pub fn new(fake_cidr: &str) -> Result<Self> {
        let (base, prefix) = parse_v4_cidr(fake_cidr)
            .with_context(|| format!("parse fakeIpCidr `{fake_cidr}`"))?;
        anyhow::ensure!(
            prefix <= 30,
            "fakeIpCidr must be /30 or larger; got /{prefix}"
        );
        let size = 1u32 << (32 - prefix);
        Ok(Self {
            fake_base_be: u32::from(base).to_be(),
            fake_size: size,
            next_offset: AtomicU32::new(1), // skip the network address
            by_ip: RwLock::new(HashMap::new()),
            by_name: RwLock::new(HashMap::new()),
        })
    }

    /// Allocate or retrieve the fake IP for `hostname`.
    ///
    /// Hostname is canonicalised to lowercase, no trailing dot.
    pub fn allocate(&self, hostname: &str) -> Ipv4Addr {
        let canon = canonicalise(hostname);

        if let Some(&fake_be) = self.by_name.read().get(&canon) {
            return Ipv4Addr::from(u32::from_be(fake_be));
        }

        // Reserve next offset; wrap and recycle if pool exhausted.
        // We skip offset 0 to avoid the network address.
        let offset = loop {
            let raw = self.next_offset.fetch_add(1, Ordering::Relaxed);
            let off = raw % self.fake_size;
            if off != 0 {
                break off;
            }
        };

        let base_host = u32::from_be(self.fake_base_be);
        let fake_host = base_host + offset;
        let fake_be = fake_host.to_be();
        let fake = Ipv4Addr::from(fake_host);

        // If this slot was used by another hostname, evict.
        let mut by_ip = self.by_ip.write();
        let mut by_name = self.by_name.write();
        if let Some(prev) = by_ip.insert(fake_be, canon.clone()) {
            by_name.remove(&prev);
            debug!(evicted = %prev, %fake, "fake-IP slot recycled");
        }
        by_name.insert(canon, fake_be);

        fake
    }

    /// Reverse lookup: fake IP (network byte order) → hostname.
    pub fn lookup_be(&self, fake_ip_be: u32) -> Option<String> {
        self.by_ip.read().get(&fake_ip_be).cloned()
    }

    pub fn entries(&self) -> usize {
        self.by_ip.read().len()
    }

    /// Run the UDP DNS server on `listen`. Loops forever.
    pub async fn serve(self: Arc<Self>, listen: SocketAddr) -> Result<()> {
        let sock = UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind DNS UDP on {listen}"))?;
        info!(listen = %listen, "fake-IP DNS server ready");

        let sock = Arc::new(sock);
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "DNS recv_from failed");
                    continue;
                }
            };

            let msg = match Message::from_bytes(&buf[..n]) {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, ?peer, "malformed DNS query");
                    continue;
                }
            };

            let resp = self.handle(msg);
            let resp_bytes = match resp.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "DNS response encode failed");
                    continue;
                }
            };
            if let Err(e) = sock.send_to(&resp_bytes, peer).await {
                warn!(error = %e, ?peer, "DNS send failed");
            }
        }
    }

    fn handle(&self, query: Message) -> Message {
        let mut response = Message::new();
        let mut hdr = Header::new();
        hdr.set_id(query.id());
        hdr.set_message_type(MessageType::Response);
        hdr.set_op_code(query.op_code());
        hdr.set_recursion_desired(query.recursion_desired());
        hdr.set_recursion_available(true);
        hdr.set_response_code(ResponseCode::NoError);
        response.set_header(hdr);

        // Echo the question section.
        for q in query.queries() {
            response.add_query(q.clone());
        }

        // Only OpCode::Query is meaningful; refuse the rest.
        if query.op_code() != OpCode::Query {
            response.set_response_code(ResponseCode::NotImp);
            return response;
        }

        for q in query.queries() {
            let hostname = q.name().to_ascii();
            let host_trim = hostname.trim_end_matches('.').to_string();

            match q.query_type() {
                RecordType::A => {
                    let fake = self.allocate(&host_trim);
                    let mut rec = Record::new();
                    rec.set_name(q.name().clone())
                        .set_record_type(RecordType::A)
                        .set_dns_class(q.query_class())
                        .set_ttl(FAKE_IP_TTL_SEC)
                        .set_data(Some(RData::A(A(fake))));
                    response.add_answer(rec);
                    debug!(host = %host_trim, %fake, "A → fake IP");
                }
                RecordType::AAAA => {
                    debug!(host = %host_trim, "AAAA → empty NOERROR");
                }
                other => {
                    debug!(host = %host_trim, ty = ?other, "unsupported qtype → empty NOERROR");
                }
            }
        }
        response
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn canonicalise(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .with_context(|| format!("CIDR missing `/`: {s}"))?;
    let ip = Ipv4Addr::from_str(ip_str)?;
    let prefix: u8 = prefix_str.parse()?;
    anyhow::ensure!(prefix <= 32, "invalid prefix /{prefix}");
    Ok((ip, prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_stable_ip_for_same_host() {
        let r = DnsResolver::new("198.19.0.0/16").unwrap();
        let a = r.allocate("foo.example");
        let b = r.allocate("foo.example");
        assert_eq!(a, b, "same host must get same fake IP");
    }

    #[test]
    fn allocate_distinct_ips_for_distinct_hosts() {
        let r = DnsResolver::new("198.19.0.0/16").unwrap();
        let a = r.allocate("a.test");
        let b = r.allocate("b.test");
        assert_ne!(a, b);
    }

    #[test]
    fn fake_ip_falls_in_pool() {
        let r = DnsResolver::new("198.19.0.0/16").unwrap();
        let ip = r.allocate("x.test");
        let octets = ip.octets();
        assert_eq!(octets[0], 198);
        assert_eq!(octets[1], 19);
    }

    #[test]
    fn case_insensitive_canonicalisation() {
        let r = DnsResolver::new("198.19.0.0/16").unwrap();
        let a = r.allocate("Foo.Example");
        let b = r.allocate("foo.example");
        let c = r.allocate("foo.example.");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn lookup_round_trip() {
        let r = DnsResolver::new("198.19.0.0/16").unwrap();
        let ip = r.allocate("svc.example");
        let be = u32::from(ip).to_be();
        assert_eq!(r.lookup_be(be).as_deref(), Some("svc.example"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(DnsResolver::new("not a cidr").is_err());
        assert!(DnsResolver::new("198.19.0.0/40").is_err());
        assert!(DnsResolver::new("198.19.0.0/31").is_err());
    }

    #[test]
    fn small_pool_recycles_without_crashing() {
        // /30 = 4 addresses, we skip offset 0 so 3 effective slots.
        let r = DnsResolver::new("198.19.0.0/30").unwrap();
        for i in 0..20 {
            let host = format!("h{i}.test");
            let _ = r.allocate(&host);
        }
        // Still in pool
        for (_be, host) in r.by_ip.read().iter() {
            assert!(host.starts_with("h"));
        }
    }
}
