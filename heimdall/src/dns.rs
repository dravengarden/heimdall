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
//! AAAA queries are answered with synthetic IPv6 addresses from a
//! parallel `fake_ip6_cidr` pool, mirroring the IPv4 path: same
//! reverse-lookup at relay time, same SOCKS5 ATYP=0x03 hostname
//! forwarding upstream. When `fake_ip6_cidr` is empty (or unset)
//! AAAA falls back to NOERROR + 0 records, keeping the legacy
//! "force IPv4" behaviour. Other RR types remain empty NOERROR.
//!
//! Mappings stay stable for the daemon lifetime. Pool exhaustion returns
//! SERVFAIL instead of recycling an address that an application may still
//! hold in its DNS cache.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, OpCode, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
    serialize::binary::{BinDecodable, BinEncodable},
};
use parking_lot::RwLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::{debug, info, warn};

const FAKE_IP_TTL_SEC: u32 = 30;

pub struct DnsResolver {
    /// Pool base in network byte order.
    fake_base_be: u32,
    /// Total number of addresses in the pool. Allocation skips both the
    /// network and broadcast address and never recycles a live mapping.
    fake_size: u64,
    /// Next offset to allocate.
    next_offset: AtomicU64,

    /// fake_ip (network byte order u32) → hostname.
    by_ip: RwLock<HashMap<u32, String>>,
    /// hostname → fake_ip (network byte order u32).
    by_name: RwLock<HashMap<String, u32>>,

    /// IPv6 fake-IP pool: only populated when `fake_ip6_cidr` is set.
    /// Mirror of the v4 fields, scaled up: 128-bit base + 64-bit ring
    /// counter (we only allocate within the host bits, which is
    /// always ≤ 128 - prefix; for typical /96 that's 32 bits anyway).
    /// `None` means "answer AAAA with empty NOERROR" (legacy behaviour).
    v6: Option<V6Pool>,
}

struct V6Pool {
    /// Network bytes of the v6 prefix; bytes outside the prefix are
    /// filled in from the per-host counter.
    base: [u8; 16],
    /// Prefix length in bits (≤ 124).
    prefix: u8,
    /// Number of usable v6 addresses (saturated at u64::MAX so we can
    /// store it). For a /96 this is 2^32 = 4G addresses; for a /124
    /// it's 16. We compute as min(2^(128 - prefix), u64::MAX).
    size: u64,
    /// Next host-offset to allocate. Skips offset 0 and never recycles.
    next_offset: AtomicU64,

    /// fake_v6 → hostname. Keyed by the full 16-byte address (network
    /// byte order, same as the wire) so reverse lookup is a single
    /// comparison.
    by_ip: RwLock<HashMap<[u8; 16], String>>,
    /// hostname → fake_v6.
    by_name: RwLock<HashMap<String, [u8; 16]>>,
}

pub struct DnsServer {
    resolver: Arc<DnsResolver>,
    udp4: Arc<UdpSocket>,
    udp6: Arc<UdpSocket>,
    tcp4: TcpListener,
    tcp6: TcpListener,
    port: u16,
}

impl DnsResolver {
    /// `fake_cidr` is the IPv4 CIDR; `fake6_cidr` is the optional IPv6
    /// CIDR for AAAA synthesis (pass empty string to disable IPv6).
    pub fn new(fake_cidr: &str, fake6_cidr: &str) -> Result<Self> {
        let (base, prefix) = parse_v4_cidr(fake_cidr)
            .with_context(|| format!("parse fake_ip_cidr `{fake_cidr}`"))?;
        anyhow::ensure!(
            prefix <= 30,
            "fake_ip_cidr must be /30 or larger; got /{prefix}"
        );
        let size = 1u64 << (32 - prefix);

        let v6 = if fake6_cidr.is_empty() {
            None
        } else {
            let (base6, prefix6) = parse_v6_cidr(fake6_cidr)
                .with_context(|| format!("parse fake_ip6_cidr `{fake6_cidr}`"))?;
            anyhow::ensure!(
                prefix6 <= 124,
                "fake_ip6_cidr must be /124 or larger; got /{prefix6}"
            );
            let host_bits = 128 - prefix6;
            let size6: u64 = if host_bits >= 64 {
                u64::MAX
            } else {
                1u64 << host_bits
            };
            Some(V6Pool {
                base: base6.octets(),
                prefix: prefix6,
                size: size6,
                next_offset: AtomicU64::new(1), // skip ::0 in the prefix
                by_ip: RwLock::new(HashMap::new()),
                by_name: RwLock::new(HashMap::new()),
            })
        };

        Ok(Self {
            fake_base_be: u32::from(base).to_be(),
            fake_size: size,
            next_offset: AtomicU64::new(1), // skip the network address
            by_ip: RwLock::new(HashMap::new()),
            by_name: RwLock::new(HashMap::new()),
            v6,
        })
    }

    /// Allocate or retrieve the fake IP for `hostname`.
    ///
    /// Hostname is canonicalised to lowercase, no trailing dot.
    pub fn allocate(&self, hostname: &str) -> Option<Ipv4Addr> {
        let canon = canonicalise(hostname);
        let mut by_name = self.by_name.write();
        if let Some(&fake_be) = by_name.get(&canon) {
            return Some(Ipv4Addr::from(u32::from_be(fake_be)));
        }

        // Offset 0 is the network address and size - 1 is broadcast.
        // Refusing exhaustion preserves the lifetime identity of every fake
        // IP; recycling could send a stale application cache to another host.
        let offset = self.next_offset.fetch_add(1, Ordering::Relaxed);
        if offset >= self.fake_size - 1 {
            return None;
        }

        let base_host = u32::from_be(self.fake_base_be);
        let fake_host = base_host + offset as u32;
        let fake_be = fake_host.to_be();
        let fake = Ipv4Addr::from(fake_host);

        let mut by_ip = self.by_ip.write();
        by_ip.insert(fake_be, canon.clone());
        by_name.insert(canon, fake_be);

        Some(fake)
    }

    /// Reverse lookup: fake IP (network byte order) → hostname.
    pub fn lookup_be(&self, fake_ip_be: u32) -> Option<String> {
        self.by_ip.read().get(&fake_ip_be).cloned()
    }

    /// IPv6 sibling of [`allocate`] — returns None when no IPv6 pool
    /// is configured.
    pub fn allocate6(&self, hostname: &str) -> Option<Ipv6Addr> {
        let pool = self.v6.as_ref()?;
        let canon = canonicalise(hostname);
        let mut by_name = pool.by_name.write();
        if let Some(addr) = by_name.get(&canon) {
            return Some(Ipv6Addr::from(*addr));
        }

        let offset = pool.next_offset.fetch_add(1, Ordering::Relaxed);
        if offset >= pool.size {
            return None;
        }

        // Compose: base bytes + (offset spread across the host bits).
        // For prefix p, host_bits = 128 - p; the offset occupies the
        // low `host_bits` bits of the address. We pour it in big-endian.
        let mut addr = pool.base;
        let host_bits = 128 - pool.prefix as usize;
        // Walk back from the last byte, OR the offset bits.
        let mut remaining = offset;
        let mut bit_idx = 0usize;
        while bit_idx < host_bits && remaining != 0 {
            let byte_idx = 15 - (bit_idx / 8);
            let shift = bit_idx % 8;
            addr[byte_idx] |= ((remaining & 0xff) << shift) as u8;
            // Move to the next 8 bits.
            remaining >>= 8 - shift;
            bit_idx += 8 - shift;
        }

        let mut by_ip = pool.by_ip.write();
        by_ip.insert(addr, canon.clone());
        by_name.insert(canon, addr);

        Some(Ipv6Addr::from(addr))
    }

    /// Reverse lookup for IPv6 fake addresses. Returns None when no
    /// v6 pool is configured or the address isn't in the map.
    pub fn lookup6(&self, addr: &Ipv6Addr) -> Option<String> {
        let pool = self.v6.as_ref()?;
        pool.by_ip.read().get(&addr.octets()).cloned()
    }

    /// Bind UDP and TCP before daemon readiness so a valid fake-DNS policy
    /// cannot silently start with an unusable resolver.
    pub async fn bind(self: Arc<Self>, port: u16) -> Result<DnsServer> {
        let udp4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .with_context(|| format!("bind IPv4 DNS UDP on port {port}"))?;
        let udp6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, port))
            .await
            .with_context(|| format!("bind IPv6 DNS UDP on port {port}"))?;
        let tcp4 = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .with_context(|| format!("bind IPv4 DNS TCP on port {port}"))?;
        let tcp6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port))
            .await
            .with_context(|| format!("bind IPv6 DNS TCP on port {port}"))?;
        Ok(DnsServer {
            resolver: self,
            udp4: Arc::new(udp4),
            udp6: Arc::new(udp6),
            tcp4,
            tcp6,
            port,
        })
    }

    async fn serve_udp(self: Arc<Self>, sock: Arc<UdpSocket>) {
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

    async fn serve_tcp(&self, mut stream: TcpStream) -> Result<()> {
        loop {
            let length = match stream.read_u16().await {
                Ok(length) => usize::from(length),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error).context("read DNS TCP length"),
            };
            anyhow::ensure!(length > 0, "zero-length DNS TCP frame");
            let mut request = vec![0_u8; length];
            stream
                .read_exact(&mut request)
                .await
                .context("read DNS TCP query")?;
            let query = Message::from_bytes(&request).context("decode DNS TCP query")?;
            let response = self
                .handle(query)
                .to_bytes()
                .context("encode DNS TCP response")?;
            anyhow::ensure!(
                response.len() <= usize::from(u16::MAX),
                "DNS TCP response too large"
            );
            stream
                .write_u16(response.len() as u16)
                .await
                .context("write DNS TCP length")?;
            stream
                .write_all(&response)
                .await
                .context("write DNS TCP response")?;
        }
    }

    fn handle(&self, query: Message) -> Message {
        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.response_code = ResponseCode::NoError;

        // Echo the question section.
        for q in &query.queries {
            response.add_query(q.clone());
        }

        // Only OpCode::Query is meaningful; refuse the rest.
        if query.metadata.op_code != OpCode::Query {
            response.metadata.response_code = ResponseCode::NotImp;
            return response;
        }

        for q in &query.queries {
            let hostname = q.name().to_ascii();
            let host_trim = hostname.trim_end_matches('.').to_string();

            match q.query_type() {
                RecordType::A => {
                    let Some(fake) = self.allocate(&host_trim) else {
                        warn!(host = %host_trim, "fake IPv4 pool exhausted");
                        response.metadata.response_code = ResponseCode::ServFail;
                        return response;
                    };
                    let mut rec =
                        Record::from_rdata(q.name().clone(), FAKE_IP_TTL_SEC, RData::A(A(fake)));
                    rec.dns_class = q.query_class();
                    response.add_answer(rec);
                    debug!(host = %host_trim, %fake, "A → fake IP");
                }
                RecordType::AAAA => match self.allocate6(&host_trim) {
                    Some(fake6) => {
                        let mut rec = Record::from_rdata(
                            q.name().clone(),
                            FAKE_IP_TTL_SEC,
                            RData::AAAA(AAAA(fake6)),
                        );
                        rec.dns_class = q.query_class();
                        response.add_answer(rec);
                        debug!(host = %host_trim, %fake6, "AAAA → fake IPv6");
                    }
                    None => {
                        if self.v6.is_some() {
                            warn!(host = %host_trim, "fake IPv6 pool exhausted");
                            response.metadata.response_code = ResponseCode::ServFail;
                            return response;
                        }
                        debug!(host = %host_trim, "AAAA → empty NOERROR (no v6 pool)");
                    }
                },
                other => {
                    debug!(host = %host_trim, ty = ?other, "unsupported qtype → empty NOERROR");
                }
            }
        }
        response
    }
}

impl DnsServer {
    /// Serve both DNS transports after [`DnsResolver::bind`] succeeded.
    pub async fn serve(self) -> Result<()> {
        info!(
            port = self.port,
            "fake-IP DNS ready on IPv4/IPv6 UDP/TCP loopback"
        );
        let resolver = self.resolver.clone();
        tokio::spawn(async move { resolver.serve_udp(self.udp4).await });
        let resolver = self.resolver.clone();
        tokio::spawn(async move { resolver.serve_udp(self.udp6).await });

        loop {
            let (stream, peer) = tokio::select! {
                accepted = self.tcp4.accept() => accepted.context("accept IPv4 DNS TCP")?,
                accepted = self.tcp6.accept() => accepted.context("accept IPv6 DNS TCP")?,
            };
            let resolver = self.resolver.clone();
            tokio::spawn(async move {
                if let Err(error) = resolver.serve_tcp(stream).await {
                    warn!(%peer, %error, "DNS TCP connection failed");
                }
            });
        }
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

fn parse_v6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .with_context(|| format!("CIDR missing `/`: {s}"))?;
    let ip = Ipv6Addr::from_str(ip_str)?;
    let prefix: u8 = prefix_str.parse()?;
    anyhow::ensure!(prefix <= 128, "invalid v6 prefix /{prefix}");
    Ok((ip, prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_reserves_udp_and_tcp_before_serving() {
        let resolver = Arc::new(DnsResolver::new("198.19.0.0/16", "").unwrap());
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let _server = resolver.bind(port).await.unwrap();
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await.is_err());
        assert!(UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).await.is_err());
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .is_err()
        );
        assert!(
            TcpListener::bind((Ipv6Addr::LOCALHOST, port))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_dns_uses_rfc_length_frames() {
        use hickory_proto::{
            op::{MessageType, Query},
            rr::Name,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client.unwrap();
        let resolver = Arc::new(DnsResolver::new("198.19.0.0/16", "").unwrap());
        let server = tokio::spawn({
            let resolver = resolver.clone();
            async move { resolver.serve_tcp(accepted.unwrap().0).await }
        });

        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = query.to_bytes().unwrap();
        client.write_u16(bytes.len() as u16).await.unwrap();
        client.write_all(&bytes).await.unwrap();

        let length = client.read_u16().await.unwrap();
        let mut response = vec![0_u8; usize::from(length)];
        client.read_exact(&mut response).await.unwrap();
        let response = Message::from_bytes(&response).unwrap();
        assert_eq!(response.id, 42);
        assert_eq!(response.answers.len(), 1);

        drop(client);
        server.await.unwrap().unwrap();
    }

    #[test]
    fn allocate_returns_stable_ip_for_same_host() {
        let r = DnsResolver::new("198.19.0.0/16", "").unwrap();
        let a = r.allocate("foo.example").unwrap();
        let b = r.allocate("foo.example").unwrap();
        assert_eq!(a, b, "same host must get same fake IP");
    }

    #[test]
    fn allocate_distinct_ips_for_distinct_hosts() {
        let r = DnsResolver::new("198.19.0.0/16", "").unwrap();
        let a = r.allocate("a.test").unwrap();
        let b = r.allocate("b.test").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fake_ip_falls_in_pool() {
        let r = DnsResolver::new("198.19.0.0/16", "").unwrap();
        let ip = r.allocate("x.test").unwrap();
        let octets = ip.octets();
        assert_eq!(octets[0], 198);
        assert_eq!(octets[1], 19);
    }

    #[test]
    fn case_insensitive_canonicalisation() {
        let r = DnsResolver::new("198.19.0.0/16", "").unwrap();
        let a = r.allocate("Foo.Example").unwrap();
        let b = r.allocate("foo.example").unwrap();
        let c = r.allocate("foo.example.").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn lookup_round_trip() {
        let r = DnsResolver::new("198.19.0.0/16", "").unwrap();
        let ip = r.allocate("svc.example").unwrap();
        let be = u32::from(ip).to_be();
        assert_eq!(r.lookup_be(be).as_deref(), Some("svc.example"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(DnsResolver::new("not a cidr", "").is_err());
        assert!(DnsResolver::new("198.19.0.0/40", "").is_err());
        assert!(DnsResolver::new("198.19.0.0/31", "").is_err());
    }

    #[test]
    fn small_pool_never_reassigns_a_stale_fake_ip() {
        // /30 has two usable addresses after network and broadcast.
        let r = DnsResolver::new("198.19.0.0/30", "").unwrap();
        let first = r.allocate("first.test").unwrap();
        let second = r.allocate("second.test").unwrap();
        assert_ne!(first, second);
        assert_eq!(r.allocate("third.test"), None);
        assert_eq!(r.allocate("first.test"), Some(first));
        assert_eq!(
            r.lookup_be(u32::from(first).to_be()).as_deref(),
            Some("first.test")
        );
    }
}
