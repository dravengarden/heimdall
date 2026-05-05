//! SNI extraction from a TLS ClientHello on a freshly-accepted client
//! socket. Used by the relay to recover a hostname for connections
//! that bypassed heimdall's fake-IP DNS (i.e. the pod connected by
//! literal IP, not via name resolution).
//!
//! Why this exists: tap modules don't cover stripped binaries (Bun,
//! Deno, Envoy data plane, Chromium-derived crawlers). For those,
//! plaintext capture is impossible — but we can still surface the
//! destination hostname by peeking at the first TLS record, which is
//! always the ClientHello with its `server_name` extension. That gets
//! us "rancher couldn't decrypt this Bun pod's traffic, but it was
//! talking to api.openai.com" instead of "rancher saw an opaque blob
//! to 104.18.6.83".
//!
//! Cost: one non-blocking peek + ~150 lines of byte parsing. Time-
//! bounded so a non-TLS client doesn't stall the relay's accept loop.
//!
//! We deliberately don't consume bytes from the stream — `peek()`
//! leaves the bytes in the kernel's TCP receive buffer for the relay's
//! later forwarding stage to read normally.

use std::time::Duration;

use tokio::net::TcpStream;

/// Peek the first TLS record on `stream`, parse the ClientHello, and
/// return the SNI server_name extension value as a UTF-8 hostname.
///
/// Returns `None` for any of:
///   - peek timeout (`max_wait` exceeded — non-TLS or very slow client)
///   - peek error (socket gone, etc.)
///   - bytes don't look like a TLS handshake
///   - ClientHello has no server_name extension
///   - server_name isn't valid UTF-8
///
/// We never consume from the socket — `TcpStream::peek` is destructive-
/// free, so the bytes stay in the kernel buffer for the caller to
/// forward upstream.
pub async fn peek_sni(stream: &TcpStream, max_wait: Duration) -> Option<String> {
    // 2 KiB is enough for any sane ClientHello: handshake header (9 B)
    // + version (2) + random (32) + session-id (≤33) + cipher suites
    // (≤2 KiB but typically <100 B) + compression (≤2 B) + extensions
    // (a few hundred bytes; SNI alone is rarely >200 B). Larger than
    // ~700 B is unusual; 2 KiB gives plenty of headroom for jumbo
    // post-quantum handshakes.
    let mut buf = vec![0u8; 2048];
    let n = match tokio::time::timeout(max_wait, stream.peek(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    parse_sni(&buf[..n])
}

/// Parse a TLS ClientHello byte slice and return the SNI hostname.
///
/// Layout (all `u16` / `u24` are big-endian):
///
/// ```text
/// TLSPlaintext
///   ContentType   = 22 (handshake)        : 1 byte
///   ProtocolVersion                       : 2 bytes
///   length                                : 2 bytes
///   Handshake
///     msg_type = 1 (ClientHello)          : 1 byte
///     length                              : 3 bytes
///     ClientHello
///       legacy_version                    : 2
///       random                            : 32
///       session_id_length / session_id    : 1 + n
///       cipher_suites_len / cipher_suites : 2 + n
///       compression_len / compression     : 1 + n
///       extensions_len                    : 2
///       extensions                        : n
///         extension_type   (server_name = 0)
///         extension_data_len
///         extension_data
///           ServerNameList:
///             server_name_list_len
///             entries:
///               name_type (host_name = 0)
///               host_name_length
///               host_name
/// ```
pub(crate) fn parse_sni(buf: &[u8]) -> Option<String> {
    let mut r = Reader::new(buf);

    // TLSPlaintext header.
    if r.u8()? != 0x16 {
        return None; // Not a handshake.
    }
    r.skip(2)?; // legacy version
    let _record_len = r.u16()?;

    // Handshake header.
    if r.u8()? != 0x01 {
        return None; // Not ClientHello.
    }
    let _hs_len = r.u24()?;

    // ClientHello body.
    r.skip(2)?; // legacy version
    r.skip(32)?; // random

    let sid_len = r.u8()? as usize;
    r.skip(sid_len)?;

    let cs_len = r.u16()? as usize;
    r.skip(cs_len)?;

    let cm_len = r.u8()? as usize;
    r.skip(cm_len)?;

    let ext_total = r.u16()? as usize;
    let mut ext_r = r.sub(ext_total)?;

    while ext_r.remaining() >= 4 {
        let ext_type = ext_r.u16()?;
        let ext_len = ext_r.u16()? as usize;
        let mut ext_body = ext_r.sub(ext_len)?;
        if ext_type == 0x0000 {
            // ServerNameList: 2-byte total len, then entries.
            let _list_len = ext_body.u16()?;
            while ext_body.remaining() >= 3 {
                let name_type = ext_body.u8()?;
                let name_len = ext_body.u16()? as usize;
                let name_bytes = ext_body.bytes(name_len)?;
                if name_type == 0x00 {
                    return std::str::from_utf8(name_bytes).ok().map(str::to_owned);
                }
            }
            return None;
        }
    }
    None
}

/// Bounds-checked byte reader. Each method returns `None` on EOF rather
/// than panicking, so a truncated handshake just gives `parse_sni` an
/// `Option::None` to bubble up.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let v = u32::from_be_bytes([
            0,
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
        ]);
        self.pos += 3;
        Some(v)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.remaining() < n {
            return None;
        }
        self.pos += n;
        Some(())
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    /// Carve out a sub-reader of `len` bytes; advance `self` past them.
    fn sub(&mut self, len: usize) -> Option<Reader<'a>> {
        let s = self.bytes(len)?;
        Some(Reader::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-crafted minimal ClientHello with SNI = "example.com".
    /// Cipher suites and extensions are kept to the minimum so the
    /// length math is easy to follow.
    fn build_clienthello(host: &[u8]) -> Vec<u8> {
        let mut sni_ext = Vec::new();
        // ServerNameList:
        //   list_len (u16)
        //   name_type (u8) + host_name_len (u16) + host_name
        let entry_len = 1 + 2 + host.len();
        sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list_len
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // ext_type = SNI
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_length
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites_len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression_methods_len
        body.push(0); // null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let body_len_be = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len_be[1..4]); // u24
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni_from_clienthello() {
        let hello = build_clienthello(b"example.com");
        assert_eq!(parse_sni(&hello).as_deref(), Some("example.com"));
    }

    #[test]
    fn extracts_sni_with_long_hostname() {
        let host = "a-very-long-subdomain.example.org";
        let hello = build_clienthello(host.as_bytes());
        assert_eq!(parse_sni(&hello).as_deref(), Some(host));
    }

    #[test]
    fn rejects_non_handshake() {
        let bytes = vec![0x17, 0x03, 0x03, 0x00, 0x10]; // application_data
        assert_eq!(parse_sni(&bytes), None);
    }

    #[test]
    fn rejects_truncated() {
        let hello = build_clienthello(b"example.com");
        assert_eq!(parse_sni(&hello[..20]), None); // mid-record cut
    }

    #[test]
    fn rejects_no_sni_extension() {
        // Build a hello with empty extensions block.
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&0x0002u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0x0000u16.to_be_bytes()); // 0 extensions

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len_be = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len_be[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(parse_sni(&record), None);
    }
}
