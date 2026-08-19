//! Conservative HTTP/1 metadata derived only from explicit plaintext events.

use serde_json::{Value, json};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const PARSER_NAME: &str = "heimdall-http1";
const PARSER_VERSION: &str = "1";

pub(crate) struct DerivedHttp {
    pub kind: &'static str,
    pub data: Value,
}

#[derive(Default)]
pub(crate) struct HttpDeriver {
    request: HeaderStream,
    response: HeaderStream,
}

#[derive(Default)]
struct HeaderStream {
    bytes: Vec<u8>,
    source_seq: Vec<u64>,
    complete: bool,
}

impl HttpDeriver {
    pub fn observe(
        &mut self,
        direction: &str,
        payload: &[u8],
        source_seq: u64,
    ) -> Option<DerivedHttp> {
        match direction {
            "client_to_remote" => self.request.observe(payload, source_seq, parse_request),
            "remote_to_client" => self.response.observe(payload, source_seq, parse_response),
            _ => None,
        }
    }
}

impl HeaderStream {
    fn observe(
        &mut self,
        payload: &[u8],
        source_seq: u64,
        parser: fn(&[u8], &[u64]) -> Option<DerivedHttp>,
    ) -> Option<DerivedHttp> {
        if self.complete {
            return None;
        }
        if self.bytes.len().saturating_add(payload.len()) > MAX_HEADER_BYTES {
            self.complete = true;
            self.bytes.clear();
            self.source_seq.clear();
            return None;
        }
        self.bytes.extend_from_slice(payload);
        if self.source_seq.last() != Some(&source_seq) {
            self.source_seq.push(source_seq);
        }
        let end = self
            .bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")?
            + 4;
        self.complete = true;
        parser(&self.bytes[..end], &self.source_seq)
    }
}

fn parse_request(header: &[u8], source_seq: &[u64]) -> Option<DerivedHttp> {
    let text = std::str::from_utf8(header).ok()?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let start = lines.next()?;
    let mut parts = start.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || !valid_token(method)
        || !version.starts_with("HTTP/1.")
        || target.is_empty()
    {
        return None;
    }
    let headers = parse_headers(lines)?;
    let host = header_value(&headers, "host").map(ToOwned::to_owned);
    let (scheme, authority, path) = split_target(target, host);
    Some(DerivedHttp {
        kind: "http.request",
        data: json!({
            "parser": {"name": PARSER_NAME, "version": PARSER_VERSION},
            "source_seq": source_seq,
            "method": method,
            "scheme": scheme,
            "authority": authority,
            "path": path,
            "headers": headers,
            "body": null
        }),
    })
}

fn parse_response(header: &[u8], source_seq: &[u64]) -> Option<DerivedHttp> {
    let text = std::str::from_utf8(header).ok()?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let start = lines.next()?;
    let mut parts = start.splitn(3, ' ');
    let version = parts.next()?;
    let status = parts.next()?.parse::<u16>().ok()?;
    if !version.starts_with("HTTP/1.") || !(100..=999).contains(&status) {
        return None;
    }
    let headers = parse_headers(lines)?;
    Some(DerivedHttp {
        kind: "http.response",
        data: json!({
            "parser": {"name": PARSER_NAME, "version": PARSER_VERSION},
            "source_seq": source_seq,
            "status": status,
            "headers": headers,
            "body": null
        }),
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Option<Vec<Value>> {
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if !valid_token(name) {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if value.chars().any(char::is_control) {
            return None;
        }
        let value = if sensitive_header(name) {
            "[REDACTED]"
        } else {
            value
        };
        headers.push(json!({"name": name, "value": value}));
    }
    Some(headers)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn sensitive_header(name: &str) -> bool {
    [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    ]
    .iter()
    .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

fn header_value<'a>(headers: &'a [Value], wanted: &str) -> Option<&'a str> {
    headers.iter().find_map(|header| {
        header["name"]
            .as_str()
            .filter(|name| name.eq_ignore_ascii_case(wanted))
            .and_then(|_| header["value"].as_str())
    })
}

fn split_target(target: &str, host: Option<String>) -> (Option<&str>, Option<String>, &str) {
    for scheme in ["http", "https"] {
        if let Some(rest) = target.strip_prefix(&format!("{scheme}://")) {
            let split = rest.find('/').unwrap_or(rest.len());
            let authority = (!rest[..split].is_empty()).then(|| rest[..split].to_owned());
            let path = if split == rest.len() {
                "/"
            } else {
                &rest[split..]
            };
            return (Some(scheme), authority, path);
        }
    }
    (Some("https"), host, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_split_request_with_source_sequences_and_secret_header_masking() {
        let mut parser = HttpDeriver::default();
        assert!(
            parser
                .observe("client_to_remote", b"GET /v1 HTTP/1.1\r\nHo", 8)
                .is_none()
        );
        let event = parser
            .observe(
                "client_to_remote",
                b"st: api.example\r\nAuthorization: bearer value\r\n\r\n",
                9,
            )
            .unwrap();
        assert_eq!(event.kind, "http.request");
        assert_eq!(event.data["source_seq"], json!([8, 9]));
        assert_eq!(event.data["authority"], "api.example");
        assert_eq!(event.data["path"], "/v1");
        assert_eq!(event.data["headers"][1]["value"], "[REDACTED]");
    }

    #[test]
    fn derives_response_and_ignores_non_http_plaintext() {
        let mut parser = HttpDeriver::default();
        let event = parser
            .observe(
                "remote_to_client",
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
                12,
            )
            .unwrap();
        assert_eq!(event.kind, "http.response");
        assert_eq!(event.data["status"], 204);
        assert!(
            HttpDeriver::default()
                .observe("client_to_remote", b"not http\r\n\r\n", 1)
                .is_none()
        );
    }
}
