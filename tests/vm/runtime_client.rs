use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

fn main() {
    let mode = std::env::args()
        .nth(1)
        .expect("usage: runtime-client tcp|udp4|udp6");
    match mode.as_str() {
        "tcp" => tcp(),
        "udp4" => udp(false),
        "udp6" => udp(true),
        _ => panic!("unknown mode: {mode}"),
    }
    println!("rust-{mode}-ok");
}

fn tcp() {
    let mut stream = TcpStream::connect(("fixture.test", 18080)).expect("connect TCP fixture");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set TCP timeout");
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n")
        .expect("write HTTP request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read HTTP response");
    assert!(response.ends_with(b"fixture-v4"), "unexpected TCP response");
}

fn udp(ipv6: bool) {
    let (bind, target, payload, expected) = if ipv6 {
        (
            "[::]:0",
            "[::1]:18083",
            b"runtime-rust".as_slice(),
            b"udp-v6:runtime-rust".as_slice(),
        )
    } else {
        (
            "0.0.0.0:0",
            "127.0.0.1:18082",
            b"runtime-rust".as_slice(),
            b"udp-v4:runtime-rust".as_slice(),
        )
    };
    let socket = UdpSocket::bind(bind).expect("bind UDP socket");
    socket.connect(target).expect("connect UDP fixture");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set UDP timeout");
    socket.send(payload).expect("send UDP payload");
    let mut response = [0_u8; 128];
    let received = socket.recv(&mut response).expect("receive UDP response");
    assert_eq!(&response[..received], expected, "unexpected UDP response");
    assert_eq!(socket.peer_addr().expect("read UDP peer").to_string(), target);
}
