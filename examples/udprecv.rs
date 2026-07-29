// Control test: can a fresh Rust binary receive LAN UDP on macOS?
// Usage: udprecv <bind_port>
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9999);
    let sock = UdpSocket::bind(("0.0.0.0", port)).expect("bind");
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    println!("listening udp 0.0.0.0:{port} for 8s ...");
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => println!("RECEIVED {n} bytes from {from}"),
        Err(e) => println!("NO PACKET RECEIVED: {e}"),
    }
}
