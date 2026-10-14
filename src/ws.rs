//! MQTT over WebSockets, server side (RFC 6455; MQTT v3.1.1 and v5.0 chapter 6).
//!
//! The HTTP upgrade and the frame layer are implemented here rather than taken from a WebSocket
//! crate, so that wolfSSL stays the only cryptographic code in the broker: the
//! `Sec-WebSocket-Accept` digest uses wolfCrypt SHA-1, and a server never masks its frames, so
//! no random numbers are needed.
//!
//! After the upgrade, a pump task translates between WebSocket frames and an in-memory byte
//! stream that the ordinary MQTT connection handler reads and writes. MQTT packets may span
//! frames and frames may carry several packets (MQTT-6.0.0-2); the handler never sees frames.

use crate::crypto;
use bytes::{Buf, BufMut, BytesMut};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// RFC 6455 §1.3.
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The subprotocol MQTT clients offer and the server must select (MQTT-6.0.0-3, -4).
pub const SUBPROTOCOL: &str = "mqtt";
const MAX_HEADERS: usize = 64;
/// Bytes buffered between the frame pump and the MQTT connection handler, per direction.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Close status codes (RFC 6455 §7.4.1).
pub mod close {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const UNSUPPORTED_DATA: u16 = 1003;
    pub const MESSAGE_TOO_BIG: u16 = 1009;
}

/// Settings of one WebSocket listener.
#[derive(Debug, Clone)]
pub struct WsSettings {
    /// HTTP path that accepts MQTT connections (query strings are ignored).
    pub path: String,
    /// Browser origins allowed to connect (`*` = any). Requests without an Origin header
    /// (non-browser clients) are always allowed.
    pub allowed_origins: Vec<String>,
    /// Reverse proxies whose `X-Forwarded-For` header is trusted for the client address.
    pub trusted_proxies: Vec<IpAddr>,
    /// Largest HTTP upgrade request (request line and headers).
    pub max_header_bytes: usize,
    /// Largest WebSocket frame payload accepted.
    pub max_frame_size: usize,
}

impl Default for WsSettings {
    fn default() -> Self {
        Self {
            path: "/mqtt".into(),
            allowed_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            max_header_bytes: 8192,
            max_frame_size: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Error)]
pub enum UpgradeError {
    #[error("connection closed during the WebSocket upgrade: {0}")]
    Io(#[from] std::io::Error),
    #[error("WebSocket upgrade not completed in time")]
    Timeout,
    #[error("WebSocket upgrade refused ({status}): {detail}")]
    Refused { status: u16, detail: String },
}

/// A refused upgrade: the HTTP status, an optional extra header, and the reason for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub extra_header: Option<&'static str>,
    pub detail: String,
}

fn refuse(status: u16, detail: impl Into<String>) -> Refusal {
    Refusal {
        status,
        extra_header: None,
        detail: detail.into(),
    }
}

/// A validated upgrade request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub accept_key: String,
    /// Client address reported by a trusted reverse proxy.
    pub forwarded_for: Option<IpAddr>,
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        426 => "Upgrade Required",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

/// True when a comma-separated header value contains `token` (case-insensitive).
fn has_token(values: &[&str], token: &str) -> bool {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// The value `Sec-WebSocket-Accept` must carry for a client key (RFC 6455 §4.2.2).
pub fn accept_key(client_key: &str) -> String {
    crypto::base64_encode(&crypto::sha1(
        format!("{client_key}{ACCEPT_GUID}").as_bytes(),
    ))
}

/// A `Sec-WebSocket-Key` is the Base64 encoding of 16 bytes: 22 characters and `==`.
fn valid_client_key(key: &str) -> bool {
    key.len() == 24
        && key.ends_with("==")
        && key[..22]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Validates a parsed upgrade request against the listener settings.
pub fn check_request(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    settings: &WsSettings,
    peer: Option<IpAddr>,
) -> Result<Handshake, Refusal> {
    let all = |name: &str| -> Vec<&str> {
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
            .collect()
    };
    let one = |name: &str| all(name).first().copied();

    if method != "GET" {
        return Err(refuse(405, format!("method {method}")));
    }
    let request_path = path.split('?').next().unwrap_or_default();
    if request_path != settings.path {
        return Err(refuse(404, format!("path {request_path}")));
    }
    if one("Host").is_none() {
        return Err(refuse(400, "no Host header"));
    }
    if !has_token(&all("Upgrade"), "websocket") || !has_token(&all("Connection"), "upgrade") {
        return Err(refuse(426, "not a WebSocket upgrade request"));
    }
    if one("Sec-WebSocket-Version").map(str::trim) != Some("13") {
        return Err(Refusal {
            status: 426,
            extra_header: Some("Sec-WebSocket-Version: 13"),
            detail: "unsupported WebSocket version".into(),
        });
    }
    let key = one("Sec-WebSocket-Key").map(str::trim).unwrap_or_default();
    if !valid_client_key(key) {
        return Err(refuse(400, "invalid Sec-WebSocket-Key"));
    }
    // Subprotocol tokens are case-sensitive (RFC 6455 §11.3.4).
    let offers_mqtt = all("Sec-WebSocket-Protocol")
        .iter()
        .flat_map(|v| v.split(','))
        .any(|p| p.trim() == SUBPROTOCOL);
    if !offers_mqtt {
        return Err(refuse(400, "the 'mqtt' subprotocol was not offered"));
    }
    // Browsers always send Origin; refusing unknown ones stops other web sites from opening
    // connections with a visitor's browser (RFC 6455 §10.2).
    if let Some(origin) = one("Origin") {
        let allowed = settings
            .allowed_origins
            .iter()
            .any(|o| o == "*" || o.eq_ignore_ascii_case(origin.trim()));
        if !allowed {
            return Err(refuse(403, format!("origin {origin} is not allowed")));
        }
    }
    let forwarded_for = match peer {
        Some(ip) if settings.trusted_proxies.contains(&ip) => one("X-Forwarded-For")
            // The last entry is the address the trusted proxy itself saw.
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok()),
        _ => None,
    };
    Ok(Handshake {
        accept_key: accept_key(key),
        forwarded_for,
    })
}

/// Reads and answers the HTTP upgrade request. On success returns the stream, any bytes the
/// client sent after the request, and the client address reported by a trusted proxy.
pub async fn accept<S>(
    stream: &mut S,
    peer: Option<SocketAddr>,
    settings: &WsSettings,
    deadline: Instant,
) -> Result<(BytesMut, Option<IpAddr>), UpgradeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(2048);
    let (outcome, consumed) = loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let fields: Vec<(&str, &str)> = req
                    .headers
                    .iter()
                    .filter_map(|h| Some((h.name, std::str::from_utf8(h.value).ok()?)))
                    .collect();
                let outcome = if req.version != Some(1) {
                    Err(refuse(400, "HTTP/1.1 required"))
                } else {
                    check_request(
                        req.method.unwrap_or_default(),
                        req.path.unwrap_or_default(),
                        &fields,
                        settings,
                        peer.map(|p| p.ip()),
                    )
                };
                break (outcome, n);
            }
            Ok(httparse::Status::Partial) => {}
            Err(httparse::Error::TooManyHeaders) => {
                break (Err(refuse(431, "too many headers")), 0);
            }
            Err(e) => break (Err(refuse(400, format!("malformed request: {e}"))), 0),
        }
        if buf.len() >= settings.max_header_bytes {
            break (Err(refuse(431, "request headers too large")), 0);
        }
        let room = settings.max_header_bytes - buf.len();
        let mut chunk = vec![0u8; room.min(4096)];
        let n = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| UpgradeError::Timeout)??;
        if n == 0 {
            return Err(UpgradeError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    match outcome {
        Ok(handshake) => {
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n",
                handshake.accept_key
            );
            tokio::time::timeout_at(deadline, stream.write_all(response.as_bytes()))
                .await
                .map_err(|_| UpgradeError::Timeout)??;
            buf.advance(consumed);
            Ok((buf, handshake.forwarded_for))
        }
        Err(refusal) => {
            let mut response = format!(
                "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: 0\r\n",
                refusal.status,
                reason_phrase(refusal.status)
            );
            if let Some(h) = refusal.extra_header {
                response.push_str(h);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            let _ = tokio::time::timeout_at(deadline, stream.write_all(response.as_bytes())).await;
            let _ = stream.shutdown().await;
            Err(UpgradeError::Refused {
                status: refusal.status,
                detail: refusal.detail,
            })
        }
    }
}

// ── Frames ─────────────────────────────────────────────────────────────────────────────────

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// What a client frame means for the connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Payload of a binary message (or a fragment of one): MQTT bytes.
    Data(BytesMut),
    Ping(BytesMut),
    Pong,
    Close,
}

/// Incremental parser of client-to-server frames (RFC 6455 §5).
#[derive(Debug)]
pub struct FrameDecoder {
    max_frame_size: usize,
    /// A fragmented binary message is in progress.
    in_message: bool,
}

impl FrameDecoder {
    pub fn new(max_frame_size: usize) -> Self {
        Self {
            max_frame_size,
            in_message: false,
        }
    }

    /// Decodes the next frame from `buf`. `Ok(None)` means more bytes are needed; `Err` carries
    /// the close status code to send before closing the connection.
    pub fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Event>, u16> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let (b0, b1) = (buf[0], buf[1]);
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0F;
        // No extension is negotiated, so the reserved bits must be clear (§5.2).
        if b0 & 0x70 != 0 {
            return Err(close::PROTOCOL_ERROR);
        }
        // Every client frame must be masked (§5.1).
        if b1 & 0x80 == 0 {
            return Err(close::PROTOCOL_ERROR);
        }
        let (len, header) = match b1 & 0x7F {
            126 => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
            }
            127 => {
                if buf.len() < 10 {
                    return Ok(None);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[2..10]);
                let len = u64::from_be_bytes(b);
                if len >> 63 != 0 {
                    return Err(close::PROTOCOL_ERROR);
                }
                (len, 10)
            }
            n => (u64::from(n), 2),
        };
        let control = opcode & 0x08 != 0;
        if control && (!fin || len > 125) {
            return Err(close::PROTOCOL_ERROR);
        }
        if !matches!(
            opcode,
            OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
        ) {
            return Err(close::PROTOCOL_ERROR);
        }
        // MQTT is carried in binary frames only (MQTT-6.0.0-1).
        if opcode == OP_TEXT || (opcode == OP_CONTINUATION && !self.in_message) {
            return Err(if opcode == OP_TEXT {
                close::UNSUPPORTED_DATA
            } else {
                close::PROTOCOL_ERROR
            });
        }
        if opcode == OP_BINARY && self.in_message {
            return Err(close::PROTOCOL_ERROR);
        }
        if len > self.max_frame_size as u64 {
            return Err(close::MESSAGE_TOO_BIG);
        }
        let len = len as usize;
        let total = header + 4 + len;
        if buf.len() < total {
            buf.reserve(total - buf.len());
            return Ok(None);
        }
        let mask = [
            buf[header],
            buf[header + 1],
            buf[header + 2],
            buf[header + 3],
        ];
        buf.advance(header + 4);
        let mut payload = buf.split_to(len);
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
        Ok(Some(match opcode {
            OP_BINARY | OP_CONTINUATION => {
                self.in_message = !fin;
                Event::Data(payload)
            }
            OP_PING => Event::Ping(payload),
            OP_PONG => Event::Pong,
            _ => Event::Close,
        }))
    }
}

/// Appends a server-to-client frame (never masked, §5.1).
pub fn encode_frame(opcode: u8, payload: &[u8], out: &mut BytesMut) {
    out.put_u8(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.put_u8(n as u8),
        n if n <= u16::MAX as usize => {
            out.put_u8(126);
            out.put_u16(n as u16);
        }
        n => {
            out.put_u8(127);
            out.put_u64(n as u64);
        }
    }
    out.extend_from_slice(payload);
}

fn close_payload(code: u16) -> [u8; 2] {
    code.to_be_bytes()
}

// ── Pump ───────────────────────────────────────────────────────────────────────────────────

enum Control {
    Pong(BytesMut),
    /// Send a Close frame with this code (`None`: the peer is gone, just close).
    Close(Option<u16>),
}

/// Starts the frame pump for an upgraded connection and returns the byte stream the MQTT
/// connection handler uses. The pump ends when either side closes.
pub fn spawn_pump<S>(stream: S, leftover: BytesMut, max_frame_size: usize) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (app, pipe) = tokio::io::duplex(PIPE_CAPACITY);
    tokio::spawn(pump(stream, leftover, pipe, max_frame_size));
    app
}

async fn pump<S>(stream: S, leftover: BytesMut, pipe: DuplexStream, max_frame_size: usize)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut net_rd, mut net_wr) = tokio::io::split(stream);
    let (mut pipe_rd, mut pipe_wr) = tokio::io::split(pipe);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Control>(16);

    // Client → broker: frames in, MQTT bytes out. Only this task reads the socket.
    let inbound = tokio::spawn(async move {
        let code = inbound_loop(
            &mut net_rd,
            leftover,
            &mut pipe_wr,
            &ctrl_tx,
            max_frame_size,
        )
        .await;
        // The connection handler sees end-of-stream (an abnormal close unless it got
        // DISCONNECT), then the client gets its Close frame.
        let _ = pipe_wr.shutdown().await;
        let _ = ctrl_tx.send(Control::Close(code)).await;
    });

    // Broker → client: MQTT bytes in, binary frames out. Only this task writes the socket.
    let mut chunk = vec![0u8; 16 * 1024];
    let mut out = BytesMut::with_capacity(16 * 1024 + 14);
    let final_code = loop {
        out.clear();
        tokio::select! {
            biased;
            ctrl = ctrl_rx.recv() => match ctrl {
                Some(Control::Pong(payload)) => encode_frame(OP_PONG, &payload, &mut out),
                Some(Control::Close(code)) => break code,
                None => break None,
            },
            n = pipe_rd.read(&mut chunk) => match n {
                Ok(0) | Err(_) => break Some(close::NORMAL),
                Ok(n) => encode_frame(OP_BINARY, &chunk[..n], &mut out),
            },
        }
        if net_wr.write_all(&out).await.is_err() || net_wr.flush().await.is_err() {
            break None;
        }
    };
    if let Some(code) = final_code {
        out.clear();
        encode_frame(OP_CLOSE, &close_payload(code), &mut out);
        let _ = net_wr.write_all(&out).await;
        let _ = net_wr.flush().await;
    }
    let _ = net_wr.shutdown().await;
    inbound.abort();
}

/// Returns the close code to answer with, or `None` when the client is gone.
async fn inbound_loop<R, W>(
    net: &mut R,
    mut buf: BytesMut,
    app: &mut W,
    ctrl: &mpsc::Sender<Control>,
    max_frame_size: usize,
) -> Option<u16>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = FrameDecoder::new(max_frame_size);
    loop {
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(Event::Data(bytes))) => {
                    if app.write_all(&bytes).await.is_err() {
                        return Some(close::GOING_AWAY);
                    }
                }
                Ok(Some(Event::Ping(payload))) => {
                    if ctrl.send(Control::Pong(payload)).await.is_err() {
                        return None;
                    }
                }
                Ok(Some(Event::Pong)) => {}
                // The client closes: answer with a normal close (RFC 6455 §5.5.1).
                Ok(Some(Event::Close)) => return Some(close::NORMAL),
                Ok(None) => break,
                Err(code) => return Some(code),
            }
        }
        match net.read_buf(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> WsSettings {
        WsSettings {
            allowed_origins: vec!["https://app.example.com".into()],
            trusted_proxies: vec!["10.0.0.1".parse().unwrap()],
            ..Default::default()
        }
    }

    fn request<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        let mut h = vec![
            ("Host", "broker.example.com"),
            ("Upgrade", "websocket"),
            ("Connection", "keep-alive, Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Protocol", "mqttv3.1, mqtt"),
        ];
        h.extend_from_slice(extra);
        h
    }

    #[test]
    fn accept_key_matches_rfc6455_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn valid_upgrade_is_accepted() {
        let h = check_request("GET", "/mqtt?x=1", &request(&[]), &settings(), None).unwrap();
        assert_eq!(h.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(h.forwarded_for, None);
    }

    #[test]
    fn invalid_upgrades_are_refused() {
        let s = settings();
        let status = |method: &str, path: &str, headers: Vec<(&str, &str)>| {
            check_request(method, path, &headers, &s, None)
                .unwrap_err()
                .status
        };
        assert_eq!(status("POST", "/mqtt", request(&[])), 405);
        assert_eq!(status("GET", "/other", request(&[])), 404);
        let mut no_proto = request(&[]);
        no_proto.retain(|(n, _)| *n != "Sec-WebSocket-Protocol");
        assert_eq!(status("GET", "/mqtt", no_proto), 400);
        let mut v8 = request(&[]);
        v8.retain(|(n, _)| *n != "Sec-WebSocket-Version");
        v8.push(("Sec-WebSocket-Version", "8"));
        let r = check_request("GET", "/mqtt", &v8, &s, None).unwrap_err();
        assert_eq!(
            (r.status, r.extra_header),
            (426, Some("Sec-WebSocket-Version: 13"))
        );
        let mut plain_http = request(&[]);
        plain_http.retain(|(n, _)| *n != "Upgrade");
        assert_eq!(status("GET", "/mqtt", plain_http), 426);
        let mut bad_key = request(&[]);
        bad_key.retain(|(n, _)| *n != "Sec-WebSocket-Key");
        bad_key.push(("Sec-WebSocket-Key", "short"));
        assert_eq!(status("GET", "/mqtt", bad_key), 400);
        // Subprotocol names are case-sensitive.
        let mut upper = request(&[]);
        upper.retain(|(n, _)| *n != "Sec-WebSocket-Protocol");
        upper.push(("Sec-WebSocket-Protocol", "MQTT"));
        assert_eq!(status("GET", "/mqtt", upper), 400);
    }

    #[test]
    fn origins_are_checked_only_for_browsers() {
        let s = settings();
        let ok = request(&[("Origin", "https://APP.example.com")]);
        assert!(check_request("GET", "/mqtt", &ok, &s, None).is_ok());
        let evil = request(&[("Origin", "https://evil.example")]);
        assert_eq!(
            check_request("GET", "/mqtt", &evil, &s, None)
                .unwrap_err()
                .status,
            403
        );
        let any = WsSettings {
            allowed_origins: vec!["*".into()],
            ..Default::default()
        };
        assert!(check_request("GET", "/mqtt", &evil, &any, None).is_ok());
    }

    #[test]
    fn forwarded_for_is_trusted_only_from_proxies() {
        let s = settings();
        let h = request(&[("X-Forwarded-For", "203.0.113.9, 198.51.100.7")]);
        let from_proxy = check_request("GET", "/mqtt", &h, &s, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(
            from_proxy.unwrap().forwarded_for,
            Some("198.51.100.7".parse().unwrap())
        );
        let direct = check_request("GET", "/mqtt", &h, &s, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(direct.unwrap().forwarded_for, None);
    }

    fn client_frame(first: u8, payload: &[u8]) -> BytesMut {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut out = BytesMut::new();
        out.put_u8(first);
        match payload.len() {
            n if n < 126 => out.put_u8(0x80 | n as u8),
            n if n <= 65535 => {
                out.put_u8(0x80 | 126);
                out.put_u16(n as u16);
            }
            n => {
                out.put_u8(0x80 | 127);
                out.put_u64(n as u64);
            }
        }
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        out
    }

    #[test]
    fn frames_are_unmasked_and_fragments_reassembled_in_order() {
        let mut d = FrameDecoder::new(1 << 20);
        let mut buf = client_frame(0x02, b"ab"); // binary, not final
        buf.extend_from_slice(&client_frame(0x89, b"hi")); // ping between fragments
        buf.extend_from_slice(&client_frame(0x80, b"cd")); // final continuation
        let big = vec![7u8; 70_000];
        buf.extend_from_slice(&client_frame(0x82, &big));
        assert_eq!(
            d.decode(&mut buf),
            Ok(Some(Event::Data(BytesMut::from(&b"ab"[..]))))
        );
        assert_eq!(
            d.decode(&mut buf),
            Ok(Some(Event::Ping(BytesMut::from(&b"hi"[..]))))
        );
        assert_eq!(
            d.decode(&mut buf),
            Ok(Some(Event::Data(BytesMut::from(&b"cd"[..]))))
        );
        assert_eq!(
            d.decode(&mut buf),
            Ok(Some(Event::Data(BytesMut::from(&big[..]))))
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_frames_wait_for_more_bytes() {
        let mut d = FrameDecoder::new(1 << 20);
        let full = client_frame(0x82, &[1u8; 300]);
        let mut buf = BytesMut::from(&full[..3]);
        assert_eq!(d.decode(&mut buf), Ok(None));
        buf.extend_from_slice(&full[3..100]);
        assert_eq!(d.decode(&mut buf), Ok(None));
        buf.extend_from_slice(&full[100..]);
        assert!(matches!(d.decode(&mut buf), Ok(Some(Event::Data(p))) if p.len() == 300));
    }

    #[test]
    fn protocol_violations_map_to_close_codes() {
        let decode = |bytes: BytesMut| FrameDecoder::new(1024).decode(&mut bytes.clone());
        // Unmasked client frame.
        assert_eq!(
            decode(BytesMut::from(&[0x82u8, 0x01, 0x00][..])),
            Err(close::PROTOCOL_ERROR)
        );
        // Text frame (MQTT-6.0.0-1).
        assert_eq!(
            decode(client_frame(0x81, b"x")),
            Err(close::UNSUPPORTED_DATA)
        );
        // Reserved bit set (no extension negotiated, e.g. no compression).
        assert_eq!(decode(client_frame(0xC2, b"x")), Err(close::PROTOCOL_ERROR));
        // Unknown opcode, fragmented control frame, oversized control frame.
        assert_eq!(decode(client_frame(0x83, b"x")), Err(close::PROTOCOL_ERROR));
        assert_eq!(decode(client_frame(0x09, b"x")), Err(close::PROTOCOL_ERROR));
        assert_eq!(
            decode(client_frame(0x89, &[0u8; 126])),
            Err(close::PROTOCOL_ERROR)
        );
        // Continuation without a message in progress.
        assert_eq!(decode(client_frame(0x80, b"x")), Err(close::PROTOCOL_ERROR));
        // Frame larger than the limit: refused before its payload is buffered.
        let mut huge = BytesMut::new();
        huge.extend_from_slice(&[0x82, 0x80 | 127]);
        huge.put_u64(10 * 1024 * 1024);
        assert_eq!(decode(huge), Err(close::MESSAGE_TOO_BIG));
        // A new binary message while a fragmented one is in progress.
        let mut d = FrameDecoder::new(1024);
        let mut buf = client_frame(0x02, b"a");
        buf.extend_from_slice(&client_frame(0x82, b"b"));
        assert!(d.decode(&mut buf).unwrap().is_some());
        assert_eq!(d.decode(&mut buf), Err(close::PROTOCOL_ERROR));
    }

    #[test]
    fn server_frames_use_minimal_unmasked_headers() {
        let mut out = BytesMut::new();
        encode_frame(OP_BINARY, &[1, 2, 3], &mut out);
        assert_eq!(&out[..], &[0x82, 3, 1, 2, 3]);
        out.clear();
        encode_frame(OP_BINARY, &[0u8; 300], &mut out);
        assert_eq!(&out[..4], &[0x82, 126, 0x01, 0x2C]);
        out.clear();
        encode_frame(OP_BINARY, &vec![0u8; 70_000], &mut out);
        assert_eq!(out[1], 127);
        assert_eq!(out.len(), 10 + 70_000);
    }
}
