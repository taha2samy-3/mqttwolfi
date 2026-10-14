//! Minimal MQTT client used by the bundled tools (simulator, benchmark) and the test-suite.
//!
//! It speaks the wire protocol for one negotiated version, handles the QoS 1/2 publisher flows
//! and buffers packets that arrive while it waits for a specific reply. It does not reconnect
//! or retransmit; it is not intended as a general-purpose application client.

use crate::protocol::{
    ConnectPacket, MqttPacket, Properties, ProtocolVersion, PublishPacket, QoS, SubscriptionOptions,
};
use crate::tls::{WolfTlsConnector, WolfTlsStream};
use bytes::BytesMut;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Plain TCP or wolfSSL TLS stream, or an in-memory pipe (e.g. to a WebSocket adapter).
pub enum ClientStream {
    Tcp(TcpStream),
    Tls(Box<WolfTlsStream>),
    Pipe(tokio::io::DuplexStream),
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            ClientStream::Pipe(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ClientStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            ClientStream::Pipe(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            ClientStream::Pipe(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            ClientStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            ClientStream::Pipe(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Result of a CONNECT exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnAckInfo {
    pub session_present: bool,
    pub reason_code: u8,
    pub properties: Properties,
}

pub struct RawClient {
    stream: ClientStream,
    buf: BytesMut,
    pending: VecDeque<MqttPacket>,
    pub version: ProtocolVersion,
    next_pid: u16,
    /// Default timeout for request/response helpers.
    pub timeout: Duration,
}

impl RawClient {
    pub fn new(stream: ClientStream, version: ProtocolVersion) -> Self {
        Self {
            stream,
            buf: BytesMut::with_capacity(8192),
            pending: VecDeque::new(),
            version,
            next_pid: 1,
            timeout: Duration::from_secs(5),
        }
    }

    /// Opens a TCP connection and performs the CONNECT / CONNACK exchange.
    pub async fn connect(
        addr: impl ToSocketAddrs,
        connect: ConnectPacket,
    ) -> io::Result<(Self, ConnAckInfo)> {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        Self::handshake(ClientStream::Tcp(tcp), connect).await
    }

    /// Opens a TLS connection (verifying the server against `domain`) and connects.
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        domain: &str,
        connector: &WolfTlsConnector,
        connect: ConnectPacket,
    ) -> io::Result<(Self, ConnAckInfo)> {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let tls = connector.connect(domain, tcp).await?;
        Self::handshake(ClientStream::Tls(Box::new(tls)), connect).await
    }

    /// Performs the CONNECT / CONNACK exchange on an already open stream.
    pub async fn handshake(
        stream: ClientStream,
        connect: ConnectPacket,
    ) -> io::Result<(Self, ConnAckInfo)> {
        let mut client = Self::new(stream, connect.version);
        client.send(&MqttPacket::Connect(connect)).await?;
        match client.recv().await? {
            MqttPacket::ConnAck {
                session_present,
                reason_code,
                properties,
            } => Ok((
                client,
                ConnAckInfo {
                    session_present,
                    reason_code,
                    properties,
                },
            )),
            other => Err(invalid(format!("expected CONNACK, got {other:?}"))),
        }
    }

    pub fn next_packet_id(&mut self) -> u16 {
        let pid = self.next_pid;
        self.next_pid = self.next_pid.checked_add(1).unwrap_or(1);
        pid
    }

    pub async fn send(&mut self, pkt: &MqttPacket) -> io::Result<()> {
        let bytes = pkt.to_bytes(self.version).map_err(invalid)?;
        self.send_raw(&bytes).await
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    /// Reads the next packet (buffered packets first). EOF is reported as `UnexpectedEof`.
    pub async fn recv(&mut self) -> io::Result<MqttPacket> {
        if let Some(p) = self.pending.pop_front() {
            return Ok(p);
        }
        self.read_packet().await
    }

    async fn read_packet(&mut self) -> io::Result<MqttPacket> {
        loop {
            if let Some(p) =
                MqttPacket::decode_from(&mut self.buf, self.version, usize::MAX).map_err(invalid)?
            {
                return Ok(p);
            }
            if self.stream.read_buf(&mut self.buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Like [`RawClient::recv`] but returns `Ok(None)` when nothing arrives within `d`.
    pub async fn recv_timeout(&mut self, d: Duration) -> io::Result<Option<MqttPacket>> {
        if let Some(p) = self.pending.pop_front() {
            return Ok(Some(p));
        }
        match tokio::time::timeout(d, self.read_packet()).await {
            Ok(r) => r.map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Waits for the first packet accepted by `pred`, buffering the others.
    pub async fn expect(
        &mut self,
        mut pred: impl FnMut(&MqttPacket) -> bool,
    ) -> io::Result<MqttPacket> {
        if let Some(pos) = self.pending.iter().position(&mut pred) {
            return Ok(self.pending.remove(pos).expect("index valid"));
        }
        let timeout = self.timeout;
        let fut = async {
            loop {
                let p = self.read_packet().await?;
                if pred(&p) {
                    return Ok(p);
                }
                self.pending.push_back(p);
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "expected packet not received"))?
    }

    /// Waits for the next PUBLISH. QoS 1/2 messages are acknowledged automatically
    /// (QoS 2 completes its PUBREC / PUBREL / PUBCOMP flow).
    pub async fn recv_publish(&mut self) -> io::Result<PublishPacket> {
        let p = self.expect(|p| matches!(p, MqttPacket::Publish(_))).await?;
        let MqttPacket::Publish(p) = p else {
            unreachable!()
        };
        self.ack_publish(&p).await?;
        Ok(p)
    }

    /// Acknowledges an incoming PUBLISH according to its QoS.
    pub async fn ack_publish(&mut self, p: &PublishPacket) -> io::Result<()> {
        match (p.qos, p.packet_id) {
            (QoS::AtLeastOnce, Some(pid)) => self.send(&MqttPacket::puback(pid)).await,
            (QoS::ExactlyOnce, Some(pid)) => {
                self.send(&MqttPacket::pubrec(pid)).await?;
                self.expect(
                    |x| matches!(x, MqttPacket::PubRel { packet_id, .. } if *packet_id == pid),
                )
                .await?;
                self.send(&MqttPacket::pubcomp(pid)).await
            }
            _ => Ok(()),
        }
    }

    /// Subscribes to one filter and returns the SUBACK reason code.
    pub async fn subscribe(&mut self, filter: &str, qos: QoS) -> io::Result<u8> {
        let codes = self
            .subscribe_with(
                vec![(filter.to_owned(), SubscriptionOptions::new(qos))],
                Properties::new(),
            )
            .await?;
        Ok(codes[0])
    }

    /// Sends a SUBSCRIBE and returns the SUBACK reason codes.
    pub async fn subscribe_with(
        &mut self,
        filters: Vec<(String, SubscriptionOptions)>,
        properties: Properties,
    ) -> io::Result<Vec<u8>> {
        let pid = self.next_packet_id();
        self.send(&MqttPacket::Subscribe {
            packet_id: pid,
            filters,
            properties,
        })
        .await?;
        match self
            .expect(|p| matches!(p, MqttPacket::SubAck { packet_id, .. } if *packet_id == pid))
            .await?
        {
            MqttPacket::SubAck { reason_codes, .. } => Ok(reason_codes),
            _ => unreachable!(),
        }
    }

    /// Unsubscribes and returns the UNSUBACK reason codes (empty for MQTT v3.1.1).
    pub async fn unsubscribe(&mut self, filters: &[&str]) -> io::Result<Vec<u8>> {
        let pid = self.next_packet_id();
        self.send(&MqttPacket::Unsubscribe {
            packet_id: pid,
            filters: filters.iter().map(|s| s.to_string()).collect(),
        })
        .await?;
        match self
            .expect(|p| matches!(p, MqttPacket::UnsubAck { packet_id, .. } if *packet_id == pid))
            .await?
        {
            MqttPacket::UnsubAck { reason_codes, .. } => Ok(reason_codes),
            _ => unreachable!(),
        }
    }

    /// Publishes a message, completing the QoS 1/2 flow. Returns the broker's reason code
    /// (0 for QoS 0 and for MQTT v3.1.1).
    pub async fn publish(&mut self, mut msg: PublishPacket) -> io::Result<u8> {
        if msg.qos != QoS::AtMostOnce && msg.packet_id.is_none() {
            msg.packet_id = Some(self.next_packet_id());
        }
        let qos = msg.qos;
        let pid = msg.packet_id;
        self.send(&MqttPacket::Publish(msg)).await?;
        let Some(pid) = pid else {
            return Ok(0);
        };
        match qos {
            QoS::AtMostOnce => Ok(0),
            QoS::AtLeastOnce => match self
                .expect(|p| matches!(p, MqttPacket::PubAck { packet_id, .. } if *packet_id == pid))
                .await?
            {
                MqttPacket::PubAck { reason_code, .. } => Ok(reason_code),
                _ => unreachable!(),
            },
            QoS::ExactlyOnce => {
                let rec = self
                    .expect(
                        |p| matches!(p, MqttPacket::PubRec { packet_id, .. } if *packet_id == pid),
                    )
                    .await?;
                let MqttPacket::PubRec { reason_code, .. } = rec else {
                    unreachable!()
                };
                if reason_code >= 0x80 {
                    return Ok(reason_code);
                }
                self.send(&MqttPacket::pubrel(pid)).await?;
                self.expect(
                    |p| matches!(p, MqttPacket::PubComp { packet_id, .. } if *packet_id == pid),
                )
                .await?;
                Ok(reason_code)
            }
        }
    }

    pub async fn ping(&mut self) -> io::Result<()> {
        self.send(&MqttPacket::PingReq).await?;
        self.expect(|p| matches!(p, MqttPacket::PingResp))
            .await
            .map(|_| ())
    }

    /// Sends a normal DISCONNECT and closes the connection.
    pub async fn disconnect(mut self) -> io::Result<()> {
        self.send(&MqttPacket::disconnect(0)).await?;
        self.stream.shutdown().await
    }

    /// Waits until the broker closes the connection; returns the packets received meanwhile.
    pub async fn wait_closed(&mut self, d: Duration) -> io::Result<Vec<MqttPacket>> {
        let mut got: Vec<MqttPacket> = self.pending.drain(..).collect();
        let fut = async {
            loop {
                match self.read_packet().await {
                    Ok(p) => got.push(p),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
        };
        tokio::time::timeout(d, fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection not closed"))??;
        Ok(got)
    }

    /// Access to the underlying stream (e.g. to drop it abruptly).
    pub fn into_stream(self) -> ClientStream {
        self.stream
    }
}
