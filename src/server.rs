//! TCP, wolfSSL TLS and WebSocket listeners for MQTT v3.1.1 / v5.0.

use crate::broker::BrokerContext;
use crate::connection::{serve, PeerInfo};
use crate::tls::WolfTlsAcceptor;
use crate::ws::{self, WsSettings};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Decrements the active connection gauge when a connection task ends.
struct ConnectionSlot(BrokerContext);

impl ConnectionSlot {
    /// Reserves a connection slot, or returns `None` when `max_connections` is reached.
    fn acquire(ctx: &BrokerContext) -> Option<Self> {
        let max = ctx.options.max_connections;
        let active = ctx
            .metrics
            .connections_active
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        if max != 0 && active > max {
            ctx.metrics
                .connections_active
                .fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        ctx.metrics
            .connections_total
            .fetch_add(1, Ordering::Relaxed);
        Some(Self(ctx.clone()))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0
            .metrics
            .connections_active
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// An MQTT listener on one socket address: plain TCP or TLS, optionally carrying MQTT over
/// WebSockets.
pub struct BrokerServer {
    listener: TcpListener,
    context: BrokerContext,
    tls: Option<WolfTlsAcceptor>,
    ws: Option<Arc<WsSettings>>,
}

impl BrokerServer {
    /// Binds a listener (use port 0 for an ephemeral port) serving the given broker state.
    pub async fn bind(addr: &str, context: BrokerContext) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            context,
            tls: None,
            ws: None,
        })
    }

    /// Serves MQTT over wolfSSL TLS instead of plain TCP.
    pub fn with_tls(mut self, acceptor: WolfTlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    /// Carries MQTT inside WebSocket frames (after the TLS handshake, if any).
    pub fn with_websocket(mut self, settings: WsSettings) -> Self {
        self.ws = Some(Arc::new(settings));
        self
    }

    fn kind(&self) -> &'static str {
        match (self.tls.is_some(), self.ws.is_some()) {
            (false, false) => "TCP",
            (true, false) => "TLS",
            (false, true) => "WebSocket",
            (true, true) => "WebSocket TLS",
        }
    }

    pub fn context(&self) -> &BrokerContext {
        &self.context
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Accepts connections until the broker shuts down.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let kind = self.kind();
        info!(
            "MQTT {} listener running on {}",
            kind,
            self.listener.local_addr()?
        );
        let mut shutdown = self.context.shutdown_signal();
        loop {
            let accepted = tokio::select! {
                r = self.listener.accept() => r,
                _ = shutdown.changed() => {
                    info!("MQTT {} listener stopped", kind);
                    return Ok(());
                }
            };
            let (stream, peer) = match accepted {
                Ok(v) => v,
                Err(e) => {
                    // Typically EMFILE/ENFILE: keep the listener alive and back off briefly.
                    error!("accept() failed on {} listener: {}", kind, e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Some(slot) = ConnectionSlot::acquire(&self.context) else {
                warn!("Connection limit reached; rejecting {}", peer);
                drop(stream);
                continue;
            };
            let _ = stream.set_nodelay(true);
            let ctx = self.context.clone();
            let tls = self.tls.clone();
            let ws = self.ws.clone();
            tokio::spawn(async move {
                let _slot = slot;
                handle_socket(stream, peer, tls, ws, ctx).await;
            });
        }
    }
}

async fn handle_socket(
    stream: TcpStream,
    peer: SocketAddr,
    tls: Option<WolfTlsAcceptor>,
    ws: Option<Arc<WsSettings>>,
    ctx: BrokerContext,
) {
    let Some(acceptor) = tls else {
        debug!("TCP connection from {}", peer);
        let info = PeerInfo {
            addr: Some(peer),
            tls_identities: None,
        };
        serve_transport(stream, info, ws, ctx).await;
        return;
    };
    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            let identities = acceptor.is_mutual().then(|| tls_stream.peer_identities());
            debug!(
                "TLS handshake with {} complete ({}, client identities: {:?})",
                peer,
                tls_stream.protocol_version(),
                identities
            );
            let info = PeerInfo {
                addr: Some(peer),
                tls_identities: identities,
            };
            serve_transport(tls_stream, info, ws, ctx).await;
        }
        Err(e) => warn!("TLS handshake with {} failed: {}", peer, e),
    }
}

/// Runs the MQTT connection directly on the stream, or inside WebSocket frames.
async fn serve_transport<S>(
    mut stream: S,
    mut info: PeerInfo,
    ws: Option<Arc<WsSettings>>,
    ctx: BrokerContext,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let Some(settings) = ws else {
        serve(stream, info, ctx).await;
        return;
    };
    // The upgrade counts against the CONNECT deadline: slow or idle HTTP clients are dropped.
    let deadline = tokio::time::Instant::now() + ctx.options.connect_timeout;
    match ws::accept(&mut stream, info.addr, &settings, deadline).await {
        Ok((leftover, forwarded_for)) => {
            if let Some(ip) = forwarded_for {
                debug!("WebSocket client {} via proxy {:?}", ip, info.addr);
                info.addr = Some(SocketAddr::new(ip, 0));
            }
            let pipe = ws::spawn_pump(stream, leftover, settings.max_frame_size);
            serve(pipe, info, ctx).await;
        }
        Err(e) => debug!("WebSocket upgrade from {:?} failed: {}", info.addr, e),
    }
}
