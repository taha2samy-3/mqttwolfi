//! TCP and wolfSSL TLS listeners for MQTT v3.1.1 / v5.0.

use crate::broker::BrokerContext;
use crate::connection::{serve, PeerInfo};
use crate::tls::WolfTlsAcceptor;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
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

/// An MQTT listener on one socket address, plain TCP or TLS.
pub struct BrokerServer {
    listener: TcpListener,
    context: BrokerContext,
    tls: Option<WolfTlsAcceptor>,
}

impl BrokerServer {
    /// Binds a listener (use port 0 for an ephemeral port) serving the given broker state.
    pub async fn bind(addr: &str, context: BrokerContext) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            context,
            tls: None,
        })
    }

    /// Serves MQTT over wolfSSL TLS instead of plain TCP.
    pub fn with_tls(mut self, acceptor: WolfTlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    pub fn context(&self) -> &BrokerContext {
        &self.context
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Accepts connections until the broker shuts down.
    pub async fn run(self) -> Result<(), std::io::Error> {
        let kind = if self.tls.is_some() { "TLS" } else { "TCP" };
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
            tokio::spawn(async move {
                let _slot = slot;
                handle_socket(stream, peer, tls, ctx).await;
            });
        }
    }
}

async fn handle_socket(
    stream: TcpStream,
    peer: SocketAddr,
    tls: Option<WolfTlsAcceptor>,
    ctx: BrokerContext,
) {
    let Some(acceptor) = tls else {
        debug!("TCP connection from {}", peer);
        let info = PeerInfo {
            addr: Some(peer),
            tls_identities: None,
        };
        serve(stream, info, ctx).await;
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
            serve(tls_stream, info, ctx).await;
        }
        Err(e) => warn!("TLS handshake with {} failed: {}", peer, e),
    }
}
