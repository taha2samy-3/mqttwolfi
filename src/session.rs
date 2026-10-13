//! Transport-independent MQTT session state (OASIS MQTT v5.0 §4.1).
//!
//! A session outlives a single network connection when its Session Expiry Interval is non-zero
//! (MQTT v3.1.1: `CleanSession = 0`). It owns the outbound queue, the outbound QoS 1/2 inflight
//! window with its packet identifiers, the inbound QoS 2 de-duplication set and the Will Message.

use crate::auth::UserAccount;
use crate::protocol::{PublishPacket, QoS};
use crate::queue::{OutboundQueue, QueueLimits};
use crate::routing::SessionId;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Mqtt,
    MqttSn,
}

/// Outbound QoS 1/2 message waiting for acknowledgement.
#[derive(Debug, Clone)]
pub enum InflightOut {
    /// PUBLISH sent (or about to be sent); waiting for PUBACK (QoS 1) or PUBREC (QoS 2).
    Publish(PublishPacket),
    /// PUBREL sent; waiting for PUBCOMP.
    PubRel,
}

/// Link between a session and the connection currently attached to it.
#[derive(Debug)]
pub struct Attachment {
    pub epoch: u64,
    /// Tells the connection to close with the given MQTT v5.0 reason code.
    pub kick: Option<oneshot::Sender<u8>>,
    /// Resolves once the connection has fully released the session.
    pub released: Option<oneshot::Receiver<()>>,
}

#[derive(Debug)]
pub struct SessionState {
    pub user: Arc<UserAccount>,
    /// Seconds the session survives after its connection closes (0 = ends with the connection).
    pub expiry_interval: u32,
    pub attachment: Option<Attachment>,
    pub disconnected_at: Option<Instant>,
    /// Will of the current connection (cleared by a normal DISCONNECT).
    pub will: Option<PublishPacket>,
    /// Will scheduled after disconnect because of a Will Delay Interval.
    pub pending_will: Option<(PublishPacket, Instant)>,
    pub inflight: BTreeMap<u16, InflightOut>,
    next_packet_id: u16,
    /// Inbound QoS 2 packet ids for which PUBREC was sent and PUBREL is awaited.
    pub inbound_qos2: HashSet<u16>,
    next_epoch: u64,
}

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub client_id: String,
    pub transport: Transport,
    pub queue: OutboundQueue,
    state: Mutex<SessionState>,
}

impl Session {
    pub fn new(
        id: SessionId,
        client_id: String,
        transport: Transport,
        user: Arc<UserAccount>,
        expiry_interval: u32,
        limits: QueueLimits,
    ) -> Self {
        Self {
            id,
            client_id,
            transport,
            queue: OutboundQueue::new(limits),
            state: Mutex::new(SessionState {
                user,
                expiry_interval,
                attachment: None,
                disconnected_at: None,
                will: None,
                pending_will: None,
                inflight: BTreeMap::new(),
                next_packet_id: 1,
                inbound_qos2: HashSet::new(),
                next_epoch: 1,
            }),
        }
    }

    pub fn state(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn user(&self) -> Arc<UserAccount> {
        Arc::clone(&self.state().user)
    }

    pub fn is_connected(&self) -> bool {
        self.state().attachment.is_some()
    }
}

impl SessionState {
    /// Allocates the next free outbound packet identifier (never 0, never one still inflight).
    /// Returns `None` when all 65535 identifiers are in use.
    pub fn allocate_packet_id(&mut self) -> Option<u16> {
        for _ in 0..u16::MAX {
            let candidate = self.next_packet_id;
            self.next_packet_id = self.next_packet_id.checked_add(1).unwrap_or(1);
            if !self.inflight.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Records an outbound QoS > 0 PUBLISH; returns the packet with its identifier set.
    pub fn track_outbound(&mut self, mut publish: PublishPacket) -> Option<PublishPacket> {
        debug_assert!(publish.qos != QoS::AtMostOnce);
        let pid = self.allocate_packet_id()?;
        publish.packet_id = Some(pid);
        self.inflight
            .insert(pid, InflightOut::Publish(publish.clone()));
        Some(publish)
    }

    /// Number of unacknowledged outbound QoS 1/2 messages.
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    pub(crate) fn new_epoch(&mut self) -> u64 {
        let e = self.next_epoch;
        self.next_epoch += 1;
        e
    }

    pub fn current_epoch(&self) -> Option<u64> {
        self.attachment.as_ref().map(|a| a.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::UserAccount;
    use bytes::Bytes;

    fn session() -> Session {
        Session::new(
            1,
            "c".into(),
            Transport::Mqtt,
            Arc::new(UserAccount::new_custom("u", "", vec![])),
            0,
            QueueLimits::default(),
        )
    }

    #[test]
    fn packet_ids_skip_zero_and_inflight_entries() {
        let s = session();
        let mut st = s.state();
        let m = PublishPacket::new("t", Bytes::new()).with_qos(QoS::AtLeastOnce, None);
        let a = st.track_outbound(m.clone()).unwrap().packet_id.unwrap();
        assert_eq!(a, 1);
        st.next_packet_id = u16::MAX;
        assert_eq!(st.allocate_packet_id(), Some(u16::MAX));
        // Wraps to 1, which is inflight, so 2 is chosen.
        assert_eq!(st.allocate_packet_id(), Some(2));
    }

    #[test]
    fn exhausted_packet_id_space_is_reported() {
        let s = session();
        let mut st = s.state();
        for pid in 1..=u16::MAX {
            st.inflight.insert(pid, InflightOut::PubRel);
        }
        assert_eq!(st.allocate_packet_id(), None);
    }
}
