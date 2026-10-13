//! Transport-independent MQTT session state (OASIS MQTT v5.0 §4.1).
//!
//! A session outlives a single network connection when its Session Expiry Interval is non-zero
//! (MQTT v3.1.1: `CleanSession = 0`). It owns the outbound queue, the outbound QoS 1/2 inflight
//! window with its packet identifiers, the inbound QoS 2 de-duplication set and the Will Message.

use crate::auth::UserAccount;
use crate::protocol::{PublishPacket, QoS};
use crate::queue::{OutboundQueue, QueueLimits};
use crate::routing::SessionId;
use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone)]
struct InflightEntry {
    /// Send order, so a resumed session resends in the original order even after the packet
    /// identifiers wrapped around (§4.6, MQTT-4.6.0-1).
    seq: u64,
    item: InflightOut,
}

/// Result of a PUBREC for an outbound QoS 2 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubRecOutcome {
    /// The message is now released; PUBREL must be sent and PUBCOMP awaited.
    Release,
    /// The receiver refused the message (reason code >= 0x80); the flow ends here.
    Ended,
    /// No outbound QoS 2 message with this packet identifier.
    Unknown,
}

/// A Will Message waiting for its Will Delay Interval, with the account that set it.
#[derive(Debug, Clone)]
pub struct PendingWill {
    pub message: PublishPacket,
    pub owner: Arc<UserAccount>,
    pub due: Instant,
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
    /// Will scheduled after disconnect because of a Will Delay Interval.
    pub pending_will: Option<PendingWill>,
    inflight: HashMap<u16, InflightEntry>,
    inflight_bytes: usize,
    next_seq: u64,
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
                pending_will: None,
                inflight: HashMap::new(),
                inflight_bytes: 0,
                next_seq: 0,
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

fn publish_size(p: &PublishPacket) -> usize {
    p.topic.len() + p.payload.len()
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
        self.inflight_bytes += publish_size(&publish);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.inflight.insert(
            pid,
            InflightEntry {
                seq,
                item: InflightOut::Publish(publish.clone()),
            },
        );
        Some(publish)
    }

    fn remove(&mut self, pid: u16) -> Option<InflightOut> {
        let entry = self.inflight.remove(&pid)?;
        if let InflightOut::Publish(p) = &entry.item {
            self.inflight_bytes -= publish_size(p);
        }
        Some(entry.item)
    }

    /// Handles PUBACK; returns true when it acknowledged an outbound QoS 1 message.
    pub fn complete_qos1(&mut self, pid: u16) -> bool {
        let hit = matches!(
            self.inflight.get(&pid).map(|e| &e.item),
            Some(InflightOut::Publish(p)) if p.qos == QoS::AtLeastOnce
        );
        if hit {
            self.remove(pid);
        }
        hit
    }

    /// Handles PUBREC for an outbound QoS 2 message.
    pub fn pubrec(&mut self, pid: u16, refused: bool) -> PubRecOutcome {
        let known = match self.inflight.get(&pid).map(|e| &e.item) {
            Some(InflightOut::Publish(p)) => p.qos == QoS::ExactlyOnce,
            Some(InflightOut::PubRel) => true,
            None => false,
        };
        if !known {
            return PubRecOutcome::Unknown;
        }
        if refused {
            self.remove(pid);
            return PubRecOutcome::Ended;
        }
        if let Some(entry) = self.inflight.get_mut(&pid) {
            if let InflightOut::Publish(p) = &entry.item {
                self.inflight_bytes -= publish_size(p);
            }
            entry.item = InflightOut::PubRel;
        }
        PubRecOutcome::Release
    }

    /// Handles PUBCOMP; returns true when it completed an outbound QoS 2 flow.
    pub fn complete_qos2(&mut self, pid: u16) -> bool {
        let hit = matches!(self.inflight.get(&pid).map(|e| &e.item), Some(InflightOut::PubRel));
        if hit {
            self.remove(pid);
        }
        hit
    }

    /// Drops an inflight entry (e.g. a message that could not be sent).
    pub fn forget(&mut self, pid: u16) {
        self.remove(pid);
    }

    /// Unacknowledged messages in their original send order, for resending on resume.
    pub fn resend_list(&self) -> Vec<(u16, InflightOut)> {
        let mut entries: Vec<(u64, u16, InflightOut)> = self
            .inflight
            .iter()
            .map(|(pid, e)| (e.seq, *pid, e.item.clone()))
            .collect();
        entries.sort_by_key(|(seq, _, _)| *seq);
        entries.into_iter().map(|(_, pid, item)| (pid, item)).collect()
    }

    /// Number of unacknowledged outbound QoS 1/2 messages.
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Topic + payload bytes held by unacknowledged outbound PUBLISH packets.
    pub fn inflight_bytes(&self) -> usize {
        self.inflight_bytes
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

    fn qos(q: QoS, payload: &'static [u8]) -> PublishPacket {
        PublishPacket::new("t", Bytes::from_static(payload)).with_qos(q, None)
    }

    #[test]
    fn packet_ids_skip_zero_and_inflight_entries() {
        let s = session();
        let mut st = s.state();
        let a = st.track_outbound(qos(QoS::AtLeastOnce, b"")).unwrap().packet_id.unwrap();
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
        for _ in 1..=u16::MAX {
            st.track_outbound(qos(QoS::AtLeastOnce, b"")).unwrap();
        }
        assert_eq!(st.allocate_packet_id(), None);
    }

    #[test]
    fn qos_flows_update_counts_and_bytes() {
        let s = session();
        let mut st = s.state();
        let p1 = st.track_outbound(qos(QoS::AtLeastOnce, b"1234")).unwrap().packet_id.unwrap();
        let p2 = st.track_outbound(qos(QoS::ExactlyOnce, b"12")).unwrap().packet_id.unwrap();
        assert_eq!((st.inflight_count(), st.inflight_bytes()), (2, 5 + 3));
        assert!(!st.complete_qos1(p2), "PUBACK must not complete a QoS 2 message");
        assert!(st.complete_qos1(p1));
        assert_eq!(st.pubrec(p2, false), PubRecOutcome::Release);
        assert_eq!((st.inflight_count(), st.inflight_bytes()), (1, 0));
        assert_eq!(st.pubrec(p2, false), PubRecOutcome::Release, "duplicate PUBREC");
        assert!(st.complete_qos2(p2));
        assert_eq!(st.pubrec(p2, false), PubRecOutcome::Unknown);
        assert_eq!((st.inflight_count(), st.inflight_bytes()), (0, 0));
    }

    #[test]
    fn resend_order_follows_send_order_across_packet_id_wrap() {
        let s = session();
        let mut st = s.state();
        st.next_packet_id = u16::MAX - 1;
        let ids: Vec<u16> = (0..4)
            .map(|_| st.track_outbound(qos(QoS::AtLeastOnce, b"x")).unwrap().packet_id.unwrap())
            .collect();
        assert_eq!(ids, vec![u16::MAX - 1, u16::MAX, 1, 2]);
        let resend: Vec<u16> = st.resend_list().into_iter().map(|(pid, _)| pid).collect();
        assert_eq!(resend, ids);
    }
}
