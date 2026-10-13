b//! MQTT v3.1.1 and v5.0 control packet codec.
//!
//! Every packet is encoded and decoded for an explicit protocol version. MQTT v5.0 property
//! blocks are always parsed and validated (never guessed from payload bytes), and malformed
//! input is rejected with an error that the server maps to the matching reason code.

use crate::protocol::codec::{put_binary, put_string, put_vbi, Reader};
use crate::protocol::properties::{Properties, PropertyContext};
use crate::protocol::vbi::{decode_variable_byte_integer, VbiError};
use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolVersion {
    V311 = 4,
    V500 = 5,
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            4 => Ok(ProtocolVersion::V311),
            5 => Ok(ProtocolVersion::V500),
            other => Err(PacketError::UnsupportedProtocolVersion(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum QoS {
    #[default]
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl TryFrom<u8> for QoS {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QoS::AtMostOnce),
            1 => Ok(QoS::AtLeastOnce),
            2 => Ok(QoS::ExactlyOnce),
            _ => Err(PacketError::InvalidQoS(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    Connect = 1,
    ConnAck = 2,
    Publish = 3,
    PubAck = 4,
    PubRec = 5,
    PubRel = 6,
    PubComp = 7,
    Subscribe = 8,
    SubAck = 9,
    Unsubscribe = 10,
    UnsubAck = 11,
    PingReq = 12,
    PingResp = 13,
    Disconnect = 14,
    Auth = 15,
}

impl TryFrom<u8> for PacketType {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::Connect),
            2 => Ok(PacketType::ConnAck),
            3 => Ok(PacketType::Publish),
            4 => Ok(PacketType::PubAck),
            5 => Ok(PacketType::PubRec),
            6 => Ok(PacketType::PubRel),
            7 => Ok(PacketType::PubComp),
            8 => Ok(PacketType::Subscribe),
            9 => Ok(PacketType::SubAck),
            10 => Ok(PacketType::Unsubscribe),
            11 => Ok(PacketType::UnsubAck),
            12 => Ok(PacketType::PingReq),
            13 => Ok(PacketType::PingResp),
            14 => Ok(PacketType::Disconnect),
            15 => Ok(PacketType::Auth),
            _ => Err(PacketError::InvalidPacketType(value)),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacketError {
    #[error("unsupported protocol version level: {0}")]
    UnsupportedProtocolVersion(u8),
    #[error("protocol name is not 'MQTT'")]
    InvalidProtocolName,
    #[error("invalid packet type: {0}")]
    InvalidPacketType(u8),
    #[error("invalid QoS value: {0}")]
    InvalidQoS(u8),
    #[error("invalid UTF-8 string")]
    InvalidString,
    #[error("malformed packet: {0}")]
    Malformed(&'static str),
    #[error("protocol error: {0}")]
    ProtocolError(&'static str),
    #[error("packet of {size} bytes exceeds the maximum of {max} bytes")]
    PacketTooLarge { size: usize, max: usize },
    #[error("field too long to encode")]
    EncodeTooLong,
}

impl PacketError {
    /// MQTT v5.0 reason code to report this error with (DISCONNECT / CONNACK).
    pub fn reason_code(&self) -> u8 {
        match self {
            PacketError::UnsupportedProtocolVersion(_) => reason::UNSUPPORTED_PROTOCOL_VERSION,
            PacketError::ProtocolError(_) => reason::PROTOCOL_ERROR,
            PacketError::PacketTooLarge { .. } => reason::PACKET_TOO_LARGE,
            _ => reason::MALFORMED_PACKET,
        }
    }
}

/// MQTT v5.0 reason codes (§2.4) used by the broker.
pub mod reason {
    pub const SUCCESS: u8 = 0x00;
    pub const GRANTED_QOS_1: u8 = 0x01;
    pub const GRANTED_QOS_2: u8 = 0x02;
    pub const DISCONNECT_WITH_WILL: u8 = 0x04;
    pub const NO_MATCHING_SUBSCRIBERS: u8 = 0x10;
    pub const NO_SUBSCRIPTION_EXISTED: u8 = 0x11;
    pub const UNSPECIFIED_ERROR: u8 = 0x80;
    pub const MALFORMED_PACKET: u8 = 0x81;
    pub const PROTOCOL_ERROR: u8 = 0x82;
    pub const IMPLEMENTATION_SPECIFIC_ERROR: u8 = 0x83;
    pub const UNSUPPORTED_PROTOCOL_VERSION: u8 = 0x84;
    pub const CLIENT_IDENTIFIER_NOT_VALID: u8 = 0x85;
    pub const BAD_USER_NAME_OR_PASSWORD: u8 = 0x86;
    pub const NOT_AUTHORIZED: u8 = 0x87;
    pub const SERVER_UNAVAILABLE: u8 = 0x88;
    pub const SERVER_BUSY: u8 = 0x89;
    pub const BAD_AUTHENTICATION_METHOD: u8 = 0x8C;
    pub const KEEP_ALIVE_TIMEOUT: u8 = 0x8D;
    pub const SESSION_TAKEN_OVER: u8 = 0x8E;
    pub const TOPIC_FILTER_INVALID: u8 = 0x8F;
    pub const TOPIC_NAME_INVALID: u8 = 0x90;
    pub const PACKET_IDENTIFIER_NOT_FOUND: u8 = 0x92;
    pub const RECEIVE_MAXIMUM_EXCEEDED: u8 = 0x93;
    pub const TOPIC_ALIAS_INVALID: u8 = 0x94;
    pub const PACKET_TOO_LARGE: u8 = 0x95;
    pub const QUOTA_EXCEEDED: u8 = 0x97;
    pub const PAYLOAD_FORMAT_INVALID: u8 = 0x99;
    pub const RETAIN_NOT_SUPPORTED: u8 = 0x9A;
    pub const SERVER_SHUTTING_DOWN: u8 = 0x8B;
    pub const SHARED_SUBSCRIPTIONS_NOT_SUPPORTED: u8 = 0x9E;
    pub const SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED: u8 = 0xA1;
    pub const WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED: u8 = 0xA2;
}

/// MQTT v3.1.1 CONNACK return codes (§3.2.2.3).
pub mod connack_v3 {
    pub const ACCEPTED: u8 = 0x00;
    pub const UNACCEPTABLE_PROTOCOL_VERSION: u8 = 0x01;
    pub const IDENTIFIER_REJECTED: u8 = 0x02;
    pub const SERVER_UNAVAILABLE: u8 = 0x03;
    pub const BAD_USER_NAME_OR_PASSWORD: u8 = 0x04;
    pub const NOT_AUTHORIZED: u8 = 0x05;
}

/// Retain Handling subscription option (MQTT v5.0 §3.8.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetainHandling {
    /// Send retained messages at the time of the subscribe.
    #[default]
    SendAlways = 0,
    /// Send retained messages only if the subscription did not already exist.
    SendIfNew = 1,
    /// Never send retained messages for this subscription.
    DoNotSend = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscriptionOptions {
    pub qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: RetainHandling,
}

impl SubscriptionOptions {
    pub fn new(qos: QoS) -> Self {
        Self {
            qos,
            ..Default::default()
        }
    }

    fn to_byte(self, version: ProtocolVersion) -> u8 {
        let mut b = self.qos as u8;
        if version == ProtocolVersion::V500 {
            if self.no_local {
                b |= 0x04;
            }
            if self.retain_as_published {
                b |= 0x08;
            }
            b |= (self.retain_handling as u8) << 4;
        }
        b
    }

    fn from_byte(b: u8, version: ProtocolVersion) -> Result<Self, PacketError> {
        match version {
            ProtocolVersion::V311 => {
                if b & 0xFC != 0 {
                    return Err(PacketError::Malformed(
                        "reserved subscription option bits set",
                    ));
                }
                Ok(Self::new(QoS::try_from(b & 0x03)?))
            }
            ProtocolVersion::V500 => {
                if b & 0xC0 != 0 {
                    return Err(PacketError::Malformed(
                        "reserved subscription option bits set",
                    ));
                }
                let retain_handling = match (b >> 4) & 0x03 {
                    0 => RetainHandling::SendAlways,
                    1 => RetainHandling::SendIfNew,
                    2 => RetainHandling::DoNotSend,
                    _ => return Err(PacketError::ProtocolError("invalid retain handling value")),
                };
                Ok(Self {
                    qos: QoS::try_from(b & 0x03)?,
                    no_local: b & 0x04 != 0,
                    retain_as_published: b & 0x08 != 0,
                    retain_handling,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishPacket {
    pub topic: String,
    pub qos: QoS,
    pub retain: bool,
    pub dup: bool,
    pub packet_id: Option<u16>,
    pub payload: Bytes,
    /// MQTT v5.0 publish properties (ignored when encoding for v3.1.1).
    pub properties: Properties,
}

impl PublishPacket {
    /// Creates a QoS 0, non-retained message. Use the builder methods to adjust it.
    pub fn new(topic: impl Into<String>, payload: impl Into<Bytes>) -> Self {
        Self {
            topic: topic.into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: payload.into(),
            properties: Properties::new(),
        }
    }

    pub fn with_qos(mut self, qos: QoS, packet_id: Option<u16>) -> Self {
        self.qos = qos;
        self.packet_id = packet_id;
        self
    }

    pub fn with_retain(mut self, retain: bool) -> Self {
        self.retain = retain;
        self
    }

    pub fn with_properties(mut self, properties: Properties) -> Self {
        self.properties = properties;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectPacket {
    pub version: ProtocolVersion,
    pub client_id: String,
    pub clean_start: bool,
    pub keep_alive_sec: u16,
    /// Last Will. For MQTT v5.0 its `properties` carry the Will Properties.
    pub will: Option<PublishPacket>,
    pub username: Option<String>,
    pub password: Option<Bytes>,
    pub properties: Properties,
}

impl Default for ConnectPacket {
    fn default() -> Self {
        Self {
            version: ProtocolVersion::V500,
            client_id: String::new(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
            properties: Properties::new(),
        }
    }
}

impl ConnectPacket {
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            ..Default::default()
        }
    }

    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    pub fn with_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<Bytes>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn with_will(mut self, will: PublishPacket) -> Self {
        self.will = Some(will);
        self
    }

    pub fn with_keep_alive(mut self, keep_alive_sec: u16) -> Self {
        self.keep_alive_sec = keep_alive_sec;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttPacket {
    Connect(ConnectPacket),
    ConnAck {
        session_present: bool,
        /// v5.0 reason code, or v3.1.1 return code.
        reason_code: u8,
        properties: Properties,
    },
    Publish(PublishPacket),
    PubAck {
        packet_id: u16,
        reason_code: u8,
    },
    PubRec {
        packet_id: u16,
        reason_code: u8,
    },
    PubRel {
        packet_id: u16,
        reason_code: u8,
    },
    PubComp {
        packet_id: u16,
        reason_code: u8,
    },
    Subscribe {
        packet_id: u16,
        filters: Vec<(String, SubscriptionOptions)>,
        properties: Properties,
    },
    SubAck {
        packet_id: u16,
        /// v5.0 reason codes, or v3.1.1 return codes.
        reason_codes: Vec<u8>,
    },
    Unsubscribe {
        packet_id: u16,
        filters: Vec<String>,
    },
    UnsubAck {
        packet_id: u16,
        /// One reason code per filter (v5.0 only; not sent to v3.1.1 clients).
        reason_codes: Vec<u8>,
    },
    PingReq,
    PingResp,
    Disconnect {
        reason_code: u8,
        properties: Properties,
    },
    Auth {
        reason_code: u8,
        properties: Properties,
    },
}

impl MqttPacket {
    /// Default upper bound for a single packet (fixed header included).
    pub const DEFAULT_MAX_PACKET_SIZE: usize = 4 * 1024 * 1024;

    pub fn connack(session_present: bool, reason_code: u8) -> Self {
        MqttPacket::ConnAck {
            session_present,
            reason_code,
            properties: Properties::new(),
        }
    }

    pub fn puback(packet_id: u16) -> Self {
        MqttPacket::PubAck {
            packet_id,
            reason_code: reason::SUCCESS,
        }
    }

    pub fn pubrec(packet_id: u16) -> Self {
        MqttPacket::PubRec {
            packet_id,
            reason_code: reason::SUCCESS,
        }
    }

    pub fn pubrel(packet_id: u16) -> Self {
        MqttPacket::PubRel {
            packet_id,
            reason_code: reason::SUCCESS,
        }
    }

    pub fn pubcomp(packet_id: u16) -> Self {
        MqttPacket::PubComp {
            packet_id,
            reason_code: reason::SUCCESS,
        }
    }

    pub fn subscribe(packet_id: u16, filters: Vec<(String, SubscriptionOptions)>) -> Self {
        MqttPacket::Subscribe {
            packet_id,
            filters,
            properties: Properties::new(),
        }
    }

    pub fn disconnect(reason_code: u8) -> Self {
        MqttPacket::Disconnect {
            reason_code,
            properties: Properties::new(),
        }
    }

    pub fn packet_type(&self) -> PacketType {
        match self {
            MqttPacket::Connect(_) => PacketType::Connect,
            MqttPacket::ConnAck { .. } => PacketType::ConnAck,
            MqttPacket::Publish(_) => PacketType::Publish,
            MqttPacket::PubAck { .. } => PacketType::PubAck,
            MqttPacket::PubRec { .. } => PacketType::PubRec,
            MqttPacket::PubRel { .. } => PacketType::PubRel,
            MqttPacket::PubComp { .. } => PacketType::PubComp,
            MqttPacket::Subscribe { .. } => PacketType::Subscribe,
            MqttPacket::SubAck { .. } => PacketType::SubAck,
            MqttPacket::Unsubscribe { .. } => PacketType::Unsubscribe,
            MqttPacket::UnsubAck { .. } => PacketType::UnsubAck,
            MqttPacket::PingReq => PacketType::PingReq,
            MqttPacket::PingResp => PacketType::PingResp,
            MqttPacket::Disconnect { .. } => PacketType::Disconnect,
            MqttPacket::Auth { .. } => PacketType::Auth,
        }
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// Serializes the packet for a peer that negotiated `version`.
    /// CONNECT packets are always encoded with the version stored inside them.
    pub fn encode(&self, version: ProtocolVersion, dst: &mut BytesMut) -> Result<(), PacketError> {
        let v5 = version == ProtocolVersion::V500;
        let mut body = BytesMut::new();
        let flags: u8 = match self {
            MqttPacket::Connect(conn) => {
                encode_connect(conn, &mut body)?;
                0
            }
            MqttPacket::ConnAck {
                session_present,
                reason_code,
                properties,
            } => {
                body.put_u8(u8::from(*session_present));
                body.put_u8(*reason_code);
                if v5 {
                    properties.encode(&mut body)?;
                }
                0
            }
            MqttPacket::Publish(p) => {
                if p.qos == QoS::AtMostOnce && p.dup {
                    return Err(PacketError::Malformed("DUP set on a QoS 0 PUBLISH"));
                }
                put_string(&mut body, &p.topic)?;
                if p.qos != QoS::AtMostOnce {
                    match p.packet_id {
                        Some(pid) if pid != 0 => body.put_u16(pid),
                        _ => {
                            return Err(PacketError::ProtocolError("QoS > 0 requires a packet id"))
                        }
                    }
                }
                if v5 {
                    p.properties.encode(&mut body)?;
                }
                body.put_slice(&p.payload);
                (u8::from(p.dup) << 3) | ((p.qos as u8) << 1) | u8::from(p.retain)
            }
            MqttPacket::PubAck {
                packet_id,
                reason_code,
            }
            | MqttPacket::PubRec {
                packet_id,
                reason_code,
            }
            | MqttPacket::PubRel {
                packet_id,
                reason_code,
            }
            | MqttPacket::PubComp {
                packet_id,
                reason_code,
            } => {
                body.put_u16(*packet_id);
                // v5.0 §3.4.2.1: the reason code may be omitted when it is 0x00 (Success).
                if v5 && *reason_code != reason::SUCCESS {
                    body.put_u8(*reason_code);
                }
                if matches!(self, MqttPacket::PubRel { .. }) {
                    0x02
                } else {
                    0
                }
            }
            MqttPacket::Subscribe {
                packet_id,
                filters,
                properties,
            } => {
                body.put_u16(*packet_id);
                if v5 {
                    properties.encode(&mut body)?;
                }
                for (filter, opts) in filters {
                    put_string(&mut body, filter)?;
                    body.put_u8(opts.to_byte(version));
                }
                0x02
            }
            MqttPacket::SubAck {
                packet_id,
                reason_codes,
            } => {
                body.put_u16(*packet_id);
                if v5 {
                    body.put_u8(0); // no properties
                }
                body.put_slice(reason_codes);
                0
            }
            MqttPacket::Unsubscribe { packet_id, filters } => {
                body.put_u16(*packet_id);
                if v5 {
                    body.put_u8(0);
                }
                for filter in filters {
                    put_string(&mut body, filter)?;
                }
                0x02
            }
            MqttPacket::UnsubAck {
                packet_id,
                reason_codes,
            } => {
                body.put_u16(*packet_id);
                if v5 {
                    body.put_u8(0);
                    body.put_slice(reason_codes);
                }
                0
            }
            MqttPacket::PingReq | MqttPacket::PingResp => 0,
            MqttPacket::Disconnect {
                reason_code,
                properties,
            } => {
                if v5 && (*reason_code != reason::SUCCESS || !properties.is_empty()) {
                    body.put_u8(*reason_code);
                    if !properties.is_empty() {
                        properties.encode(&mut body)?;
                    }
                }
                0
            }
            MqttPacket::Auth {
                reason_code,
                properties,
            } => {
                if !v5 {
                    return Err(PacketError::ProtocolError("AUTH requires MQTT v5.0"));
                }
                body.put_u8(*reason_code);
                properties.encode(&mut body)?;
                0
            }
        };

        dst.put_u8(((self.packet_type() as u8) << 4) | flags);
        put_vbi(dst, body.len() as u32)?;
        dst.put(body);
        Ok(())
    }

    /// Convenience wrapper returning the encoded packet as frozen bytes.
    pub fn to_bytes(&self, version: ProtocolVersion) -> Result<Bytes, PacketError> {
        let mut buf = BytesMut::new();
        self.encode(version, &mut buf)?;
        Ok(buf.freeze())
    }

    // ── Decoding ─────────────────────────────────────────────────────────────

    /// Inspects the fixed header at the start of `buf`.
    ///
    /// Returns `Ok(None)` when more bytes are needed, otherwise the total frame length
    /// (fixed header + remaining length). Frames larger than `max_packet_size` are rejected
    /// before their body is buffered.
    pub fn frame_len(buf: &[u8], max_packet_size: usize) -> Result<Option<usize>, PacketError> {
        if buf.is_empty() {
            return Ok(None);
        }
        let mut header = &buf[1..];
        let before = header.len();
        let remaining = match decode_variable_byte_integer(&mut header) {
            Ok(v) => v as usize,
            Err(VbiError::IncompleteBuffer) => return Ok(None),
            Err(VbiError::MalformedVbi) => {
                return Err(PacketError::Malformed("invalid remaining length"))
            }
        };
        let header_len = 1 + (before - header.len());
        let total = header_len + remaining;
        if total > max_packet_size {
            return Err(PacketError::PacketTooLarge {
                size: total,
                max: max_packet_size,
            });
        }
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some(total))
    }

    /// Decodes one packet from the front of `buf`, consuming it.
    ///
    /// Returns `Ok(None)` (and leaves `buf` untouched) when the packet is incomplete.
    pub fn decode_from(
        buf: &mut BytesMut,
        version: ProtocolVersion,
        max_packet_size: usize,
    ) -> Result<Option<MqttPacket>, PacketError> {
        let Some(total) = Self::frame_len(buf, max_packet_size)? else {
            return Ok(None);
        };
        let frame = buf.split_to(total).freeze();
        Self::decode_frame(frame, version).map(Some)
    }

    /// Decodes one packet from the front of a byte slice without consuming it.
    /// Returns the packet and the number of bytes it occupied.
    pub fn decode(
        buf: &[u8],
        version: ProtocolVersion,
        max_packet_size: usize,
    ) -> Result<Option<(MqttPacket, usize)>, PacketError> {
        let Some(total) = Self::frame_len(buf, max_packet_size)? else {
            return Ok(None);
        };
        let frame = Bytes::copy_from_slice(&buf[..total]);
        Self::decode_frame(frame, version).map(|p| Some((p, total)))
    }

    /// Decodes one complete frame (fixed header included).
    fn decode_frame(mut frame: Bytes, version: ProtocolVersion) -> Result<MqttPacket, PacketError> {
        let first = frame[0];
        let packet_type = PacketType::try_from(first >> 4)?;
        let flags = first & 0x0F;

        // Skip the fixed header; frame_len already validated the remaining length.
        let mut header = &frame[1..];
        let before = header.len();
        let _ = decode_variable_byte_integer(&mut header);
        let header_len = 1 + (before - header.len());
        let body = frame.split_off(header_len);

        // §2.1.3: fixed header flags are reserved for every type except PUBLISH.
        let expected_flags = match packet_type {
            PacketType::Publish => None,
            PacketType::PubRel | PacketType::Subscribe | PacketType::Unsubscribe => Some(0x02),
            _ => Some(0x00),
        };
        if let Some(expected) = expected_flags {
            if flags != expected {
                return Err(PacketError::Malformed("invalid fixed header flags"));
            }
        }

        let v5 = version == ProtocolVersion::V500;
        let mut r = Reader::new(body);
        let packet = match packet_type {
            PacketType::Connect => MqttPacket::Connect(decode_connect(&mut r)?),
            PacketType::ConnAck => {
                let ack_flags = r.u8()?;
                if ack_flags & 0xFE != 0 {
                    return Err(PacketError::Malformed("reserved CONNACK flags set"));
                }
                let reason_code = r.u8()?;
                let properties = if v5 {
                    Properties::decode(&mut r, PropertyContext::Packet(PacketType::ConnAck))?
                } else {
                    Properties::new()
                };
                MqttPacket::ConnAck {
                    session_present: ack_flags & 0x01 != 0,
                    reason_code,
                    properties,
                }
            }
            PacketType::Publish => MqttPacket::Publish(decode_publish(&mut r, flags, version)?),
            PacketType::PubAck | PacketType::PubRec | PacketType::PubRel | PacketType::PubComp => {
                let packet_id = r.u16()?;
                let mut reason_code = reason::SUCCESS;
                if v5 && r.has_remaining() {
                    reason_code = r.u8()?;
                    if r.has_remaining() {
                        Properties::decode(&mut r, PropertyContext::Packet(packet_type))?;
                    }
                }
                match packet_type {
                    PacketType::PubAck => MqttPacket::PubAck {
                        packet_id,
                        reason_code,
                    },
                    PacketType::PubRec => MqttPacket::PubRec {
                        packet_id,
                        reason_code,
                    },
                    PacketType::PubRel => MqttPacket::PubRel {
                        packet_id,
                        reason_code,
                    },
                    _ => MqttPacket::PubComp {
                        packet_id,
                        reason_code,
                    },
                }
            }
            PacketType::Subscribe => {
                let packet_id = nonzero_packet_id(r.u16()?)?;
                let properties = if v5 {
                    Properties::decode(&mut r, PropertyContext::Packet(PacketType::Subscribe))?
                } else {
                    Properties::new()
                };
                let mut filters = Vec::new();
                while r.has_remaining() {
                    let filter = r.string()?;
                    let opts = SubscriptionOptions::from_byte(r.u8()?, version)?;
                    filters.push((filter, opts));
                }
                if filters.is_empty() {
                    return Err(PacketError::ProtocolError(
                        "SUBSCRIBE without topic filters",
                    ));
                }
                MqttPacket::Subscribe {
                    packet_id,
                    filters,
                    properties,
                }
            }
            PacketType::SubAck => {
                let packet_id = r.u16()?;
                if v5 {
                    Properties::decode(&mut r, PropertyContext::Packet(PacketType::SubAck))?;
                }
                let reason_codes = r.rest().to_vec();
                MqttPacket::SubAck {
                    packet_id,
                    reason_codes,
                }
            }
            PacketType::Unsubscribe => {
                let packet_id = nonzero_packet_id(r.u16()?)?;
                if v5 {
                    Properties::decode(&mut r, PropertyContext::Packet(PacketType::Unsubscribe))?;
                }
                let mut filters = Vec::new();
                while r.has_remaining() {
                    filters.push(r.string()?);
                }
                if filters.is_empty() {
                    return Err(PacketError::ProtocolError(
                        "UNSUBSCRIBE without topic filters",
                    ));
                }
                MqttPacket::Unsubscribe { packet_id, filters }
            }
            PacketType::UnsubAck => {
                let packet_id = r.u16()?;
                let reason_codes = if v5 {
                    Properties::decode(&mut r, PropertyContext::Packet(PacketType::UnsubAck))?;
                    r.rest().to_vec()
                } else {
                    Vec::new()
                };
                MqttPacket::UnsubAck {
                    packet_id,
                    reason_codes,
                }
            }
            PacketType::PingReq => MqttPacket::PingReq,
            PacketType::PingResp => MqttPacket::PingResp,
            PacketType::Disconnect => {
                let mut reason_code = reason::SUCCESS;
                let mut properties = Properties::new();
                if v5 && r.has_remaining() {
                    reason_code = r.u8()?;
                    if r.has_remaining() {
                        properties = Properties::decode(
                            &mut r,
                            PropertyContext::Packet(PacketType::Disconnect),
                        )?;
                    }
                }
                MqttPacket::Disconnect {
                    reason_code,
                    properties,
                }
            }
            PacketType::Auth => {
                if !v5 {
                    // Packet type 15 is reserved in MQTT v3.1.1.
                    return Err(PacketError::InvalidPacketType(15));
                }
                let mut reason_code = reason::SUCCESS;
                let mut properties = Properties::new();
                if r.has_remaining() {
                    reason_code = r.u8()?;
                    properties =
                        Properties::decode(&mut r, PropertyContext::Packet(PacketType::Auth))?;
                }
                MqttPacket::Auth {
                    reason_code,
                    properties,
                }
            }
        };

        if r.has_remaining() {
            return Err(PacketError::Malformed(
                "unexpected trailing bytes in packet",
            ));
        }
        Ok(packet)
    }
}

fn nonzero_packet_id(pid: u16) -> Result<u16, PacketError> {
    if pid == 0 {
        Err(PacketError::ProtocolError(
            "packet identifier must be non-zero",
        ))
    } else {
        Ok(pid)
    }
}

/// Returns true when a topic name is valid for PUBLISH (§4.7.3: no wildcards).
pub fn is_valid_topic_name(topic: &str) -> bool {
    !topic.contains(['+', '#'])
}

fn decode_publish(
    r: &mut Reader,
    flags: u8,
    version: ProtocolVersion,
) -> Result<PublishPacket, PacketError> {
    let dup = flags & 0x08 != 0;
    let qos = QoS::try_from((flags >> 1) & 0x03)
        .map_err(|_| PacketError::Malformed("PUBLISH with QoS 3"))?;
    let retain = flags & 0x01 != 0;
    if qos == QoS::AtMostOnce && dup {
        return Err(PacketError::Malformed("DUP set on a QoS 0 PUBLISH"));
    }

    let topic = r.string()?;
    if !is_valid_topic_name(&topic) {
        return Err(PacketError::ProtocolError("wildcard in PUBLISH topic name"));
    }
    // An empty topic name is only legal in v5.0 together with a Topic Alias (checked by the server).
    if topic.is_empty() && version == ProtocolVersion::V311 {
        return Err(PacketError::ProtocolError("empty topic name"));
    }

    let packet_id = if qos != QoS::AtMostOnce {
        Some(nonzero_packet_id(r.u16()?)?)
    } else {
        None
    };

    let properties = if version == ProtocolVersion::V500 {
        Properties::decode(r, PropertyContext::Packet(PacketType::Publish))?
    } else {
        Properties::new()
    };

    Ok(PublishPacket {
        topic,
        qos,
        retain,
        dup,
        packet_id,
        payload: r.rest(),
        properties,
    })
}

fn decode_connect(r: &mut Reader) -> Result<ConnectPacket, PacketError> {
    let proto_name = r.binary()?;
    let level = r.u8()?;
    match (&proto_name[..], level) {
        (b"MQTT", 4) | (b"MQTT", 5) => {}
        // MQTT v3.1 clients identify as "MQIsdp" level 3; report it so the server can answer
        // with CONNACK 0x01 (unacceptable protocol version) as §3.1.2.2 requires.
        (b"MQIsdp", 3) | (b"MQTT", _) => {
            return Err(PacketError::UnsupportedProtocolVersion(level))
        }
        _ => return Err(PacketError::InvalidProtocolName),
    }
    let version = ProtocolVersion::try_from(level)?;

    let connect_flags = r.u8()?;
    if connect_flags & 0x01 != 0 {
        return Err(PacketError::Malformed("reserved CONNECT flag set"));
    }
    let username_flag = connect_flags & 0x80 != 0;
    let password_flag = connect_flags & 0x40 != 0;
    let will_retain = connect_flags & 0x20 != 0;
    let will_qos_raw = (connect_flags >> 3) & 0x03;
    let will_flag = connect_flags & 0x04 != 0;
    let clean_start = connect_flags & 0x02 != 0;

    if !will_flag && (will_retain || will_qos_raw != 0) {
        return Err(PacketError::Malformed(
            "will QoS/retain set without will flag",
        ));
    }
    if will_qos_raw == 3 {
        return Err(PacketError::Malformed("will QoS 3"));
    }
    // v3.1.1 §3.1.2.9: password requires user name. v5.0 lifted this restriction.
    if version == ProtocolVersion::V311 && password_flag && !username_flag {
        return Err(PacketError::Malformed(
            "password flag without user name flag",
        ));
    }

    let keep_alive_sec = r.u16()?;
    let properties = if version == ProtocolVersion::V500 {
        Properties::decode(r, PropertyContext::Packet(PacketType::Connect))?
    } else {
        Properties::new()
    };

    let client_id = r.string()?;

    let will = if will_flag {
        let will_properties = if version == ProtocolVersion::V500 {
            Properties::decode(r, PropertyContext::Will)?
        } else {
            Properties::new()
        };
        let topic = r.string()?;
        if topic.is_empty() || !is_valid_topic_name(&topic) {
            return Err(PacketError::ProtocolError("invalid will topic"));
        }
        let payload = r.binary()?;
        Some(PublishPacket {
            topic,
            qos: QoS::try_from(will_qos_raw)?,
            retain: will_retain,
            dup: false,
            packet_id: None,
            payload,
            properties: will_properties,
        })
    } else {
        None
    };

    let username = if username_flag {
        Some(r.string()?)
    } else {
        None
    };
    let password = if password_flag {
        Some(r.binary()?)
    } else {
        None
    };

    Ok(ConnectPacket {
        version,
        client_id,
        clean_start,
        keep_alive_sec,
        will,
        username,
        password,
        properties,
    })
}

fn encode_connect(conn: &ConnectPacket, body: &mut BytesMut) -> Result<(), PacketError> {
    let v5 = conn.version == ProtocolVersion::V500;
    put_string(body, "MQTT")?;
    body.put_u8(conn.version as u8);

    let mut flags = 0u8;
    if conn.clean_start {
        flags |= 0x02;
    }
    if let Some(will) = &conn.will {
        flags |= 0x04 | ((will.qos as u8) << 3);
        if will.retain {
            flags |= 0x20;
        }
    }
    if conn.password.is_some() {
        flags |= 0x40;
    }
    if conn.username.is_some() {
        flags |= 0x80;
    }
    body.put_u8(flags);
    body.put_u16(conn.keep_alive_sec);
    if v5 {
        conn.properties.encode(body)?;
    }

    put_string(body, &conn.client_id)?;
    if let Some(will) = &conn.will {
        if v5 {
            will.properties.encode(body)?;
        }
        put_string(body, &will.topic)?;
        put_binary(body, &will.payload)?;
    }
    if let Some(username) = &conn.username {
        put_string(body, username)?;
    }
    if let Some(password) = &conn.password {
        put_binary(body, password)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::properties::Property;

    const MAX: usize = MqttPacket::DEFAULT_MAX_PACKET_SIZE;

    fn roundtrip(pkt: &MqttPacket, version: ProtocolVersion) -> MqttPacket {
        let bytes = pkt.to_bytes(version).unwrap();
        let (decoded, used) = MqttPacket::decode(&bytes, version, MAX).unwrap().unwrap();
        assert_eq!(used, bytes.len(), "decoder must consume the whole frame");
        decoded
    }

    #[test]
    fn ping_and_disconnect_wire_format() {
        assert_eq!(
            &MqttPacket::PingReq.to_bytes(ProtocolVersion::V311).unwrap()[..],
            &[0xC0, 0x00]
        );
        assert_eq!(
            &MqttPacket::PingResp
                .to_bytes(ProtocolVersion::V500)
                .unwrap()[..],
            &[0xD0, 0x00]
        );
        let d = MqttPacket::disconnect(reason::SUCCESS);
        assert_eq!(
            &d.to_bytes(ProtocolVersion::V500).unwrap()[..],
            &[0xE0, 0x00]
        );
        let d = MqttPacket::disconnect(reason::KEEP_ALIVE_TIMEOUT);
        assert_eq!(
            &d.to_bytes(ProtocolVersion::V500).unwrap()[..],
            &[0xE0, 0x01, 0x8D]
        );
        assert_eq!(roundtrip(&d, ProtocolVersion::V500), d);
    }

    #[test]
    fn publish_roundtrip_both_versions_preserves_binary_payload() {
        let payload = Bytes::from_static(&[0x00, 0x01, 0x26, 0xFF, 0x00]);
        let pkt = MqttPacket::Publish(
            PublishPacket::new("factory/line1/temp", payload)
                .with_qos(QoS::AtLeastOnce, Some(1042)),
        );
        for v in [ProtocolVersion::V311, ProtocolVersion::V500] {
            assert_eq!(roundtrip(&pkt, v), pkt);
        }
    }

    #[test]
    fn v5_publish_wire_format_has_property_length() {
        let pkt = MqttPacket::Publish(PublishPacket::new("t", Bytes::from_static(&[0x00, 0xAA])));
        assert_eq!(
            &pkt.to_bytes(ProtocolVersion::V500).unwrap()[..],
            &[0x30, 0x06, 0x00, 0x01, b't', 0x00, 0x00, 0xAA]
        );
        assert_eq!(
            &pkt.to_bytes(ProtocolVersion::V311).unwrap()[..],
            &[0x30, 0x05, 0x00, 0x01, b't', 0x00, 0xAA]
        );
    }

    #[test]
    fn v5_publish_properties_roundtrip() {
        let props = Properties(vec![
            Property::MessageExpiryInterval(30),
            Property::ResponseTopic("reply".into()),
            Property::CorrelationData(Bytes::from_static(b"id-1")),
            Property::UserProperty("a".into(), "b".into()),
        ]);
        let pkt = MqttPacket::Publish(
            PublishPacket::new("device/status", Bytes::from_static(b"ONLINE"))
                .with_properties(props),
        );
        assert_eq!(roundtrip(&pkt, ProtocolVersion::V500), pkt);
    }

    #[test]
    fn subscribe_roundtrip_with_v5_options() {
        let opts = SubscriptionOptions {
            qos: QoS::ExactlyOnce,
            no_local: true,
            retain_as_published: true,
            retain_handling: RetainHandling::SendIfNew,
        };
        let pkt = MqttPacket::Subscribe {
            packet_id: 7,
            filters: vec![
                ("a/+/c".into(), opts),
                ("d/#".into(), SubscriptionOptions::new(QoS::AtMostOnce)),
            ],
            properties: Properties(vec![Property::SubscriptionIdentifier(42)]),
        };
        assert_eq!(roundtrip(&pkt, ProtocolVersion::V500), pkt);

        let v3 = MqttPacket::subscribe(
            9,
            vec![("x/y".into(), SubscriptionOptions::new(QoS::AtLeastOnce))],
        );
        assert_eq!(roundtrip(&v3, ProtocolVersion::V311), v3);
    }

    #[test]
    fn v311_subscribe_rejects_reserved_option_bits() {
        // Option byte 0x04 (No Local) is reserved in v3.1.1.
        let raw = [0x82, 0x06, 0x00, 0x01, 0x00, 0x01, b'a', 0x04];
        assert!(matches!(
            MqttPacket::decode(&raw, ProtocolVersion::V311, MAX),
            Err(PacketError::Malformed(_))
        ));
    }

    #[test]
    fn suback_and_unsuback_roundtrip() {
        let suback = MqttPacket::SubAck {
            packet_id: 42,
            reason_codes: vec![0x00, 0x00, 0x80],
        };
        // A v3.1.1 SUBACK whose first code is 0x00 used to be mis-parsed as v5 properties.
        assert_eq!(roundtrip(&suback, ProtocolVersion::V311), suback);
        assert_eq!(roundtrip(&suback, ProtocolVersion::V500), suback);

        let unsuback = MqttPacket::UnsubAck {
            packet_id: 77,
            reason_codes: vec![reason::SUCCESS, reason::NO_SUBSCRIPTION_EXISTED],
        };
        assert_eq!(roundtrip(&unsuback, ProtocolVersion::V500), unsuback);
        assert_eq!(
            &unsuback.to_bytes(ProtocolVersion::V311).unwrap()[..],
            &[0xB0, 0x02, 0x00, 0x4D]
        );
    }

    #[test]
    fn connack_v5_carries_properties() {
        let pkt = MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0,
            properties: Properties(vec![
                Property::TopicAliasMaximum(10),
                Property::AssignedClientIdentifier("auto-1".into()),
            ]),
        };
        assert_eq!(roundtrip(&pkt, ProtocolVersion::V500), pkt);
        assert_eq!(
            &pkt.to_bytes(ProtocolVersion::V311).unwrap()[..],
            &[0x20, 0x02, 0x00, 0x00]
        );
    }

    #[test]
    fn pub_acks_with_reason_codes() {
        let ok = MqttPacket::puback(5);
        assert_eq!(
            &ok.to_bytes(ProtocolVersion::V500).unwrap()[..],
            &[0x40, 0x02, 0x00, 0x05]
        );
        let denied = MqttPacket::PubAck {
            packet_id: 5,
            reason_code: reason::NOT_AUTHORIZED,
        };
        assert_eq!(roundtrip(&denied, ProtocolVersion::V500), denied);
        assert_eq!(
            &MqttPacket::pubrel(3)
                .to_bytes(ProtocolVersion::V311)
                .unwrap()[..],
            &[0x62, 0x02, 0x00, 0x03]
        );
    }

    #[test]
    fn connect_roundtrip_v311_and_v5_with_will_and_credentials() {
        let will = PublishPacket::new("status/lwt", Bytes::from_static(b"offline"))
            .with_qos(QoS::AtLeastOnce, None)
            .with_retain(true);
        let v3 = MqttPacket::Connect(
            ConnectPacket::new("c1")
                .with_version(ProtocolVersion::V311)
                .with_will(will.clone())
                .with_credentials("user", Bytes::from_static(b"pass")),
        );
        assert_eq!(roundtrip(&v3, ProtocolVersion::V311), v3);

        let mut will5 = will;
        will5.properties = Properties(vec![Property::WillDelayInterval(10)]);
        let mut conn5 = ConnectPacket::new("c2").with_will(will5);
        conn5.properties = Properties(vec![
            Property::SessionExpiryInterval(60),
            Property::ReceiveMaximum(10),
        ]);
        let v5 = MqttPacket::Connect(conn5);
        // CONNECT ignores the peer version argument; it is self-describing.
        assert_eq!(roundtrip(&v5, ProtocolVersion::V311), v5);
    }

    #[test]
    fn v5_connect_allows_password_without_username() {
        let mut conn = ConnectPacket::new("c");
        conn.password = Some(Bytes::from_static(b"token"));
        let pkt = MqttPacket::Connect(conn);
        assert_eq!(roundtrip(&pkt, ProtocolVersion::V500), pkt);
    }

    #[test]
    fn connect_rejects_bad_protocol_name_and_reports_old_versions() {
        let raw = [
            0x10, 0x0D, 0x00, 0x04, b'X', b'Y', b'Z', b'W', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x01,
            b'a',
        ];
        assert_eq!(
            MqttPacket::decode(&raw, ProtocolVersion::V311, MAX),
            Err(PacketError::InvalidProtocolName)
        );
        let mqisdp = [
            0x10, 0x0F, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x3C,
            0x00, 0x01, b'a',
        ];
        assert_eq!(
            MqttPacket::decode(&mqisdp, ProtocolVersion::V311, MAX),
            Err(PacketError::UnsupportedProtocolVersion(3))
        );
    }

    #[test]
    fn truncated_frames_wait_and_truncated_fields_are_malformed() {
        let full =
            MqttPacket::Connect(ConnectPacket::new("client").with_version(ProtocolVersion::V311))
                .to_bytes(ProtocolVersion::V311)
                .unwrap();
        for len in 0..full.len() {
            assert_eq!(
                MqttPacket::decode(&full[..len], ProtocolVersion::V311, MAX),
                Ok(None)
            );
        }
        // Remaining length claims 6 bytes but the CONNECT body stops after the protocol name.
        let short = [0x10, 0x06, 0x00, 0x04, b'M', b'Q', b'T', b'T'];
        assert!(matches!(
            MqttPacket::decode(&short, ProtocolVersion::V311, MAX),
            Err(PacketError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_invalid_fixed_header_flags_and_trailing_bytes() {
        assert!(MqttPacket::decode(
            &[0x80, 0x05, 0x00, 0x01, 0x00, 0x01, b'a'],
            ProtocolVersion::V311,
            MAX
        )
        .is_err());
        assert!(MqttPacket::decode(&[0xC1, 0x00], ProtocolVersion::V311, MAX).is_err());
        assert!(MqttPacket::decode(&[0xC0, 0x01, 0x00], ProtocolVersion::V311, MAX).is_err());
        assert!(
            MqttPacket::decode(&[0x40, 0x03, 0x00, 0x01, 0x00], ProtocolVersion::V311, MAX)
                .is_err()
        );
    }

    #[test]
    fn rejects_bad_publish_packets() {
        // Wildcard in topic name.
        let wildcard = [0x30, 0x05, 0x00, 0x03, b'a', b'/', b'+'];
        assert!(MqttPacket::decode(&wildcard, ProtocolVersion::V311, MAX).is_err());
        // QoS 3.
        assert!(MqttPacket::decode(
            &[0x36, 0x05, 0x00, 0x01, b'a', 0x00, 0x01],
            ProtocolVersion::V311,
            MAX
        )
        .is_err());
        // DUP on QoS 0.
        assert!(
            MqttPacket::decode(&[0x38, 0x03, 0x00, 0x01, b'a'], ProtocolVersion::V311, MAX)
                .is_err()
        );
        // Packet identifier 0 on QoS 1.
        assert!(MqttPacket::decode(
            &[0x32, 0x05, 0x00, 0x01, b'a', 0x00, 0x00],
            ProtocolVersion::V311,
            MAX
        )
        .is_err());
        // Empty topic in v3.1.1.
        assert!(MqttPacket::decode(&[0x30, 0x02, 0x00, 0x00], ProtocolVersion::V311, MAX).is_err());
        // NUL character inside the topic.
        assert_eq!(
            MqttPacket::decode(&[0x30, 0x03, 0x00, 0x01, 0x00], ProtocolVersion::V311, MAX),
            Err(PacketError::InvalidString)
        );
        // v5 PUBLISH whose property length runs past the packet.
        assert!(MqttPacket::decode(
            &[0x30, 0x04, 0x00, 0x01, b'a', 0x05],
            ProtocolVersion::V500,
            MAX
        )
        .is_err());
    }

    #[test]
    fn enforces_maximum_packet_size_from_the_header() {
        // Remaining length 1000 with a limit of 100: rejected before the body arrives.
        let header = [0x30, 0xE8, 0x07];
        assert_eq!(
            MqttPacket::decode(&header, ProtocolVersion::V311, 100),
            Err(PacketError::PacketTooLarge {
                size: 1003,
                max: 100
            })
        );
    }

    #[test]
    fn auth_packet_is_v5_only() {
        assert!(MqttPacket::decode(&[0xF0, 0x00], ProtocolVersion::V311, MAX).is_err());
        let ok = MqttPacket::decode(&[0xF0, 0x00], ProtocolVersion::V500, MAX)
            .unwrap()
            .unwrap()
            .0;
        assert!(matches!(ok, MqttPacket::Auth { reason_code: 0, .. }));
    }

    #[test]
    fn decode_from_consumes_only_one_frame() {
        let mut buf = BytesMut::new();
        MqttPacket::PingReq
            .encode(ProtocolVersion::V311, &mut buf)
            .unwrap();
        MqttPacket::puback(9)
            .encode(ProtocolVersion::V311, &mut buf)
            .unwrap();
        buf.extend_from_slice(&[0x30]); // start of a third, incomplete packet
        let a = MqttPacket::decode_from(&mut buf, ProtocolVersion::V311, MAX).unwrap();
        let b = MqttPacket::decode_from(&mut buf, ProtocolVersion::V311, MAX).unwrap();
        let c = MqttPacket::decode_from(&mut buf, ProtocolVersion::V311, MAX).unwrap();
        assert_eq!(a, Some(MqttPacket::PingReq));
        assert_eq!(b, Some(MqttPacket::puback(9)));
        assert_eq!(c, None);
        assert_eq!(&buf[..], &[0x30]);
    }
}
