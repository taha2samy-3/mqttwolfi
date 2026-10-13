//! OASIS MQTT-SN v1.2 message codec.

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

/// Largest MQTT-SN frame expressible with the 3-octet long length format (§5.2.1).
pub const MAX_SN_FRAME_LEN: usize = u16::MAX as usize;

/// MQTT-SN ClientId length limits (§5.3.1).
pub const MAX_SN_CLIENT_ID_LEN: usize = 23;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnError {
    #[error("buffer too short to parse MQTT-SN frame: {0} bytes")]
    Incomplete(usize),
    #[error("unknown or unsupported MQTT-SN message type: 0x{0:02X}")]
    UnknownMsgType(u8),
    #[error("invalid MQTT-SN frame length: {0}")]
    InvalidLength(usize),
    #[error("invalid MQTT-SN string")]
    InvalidString,
    #[error("invalid MQTT-SN field: {0}")]
    InvalidField(&'static str),
    #[error("MQTT-SN frame of {0} bytes exceeds the 65535 byte limit")]
    FrameTooLarge(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnMsgType {
    Advertise = 0x00,
    SearchGw = 0x01,
    GwInfo = 0x02,
    Connect = 0x04,
    ConnAck = 0x05,
    WillTopicReq = 0x06,
    WillTopic = 0x07,
    WillMsgReq = 0x08,
    WillMsg = 0x09,
    Register = 0x0A,
    RegAck = 0x0B,
    Publish = 0x0C,
    PubAck = 0x0D,
    PubComp = 0x0E,
    PubRec = 0x0F,
    PubRel = 0x10,
    Subscribe = 0x12,
    SubAck = 0x13,
    Unsubscribe = 0x14,
    UnsubAck = 0x15,
    PingReq = 0x16,
    PingResp = 0x17,
    Disconnect = 0x18,
    WillTopicUpd = 0x1A,
    WillTopicResp = 0x1B,
    WillMsgUpd = 0x1C,
    WillMsgResp = 0x1D,
    EncapMsg = 0xFE,
}

impl TryFrom<u8> for SnMsgType {
    type Error = SnError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x00 => Ok(Self::Advertise),
            0x01 => Ok(Self::SearchGw),
            0x02 => Ok(Self::GwInfo),
            0x04 => Ok(Self::Connect),
            0x05 => Ok(Self::ConnAck),
            0x06 => Ok(Self::WillTopicReq),
            0x07 => Ok(Self::WillTopic),
            0x08 => Ok(Self::WillMsgReq),
            0x09 => Ok(Self::WillMsg),
            0x0A => Ok(Self::Register),
            0x0B => Ok(Self::RegAck),
            0x0C => Ok(Self::Publish),
            0x0D => Ok(Self::PubAck),
            0x0E => Ok(Self::PubComp),
            0x0F => Ok(Self::PubRec),
            0x10 => Ok(Self::PubRel),
            0x12 => Ok(Self::Subscribe),
            0x13 => Ok(Self::SubAck),
            0x14 => Ok(Self::Unsubscribe),
            0x15 => Ok(Self::UnsubAck),
            0x16 => Ok(Self::PingReq),
            0x17 => Ok(Self::PingResp),
            0x18 => Ok(Self::Disconnect),
            0x1A => Ok(Self::WillTopicUpd),
            0x1B => Ok(Self::WillTopicResp),
            0x1C => Ok(Self::WillMsgUpd),
            0x1D => Ok(Self::WillMsgResp),
            0xFE => Ok(Self::EncapMsg),
            other => Err(SnError::UnknownMsgType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TopicIdType {
    Normal = 0b00,
    Predefined = 0b01,
    Short = 0b10,
    Reserved = 0b11,
}

impl From<u8> for TopicIdType {
    fn from(val: u8) -> Self {
        match val & 0x03 {
            0b00 => TopicIdType::Normal,
            0b01 => TopicIdType::Predefined,
            0b10 => TopicIdType::Short,
            _ => TopicIdType::Reserved,
        }
    }
}

/// MQTT-SN return codes (§5.3.10).
pub mod return_code {
    pub const ACCEPTED: u8 = 0x00;
    pub const REJECTED_CONGESTION: u8 = 0x01;
    pub const REJECTED_INVALID_TOPIC_ID: u8 = 0x02;
    pub const REJECTED_NOT_SUPPORTED: u8 = 0x03;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnPacket {
    Advertise {
        gw_id: u8,
        duration: u16,
    },
    SearchGw {
        radius: u8,
    },
    GwInfo {
        gw_id: u8,
        gw_add: Option<Vec<u8>>,
    },
    Connect {
        will: bool,
        clean_session: bool,
        duration: u16,
        client_id: String,
    },
    ConnAck {
        return_code: u8,
    },
    WillTopicReq,
    WillTopic {
        qos: u8,
        retain: bool,
        will_topic: String,
    },
    WillMsgReq,
    WillMsg {
        will_msg: Bytes,
    },
    Register {
        topic_id: u16,
        msg_id: u16,
        topic_name: String,
    },
    RegAck {
        topic_id: u16,
        msg_id: u16,
        return_code: u8,
    },
    Publish {
        dup: bool,
        qos: i8, // -1, 0, 1, 2
        retain: bool,
        topic_id_type: TopicIdType,
        topic_id: u16,
        msg_id: u16,
        data: Bytes,
    },
    PubAck {
        topic_id: u16,
        msg_id: u16,
        return_code: u8,
    },
    PubRec {
        msg_id: u16,
    },
    PubRel {
        msg_id: u16,
    },
    PubComp {
        msg_id: u16,
    },
    Subscribe {
        dup: bool,
        qos: u8,
        topic_id_type: TopicIdType,
        msg_id: u16,
        topic_id: u16,
        topic_name: Option<String>,
    },
    SubAck {
        qos: u8,
        topic_id: u16,
        msg_id: u16,
        return_code: u8,
    },
    Unsubscribe {
        topic_id_type: TopicIdType,
        msg_id: u16,
        topic_id: u16,
        topic_name: Option<String>,
    },
    UnsubAck {
        msg_id: u16,
    },
    PingReq {
        client_id: Option<String>,
    },
    PingResp,
    Disconnect {
        duration: Option<u16>,
    },
    WillTopicUpd {
        qos: u8,
        retain: bool,
        will_topic: String,
    },
    WillTopicResp {
        return_code: u8,
    },
    WillMsgUpd {
        will_msg: Bytes,
    },
    WillMsgResp {
        return_code: u8,
    },
    /// Forwarder encapsulation (§5.5). `payload` is the complete encapsulated MQTT-SN frame.
    EncapMsg {
        ctrl: u8,
        wireless_node_id: Vec<u8>,
        payload: Bytes,
    },
}

fn utf8(bytes: &[u8]) -> Result<String, SnError> {
    let s = std::str::from_utf8(bytes).map_err(|_| SnError::InvalidString)?;
    if s.contains('\0') {
        return Err(SnError::InvalidString);
    }
    Ok(s.to_owned())
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Decodes the topic part of SUBSCRIBE / UNSUBSCRIBE, which follows the flags and MsgId.
fn decode_topic_field(
    topic_id_type: TopicIdType,
    rest: &[u8],
) -> Result<(u16, Option<String>), SnError> {
    match topic_id_type {
        TopicIdType::Normal => {
            if rest.is_empty() {
                return Err(SnError::InvalidField("empty topic name"));
            }
            Ok((0, Some(utf8(rest)?)))
        }
        TopicIdType::Predefined | TopicIdType::Short => {
            if rest.len() != 2 {
                return Err(SnError::InvalidLength(rest.len()));
            }
            Ok((be16(rest, 0), None))
        }
        TopicIdType::Reserved => Err(SnError::InvalidField("reserved topic id type")),
    }
}

/// Maps the 2-bit QoS field of the flags octet (§5.3.4). 0b11 is QoS -1.
fn qos_from_flags(flags: u8) -> i8 {
    match (flags >> 5) & 0x03 {
        0b11 => -1,
        q => q as i8,
    }
}

impl SnPacket {
    /// Decodes one MQTT-SN frame from the front of `src` and advances past it.
    pub fn decode(src: &mut &[u8]) -> Result<Self, SnError> {
        if src.is_empty() {
            return Err(SnError::Incomplete(0));
        }

        let first = src[0];
        let (total_len, header_len, msg_type_raw) = if first == 0x01 {
            // Long format: 0x01, 2-octet length, MsgType.
            if src.len() < 4 {
                return Err(SnError::Incomplete(src.len()));
            }
            (be16(src, 1) as usize, 4, src[3])
        } else {
            if src.len() < 2 {
                return Err(SnError::Incomplete(src.len()));
            }
            (first as usize, 2, src[1])
        };

        if total_len < header_len {
            return Err(SnError::InvalidLength(total_len));
        }
        if src.len() < total_len {
            return Err(SnError::Incomplete(src.len()));
        }

        let body = &src[header_len..total_len];
        let msg_type = SnMsgType::try_from(msg_type_raw)?;
        let need = |n: usize| -> Result<(), SnError> {
            if body.len() < n {
                Err(SnError::InvalidLength(body.len()))
            } else {
                Ok(())
            }
        };
        let exact = |n: usize| -> Result<(), SnError> {
            if body.len() != n {
                Err(SnError::InvalidLength(body.len()))
            } else {
                Ok(())
            }
        };

        let mut consumed = total_len;
        let packet = match msg_type {
            SnMsgType::Advertise => {
                exact(3)?;
                SnPacket::Advertise {
                    gw_id: body[0],
                    duration: be16(body, 1),
                }
            }
            SnMsgType::SearchGw => {
                exact(1)?;
                SnPacket::SearchGw { radius: body[0] }
            }
            SnMsgType::GwInfo => {
                need(1)?;
                SnPacket::GwInfo {
                    gw_id: body[0],
                    gw_add: (body.len() > 1).then(|| body[1..].to_vec()),
                }
            }
            SnMsgType::Connect => {
                need(4)?;
                let flags = body[0];
                if body[1] != 0x01 {
                    return Err(SnError::InvalidField("unsupported MQTT-SN protocol id"));
                }
                let client_id = utf8(&body[4..])?;
                SnPacket::Connect {
                    will: flags & 0x08 != 0,
                    clean_session: flags & 0x04 != 0,
                    duration: be16(body, 2),
                    client_id,
                }
            }
            SnMsgType::ConnAck => {
                exact(1)?;
                SnPacket::ConnAck {
                    return_code: body[0],
                }
            }
            SnMsgType::WillTopicReq => {
                exact(0)?;
                SnPacket::WillTopicReq
            }
            SnMsgType::WillTopic => {
                // An empty WILLTOPIC (no flags, no topic) deletes the will (§5.4.7).
                if body.is_empty() {
                    SnPacket::WillTopic {
                        qos: 0,
                        retain: false,
                        will_topic: String::new(),
                    }
                } else {
                    let flags = body[0];
                    SnPacket::WillTopic {
                        qos: (flags >> 5) & 0x03,
                        retain: flags & 0x10 != 0,
                        will_topic: utf8(&body[1..])?,
                    }
                }
            }
            SnMsgType::WillMsgReq => {
                exact(0)?;
                SnPacket::WillMsgReq
            }
            SnMsgType::WillMsg => SnPacket::WillMsg {
                will_msg: Bytes::copy_from_slice(body),
            },
            SnMsgType::Register => {
                need(5)?;
                SnPacket::Register {
                    topic_id: be16(body, 0),
                    msg_id: be16(body, 2),
                    topic_name: utf8(&body[4..])?,
                }
            }
            SnMsgType::RegAck => {
                exact(5)?;
                SnPacket::RegAck {
                    topic_id: be16(body, 0),
                    msg_id: be16(body, 2),
                    return_code: body[4],
                }
            }
            SnMsgType::Publish => {
                need(5)?;
                let flags = body[0];
                SnPacket::Publish {
                    dup: flags & 0x80 != 0,
                    qos: qos_from_flags(flags),
                    retain: flags & 0x10 != 0,
                    topic_id_type: TopicIdType::from(flags),
                    topic_id: be16(body, 1),
                    msg_id: be16(body, 3),
                    data: Bytes::copy_from_slice(&body[5..]),
                }
            }
            SnMsgType::PubAck => {
                exact(5)?;
                SnPacket::PubAck {
                    topic_id: be16(body, 0),
                    msg_id: be16(body, 2),
                    return_code: body[4],
                }
            }
            SnMsgType::PubRec => {
                exact(2)?;
                SnPacket::PubRec {
                    msg_id: be16(body, 0),
                }
            }
            SnMsgType::PubRel => {
                exact(2)?;
                SnPacket::PubRel {
                    msg_id: be16(body, 0),
                }
            }
            SnMsgType::PubComp => {
                exact(2)?;
                SnPacket::PubComp {
                    msg_id: be16(body, 0),
                }
            }
            SnMsgType::Subscribe => {
                need(4)?;
                let flags = body[0];
                let topic_id_type = TopicIdType::from(flags);
                let (topic_id, topic_name) = decode_topic_field(topic_id_type, &body[3..])?;
                SnPacket::Subscribe {
                    dup: flags & 0x80 != 0,
                    qos: (flags >> 5) & 0x03,
                    topic_id_type,
                    msg_id: be16(body, 1),
                    topic_id,
                    topic_name,
                }
            }
            SnMsgType::SubAck => {
                exact(6)?;
                SnPacket::SubAck {
                    qos: (body[0] >> 5) & 0x03,
                    topic_id: be16(body, 1),
                    msg_id: be16(body, 3),
                    return_code: body[5],
                }
            }
            SnMsgType::Unsubscribe => {
                need(4)?;
                let topic_id_type = TopicIdType::from(body[0]);
                let (topic_id, topic_name) = decode_topic_field(topic_id_type, &body[3..])?;
                SnPacket::Unsubscribe {
                    topic_id_type,
                    msg_id: be16(body, 1),
                    topic_id,
                    topic_name,
                }
            }
            SnMsgType::UnsubAck => {
                exact(2)?;
                SnPacket::UnsubAck {
                    msg_id: be16(body, 0),
                }
            }
            SnMsgType::PingReq => SnPacket::PingReq {
                client_id: if body.is_empty() {
                    None
                } else {
                    Some(utf8(body)?)
                },
            },
            SnMsgType::PingResp => {
                exact(0)?;
                SnPacket::PingResp
            }
            SnMsgType::Disconnect => match body.len() {
                0 => SnPacket::Disconnect { duration: None },
                2 => SnPacket::Disconnect {
                    duration: Some(be16(body, 0)),
                },
                n => return Err(SnError::InvalidLength(n)),
            },
            SnMsgType::WillTopicUpd => {
                if body.is_empty() {
                    SnPacket::WillTopicUpd {
                        qos: 0,
                        retain: false,
                        will_topic: String::new(),
                    }
                } else {
                    let flags = body[0];
                    SnPacket::WillTopicUpd {
                        qos: (flags >> 5) & 0x03,
                        retain: flags & 0x10 != 0,
                        will_topic: utf8(&body[1..])?,
                    }
                }
            }
            SnMsgType::WillTopicResp => {
                exact(1)?;
                SnPacket::WillTopicResp {
                    return_code: body[0],
                }
            }
            SnMsgType::WillMsgUpd => SnPacket::WillMsgUpd {
                will_msg: Bytes::copy_from_slice(body),
            },
            SnMsgType::WillMsgResp => {
                exact(1)?;
                SnPacket::WillMsgResp {
                    return_code: body[0],
                }
            }
            SnMsgType::EncapMsg => {
                // §5.5: Length covers only the encapsulation header (Length, MsgType, Ctrl,
                // Wireless Node Id); the encapsulated frame follows and runs to the datagram end.
                need(1)?;
                let payload = Bytes::copy_from_slice(&src[total_len..]);
                consumed = src.len();
                SnPacket::EncapMsg {
                    ctrl: body[0],
                    wireless_node_id: body[1..].to_vec(),
                    payload,
                }
            }
        };

        *src = &src[consumed..];
        Ok(packet)
    }

    /// Encodes this MQTT-SN packet into `dst`, choosing the short or long length format.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), SnError> {
        let mut body = BytesMut::new();
        let msg_type = match self {
            SnPacket::Advertise { gw_id, duration } => {
                body.put_u8(*gw_id);
                body.put_u16(*duration);
                SnMsgType::Advertise
            }
            SnPacket::SearchGw { radius } => {
                body.put_u8(*radius);
                SnMsgType::SearchGw
            }
            SnPacket::GwInfo { gw_id, gw_add } => {
                body.put_u8(*gw_id);
                if let Some(add) = gw_add {
                    body.extend_from_slice(add);
                }
                SnMsgType::GwInfo
            }
            SnPacket::Connect {
                will,
                clean_session,
                duration,
                client_id,
            } => {
                let mut flags = 0u8;
                if *will {
                    flags |= 0x08;
                }
                if *clean_session {
                    flags |= 0x04;
                }
                body.put_u8(flags);
                body.put_u8(0x01); // ProtocolId = 0x01 (MQTT-SN v1.2)
                body.put_u16(*duration);
                body.extend_from_slice(client_id.as_bytes());
                SnMsgType::Connect
            }
            SnPacket::ConnAck { return_code } => {
                body.put_u8(*return_code);
                SnMsgType::ConnAck
            }
            SnPacket::WillTopicReq => SnMsgType::WillTopicReq,
            SnPacket::WillTopic {
                qos,
                retain,
                will_topic,
            } => {
                if !will_topic.is_empty() {
                    let mut flags = (*qos & 0x03) << 5;
                    if *retain {
                        flags |= 0x10;
                    }
                    body.put_u8(flags);
                    body.extend_from_slice(will_topic.as_bytes());
                }
                SnMsgType::WillTopic
            }
            SnPacket::WillMsgReq => SnMsgType::WillMsgReq,
            SnPacket::WillMsg { will_msg } => {
                body.extend_from_slice(will_msg);
                SnMsgType::WillMsg
            }
            SnPacket::Register {
                topic_id,
                msg_id,
                topic_name,
            } => {
                body.put_u16(*topic_id);
                body.put_u16(*msg_id);
                body.extend_from_slice(topic_name.as_bytes());
                SnMsgType::Register
            }
            SnPacket::RegAck {
                topic_id,
                msg_id,
                return_code,
            } => {
                body.put_u16(*topic_id);
                body.put_u16(*msg_id);
                body.put_u8(*return_code);
                SnMsgType::RegAck
            }
            SnPacket::Publish {
                dup,
                qos,
                retain,
                topic_id_type,
                topic_id,
                msg_id,
                data,
            } => {
                let mut flags = (*topic_id_type as u8) & 0x03;
                if *dup {
                    flags |= 0x80;
                }
                if *retain {
                    flags |= 0x10;
                }
                let qos_bits = if *qos < 0 { 0b11 } else { (*qos as u8) & 0x03 };
                flags |= qos_bits << 5;
                body.put_u8(flags);
                body.put_u16(*topic_id);
                body.put_u16(*msg_id);
                body.extend_from_slice(data);
                SnMsgType::Publish
            }
            SnPacket::PubAck {
                topic_id,
                msg_id,
                return_code,
            } => {
                body.put_u16(*topic_id);
                body.put_u16(*msg_id);
                body.put_u8(*return_code);
                SnMsgType::PubAck
            }
            SnPacket::PubRec { msg_id } => {
                body.put_u16(*msg_id);
                SnMsgType::PubRec
            }
            SnPacket::PubRel { msg_id } => {
                body.put_u16(*msg_id);
                SnMsgType::PubRel
            }
            SnPacket::PubComp { msg_id } => {
                body.put_u16(*msg_id);
                SnMsgType::PubComp
            }
            SnPacket::Subscribe {
                dup,
                qos,
                topic_id_type,
                msg_id,
                topic_id,
                topic_name,
            } => {
                let mut flags = (*topic_id_type as u8) & 0x03;
                if *dup {
                    flags |= 0x80;
                }
                flags |= (*qos & 0x03) << 5;
                body.put_u8(flags);
                body.put_u16(*msg_id);
                if *topic_id_type == TopicIdType::Normal {
                    if let Some(name) = topic_name {
                        body.extend_from_slice(name.as_bytes());
                    }
                } else {
                    body.put_u16(*topic_id);
                }
                SnMsgType::Subscribe
            }
            SnPacket::SubAck {
                qos,
                topic_id,
                msg_id,
                return_code,
            } => {
                body.put_u8((*qos & 0x03) << 5);
                body.put_u16(*topic_id);
                body.put_u16(*msg_id);
                body.put_u8(*return_code);
                SnMsgType::SubAck
            }
            SnPacket::Unsubscribe {
                topic_id_type,
                msg_id,
                topic_id,
                topic_name,
            } => {
                body.put_u8((*topic_id_type as u8) & 0x03);
                body.put_u16(*msg_id);
                if *topic_id_type == TopicIdType::Normal {
                    if let Some(name) = topic_name {
                        body.extend_from_slice(name.as_bytes());
                    }
                } else {
                    body.put_u16(*topic_id);
                }
                SnMsgType::Unsubscribe
            }
            SnPacket::UnsubAck { msg_id } => {
                body.put_u16(*msg_id);
                SnMsgType::UnsubAck
            }
            SnPacket::PingReq { client_id } => {
                if let Some(cid) = client_id {
                    body.extend_from_slice(cid.as_bytes());
                }
                SnMsgType::PingReq
            }
            SnPacket::PingResp => SnMsgType::PingResp,
            SnPacket::Disconnect { duration } => {
                if let Some(dur) = duration {
                    body.put_u16(*dur);
                }
                SnMsgType::Disconnect
            }
            SnPacket::WillTopicUpd {
                qos,
                retain,
                will_topic,
            } => {
                if !will_topic.is_empty() {
                    let mut flags = (*qos & 0x03) << 5;
                    if *retain {
                        flags |= 0x10;
                    }
                    body.put_u8(flags);
                    body.extend_from_slice(will_topic.as_bytes());
                }
                SnMsgType::WillTopicUpd
            }
            SnPacket::WillTopicResp { return_code } => {
                body.put_u8(*return_code);
                SnMsgType::WillTopicResp
            }
            SnPacket::WillMsgUpd { will_msg } => {
                body.extend_from_slice(will_msg);
                SnMsgType::WillMsgUpd
            }
            SnPacket::WillMsgResp { return_code } => {
                body.put_u8(*return_code);
                SnMsgType::WillMsgResp
            }
            SnPacket::EncapMsg {
                ctrl,
                wireless_node_id,
                payload,
            } => {
                let header_len = 3 + wireless_node_id.len();
                if header_len > 255 {
                    return Err(SnError::InvalidField("wireless node id too long"));
                }
                dst.put_u8(header_len as u8);
                dst.put_u8(SnMsgType::EncapMsg as u8);
                dst.put_u8(*ctrl);
                dst.extend_from_slice(wireless_node_id);
                dst.extend_from_slice(payload);
                return Ok(());
            }
        };

        let body_len = body.len();
        if body_len + 2 <= 255 {
            // Short format: [Length: 1B] [MsgType: 1B] [Body...]
            dst.put_u8((body_len + 2) as u8);
            dst.put_u8(msg_type as u8);
        } else {
            // Long format: [0x01] [Length: 2B BE] [MsgType: 1B] [Body...]
            let total_len = body_len + 4;
            if total_len > MAX_SN_FRAME_LEN {
                return Err(SnError::FrameTooLarge(total_len));
            }
            dst.put_u8(0x01);
            dst.put_u16(total_len as u16);
            dst.put_u8(msg_type as u8);
        }
        dst.extend_from_slice(&body);
        Ok(())
    }

    /// Encodes into a fresh buffer.
    pub fn to_bytes(&self) -> Result<BytesMut, SnError> {
        let mut buf = BytesMut::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(pkt: &SnPacket) -> SnPacket {
        let buf = pkt.to_bytes().unwrap();
        let mut slice = &buf[..];
        let decoded = SnPacket::decode(&mut slice).unwrap();
        assert!(slice.is_empty(), "decoder must consume the whole frame");
        decoded
    }

    #[test]
    fn advertise_roundtrip() {
        let pkt = SnPacket::Advertise {
            gw_id: 1,
            duration: 900,
        };
        assert_eq!(pkt.to_bytes().unwrap().len(), 5);
        assert_eq!(roundtrip(&pkt), pkt);
    }

    #[test]
    fn connect_connack_roundtrip() {
        let conn = SnPacket::Connect {
            will: false,
            clean_session: true,
            duration: 60,
            client_id: "drone-01".into(),
        };
        assert_eq!(roundtrip(&conn), conn);
        let connack = SnPacket::ConnAck { return_code: 0x00 };
        assert_eq!(&connack.to_bytes().unwrap()[..], &[0x03, 0x05, 0x00]);
        assert_eq!(roundtrip(&connack), connack);
    }

    #[test]
    fn connect_rejects_unknown_protocol_id() {
        let raw = [0x08, 0x04, 0x04, 0x02, 0x00, 0x3C, b'a', b'b'];
        assert!(SnPacket::decode(&mut &raw[..]).is_err());
    }

    #[test]
    fn register_regack_roundtrip() {
        let reg = SnPacket::Register {
            topic_id: 0,
            msg_id: 42,
            topic_name: "uav/gps".into(),
        };
        assert_eq!(roundtrip(&reg), reg);
        let regack = SnPacket::RegAck {
            topic_id: 1,
            msg_id: 42,
            return_code: 0,
        };
        assert_eq!(roundtrip(&regack), regack);
    }

    #[test]
    fn publish_qos0_and_qos_minus1_roundtrip() {
        let pub_pkt = SnPacket::Publish {
            dup: false,
            qos: 0,
            retain: false,
            topic_id_type: TopicIdType::Predefined,
            topic_id: 1,
            msg_id: 0,
            data: Bytes::from_static(b"HELLO-RADIO"),
        };
        assert_eq!(roundtrip(&pub_pkt), pub_pkt);

        let beacon = SnPacket::Publish {
            dup: false,
            qos: -1,
            retain: false,
            topic_id_type: TopicIdType::Short,
            topic_id: u16::from_be_bytes(*b"AB"),
            msg_id: 0,
            data: Bytes::from_static(b"FAST-DATA"),
        };
        assert_eq!(roundtrip(&beacon), beacon);
    }

    #[test]
    fn long_format_roundtrip_and_size_limit() {
        let big = SnPacket::Publish {
            dup: false,
            qos: 1,
            retain: false,
            topic_id_type: TopicIdType::Normal,
            topic_id: 100,
            msg_id: 7,
            data: Bytes::from(vec![0xAB; 1000]),
        };
        let buf = big.to_bytes().unwrap();
        assert_eq!(buf[0], 0x01);
        assert_eq!(roundtrip(&big), big);

        let too_big = SnPacket::WillMsg {
            will_msg: Bytes::from(vec![0; MAX_SN_FRAME_LEN]),
        };
        assert!(matches!(too_big.to_bytes(), Err(SnError::FrameTooLarge(_))));
    }

    #[test]
    fn subscribe_variants_and_validation() {
        let by_name = SnPacket::Subscribe {
            dup: false,
            qos: 1,
            topic_id_type: TopicIdType::Normal,
            msg_id: 3,
            topic_id: 0,
            topic_name: Some("a/+/c".into()),
        };
        assert_eq!(roundtrip(&by_name), by_name);
        let predefined = SnPacket::Subscribe {
            dup: false,
            qos: 0,
            topic_id_type: TopicIdType::Predefined,
            msg_id: 4,
            topic_id: 2,
            topic_name: None,
        };
        assert_eq!(roundtrip(&predefined), predefined);
        // Predefined topic id must be exactly two bytes.
        let bad = [0x06, 0x12, 0x21, 0x00, 0x04, 0x02];
        assert!(SnPacket::decode(&mut &bad[..]).is_err());
        // Invalid UTF-8 in a topic name is rejected rather than replaced.
        let invalid_utf8 = [0x07, 0x12, 0x00, 0x00, 0x05, 0xFF, 0xFE];
        assert_eq!(
            SnPacket::decode(&mut &invalid_utf8[..]),
            Err(SnError::InvalidString)
        );
    }

    #[test]
    fn encapsulated_frame_roundtrip() {
        let inner = SnPacket::PingReq { client_id: None }
            .to_bytes()
            .unwrap()
            .freeze();
        let encap = SnPacket::EncapMsg {
            ctrl: 0x00,
            wireless_node_id: vec![0xAA, 0xBB],
            payload: inner.clone(),
        };
        let buf = encap.to_bytes().unwrap();
        assert_eq!(&buf[..5], &[0x05, 0xFE, 0x00, 0xAA, 0xBB]);
        assert_eq!(roundtrip(&encap), encap);
        let mut slice = &inner[..];
        assert_eq!(
            SnPacket::decode(&mut slice).unwrap(),
            SnPacket::PingReq { client_id: None }
        );
    }

    #[test]
    fn truncated_and_inconsistent_frames_are_rejected() {
        assert!(SnPacket::decode(&mut &[][..]).is_err());
        assert!(SnPacket::decode(&mut &[0x05, 0x0D, 0x00][..]).is_err());
        // Length smaller than the header itself.
        assert!(SnPacket::decode(&mut &[0x01, 0x0D][..]).is_err());
        // PUBACK with a body that is one byte short.
        assert!(SnPacket::decode(&mut &[0x06, 0x0D, 0x00, 0x01, 0x00, 0x02][..]).is_err());
    }
}
