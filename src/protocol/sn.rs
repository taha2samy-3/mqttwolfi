use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnError {
    #[error("Buffer too short to parse MQTT-SN frame: {0} bytes")]
    Incomplete(usize),
    #[error("Unknown or unsupported MQTT-SN message type: 0x{0:02X}")]
    UnknownMsgType(u8),
    #[error("Invalid MQTT-SN frame length: {0}")]
    InvalidLength(usize),
    #[error("Invalid MQTT-SN string: {0}")]
    InvalidString(String),
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
    EncapMsg {
        ctrl: u8,
        wireless_node_id: Vec<u8>,
        payload: Bytes,
    },
}

impl SnPacket {
    /// Decodes an MQTT-SN frame from a byte buffer.
    pub fn decode(src: &mut &[u8]) -> Result<Self, SnError> {
        if src.is_empty() {
            return Err(SnError::Incomplete(0));
        }

        let first = src[0];
        let (total_len, header_len, msg_type_raw) = if first == 0x01 {
            // Long format (>= 256 octets)
            if src.len() < 4 {
                return Err(SnError::Incomplete(src.len()));
            }
            let len = u16::from_be_bytes([src[1], src[2]]) as usize;
            let mtype = src[3];
            (len, 4, mtype)
        } else {
            // Short format (< 256 octets)
            if src.len() < 2 {
                return Err(SnError::Incomplete(src.len()));
            }
            let len = first as usize;
            let mtype = src[1];
            (len, 2, mtype)
        };

        if src.len() < total_len || total_len < header_len {
            return Err(SnError::Incomplete(src.len()));
        }

        let body = &src[header_len..total_len];
        let msg_type = SnMsgType::try_from(msg_type_raw)?;

        let packet = match msg_type {
            SnMsgType::Advertise => {
                if body.len() < 3 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let gw_id = body[0];
                let duration = u16::from_be_bytes([body[1], body[2]]);
                SnPacket::Advertise { gw_id, duration }
            }
            SnMsgType::SearchGw => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                let radius = body[0];
                SnPacket::SearchGw { radius }
            }
            SnMsgType::GwInfo => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                let gw_id = body[0];
                let gw_add = if body.len() > 1 {
                    Some(body[1..].to_vec())
                } else {
                    None
                };
                SnPacket::GwInfo { gw_id, gw_add }
            }
            SnMsgType::Connect => {
                if body.len() < 4 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let flags = body[0];
                let will = (flags & 0x08) != 0;
                let clean_session = (flags & 0x04) != 0;
                let _protocol_id = body[1]; // Expected 0x01
                let duration = u16::from_be_bytes([body[2], body[3]]);
                let client_id = String::from_utf8_lossy(&body[4..]).to_string();
                SnPacket::Connect {
                    will,
                    clean_session,
                    duration,
                    client_id,
                }
            }
            SnMsgType::ConnAck => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                SnPacket::ConnAck {
                    return_code: body[0],
                }
            }
            SnMsgType::WillTopicReq => SnPacket::WillTopicReq,
            SnMsgType::WillTopic => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                let flags = body[0];
                let qos = (flags >> 5) & 0x03;
                let retain = (flags & 0x10) != 0;
                let will_topic = String::from_utf8_lossy(&body[1..]).to_string();
                SnPacket::WillTopic {
                    qos,
                    retain,
                    will_topic,
                }
            }
            SnMsgType::WillMsgReq => SnPacket::WillMsgReq,
            SnMsgType::WillMsg => SnPacket::WillMsg {
                will_msg: Bytes::copy_from_slice(body),
            },
            SnMsgType::Register => {
                if body.len() < 4 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let topic_id = u16::from_be_bytes([body[0], body[1]]);
                let msg_id = u16::from_be_bytes([body[2], body[3]]);
                let topic_name = String::from_utf8_lossy(&body[4..]).to_string();
                SnPacket::Register {
                    topic_id,
                    msg_id,
                    topic_name,
                }
            }
            SnMsgType::RegAck => {
                if body.len() < 5 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let topic_id = u16::from_be_bytes([body[0], body[1]]);
                let msg_id = u16::from_be_bytes([body[2], body[3]]);
                let return_code = body[4];
                SnPacket::RegAck {
                    topic_id,
                    msg_id,
                    return_code,
                }
            }
            SnMsgType::Publish => {
                if body.len() < 5 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let flags = body[0];
                let dup = (flags & 0x80) != 0;
                let qos_raw = (flags >> 5) & 0x03;
                let qos = if qos_raw == 0b11 { -1i8 } else { qos_raw as i8 };
                let retain = (flags & 0x10) != 0;
                let topic_id_type = TopicIdType::from(flags);
                let topic_id = u16::from_be_bytes([body[1], body[2]]);
                let msg_id = u16::from_be_bytes([body[3], body[4]]);
                let data = Bytes::copy_from_slice(&body[5..]);
                SnPacket::Publish {
                    dup,
                    qos,
                    retain,
                    topic_id_type,
                    topic_id,
                    msg_id,
                    data,
                }
            }
            SnMsgType::PubAck => {
                if body.len() < 5 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let topic_id = u16::from_be_bytes([body[0], body[1]]);
                let msg_id = u16::from_be_bytes([body[2], body[3]]);
                let return_code = body[4];
                SnPacket::PubAck {
                    topic_id,
                    msg_id,
                    return_code,
                }
            }
            SnMsgType::PubRec => {
                if body.len() < 2 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let msg_id = u16::from_be_bytes([body[0], body[1]]);
                SnPacket::PubRec { msg_id }
            }
            SnMsgType::PubRel => {
                if body.len() < 2 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let msg_id = u16::from_be_bytes([body[0], body[1]]);
                SnPacket::PubRel { msg_id }
            }
            SnMsgType::PubComp => {
                if body.len() < 2 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let msg_id = u16::from_be_bytes([body[0], body[1]]);
                SnPacket::PubComp { msg_id }
            }
            SnMsgType::Subscribe => {
                if body.len() < 3 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let flags = body[0];
                let dup = (flags & 0x80) != 0;
                let qos = (flags >> 5) & 0x03;
                let topic_id_type = TopicIdType::from(flags);
                let msg_id = u16::from_be_bytes([body[1], body[2]]);
                let (topic_id, topic_name) = match topic_id_type {
                    TopicIdType::Normal if body.len() > 3 => {
                        (0, Some(String::from_utf8_lossy(&body[3..]).to_string()))
                    }
                    TopicIdType::Short if body.len() >= 5 => {
                        let id = u16::from_be_bytes([body[3], body[4]]);
                        (id, None)
                    }
                    TopicIdType::Predefined if body.len() >= 5 => {
                        let id = u16::from_be_bytes([body[3], body[4]]);
                        (id, None)
                    }
                    _ => {
                        if body.len() >= 5 {
                            (u16::from_be_bytes([body[3], body[4]]), None)
                        } else {
                            (0, None)
                        }
                    }
                };
                SnPacket::Subscribe {
                    dup,
                    qos,
                    topic_id_type,
                    msg_id,
                    topic_id,
                    topic_name,
                }
            }
            SnMsgType::SubAck => {
                if body.len() < 6 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let flags = body[0];
                let qos = (flags >> 5) & 0x03;
                let topic_id = u16::from_be_bytes([body[1], body[2]]);
                let msg_id = u16::from_be_bytes([body[3], body[4]]);
                let return_code = body[5];
                SnPacket::SubAck {
                    qos,
                    topic_id,
                    msg_id,
                    return_code,
                }
            }
            SnMsgType::Unsubscribe => {
                if body.len() < 3 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let flags = body[0];
                let topic_id_type = TopicIdType::from(flags);
                let msg_id = u16::from_be_bytes([body[1], body[2]]);
                let (topic_id, topic_name) = if topic_id_type == TopicIdType::Normal {
                    (0, Some(String::from_utf8_lossy(&body[3..]).to_string()))
                } else if body.len() >= 5 {
                    (u16::from_be_bytes([body[3], body[4]]), None)
                } else {
                    (0, None)
                };
                SnPacket::Unsubscribe {
                    topic_id_type,
                    msg_id,
                    topic_id,
                    topic_name,
                }
            }
            SnMsgType::UnsubAck => {
                if body.len() < 2 {
                    return Err(SnError::InvalidLength(body.len()));
                }
                let msg_id = u16::from_be_bytes([body[0], body[1]]);
                SnPacket::UnsubAck { msg_id }
            }
            SnMsgType::PingReq => {
                let client_id = if body.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(body).to_string())
                };
                SnPacket::PingReq { client_id }
            }
            SnMsgType::PingResp => SnPacket::PingResp,
            SnMsgType::Disconnect => {
                let duration = if body.len() >= 2 {
                    Some(u16::from_be_bytes([body[0], body[1]]))
                } else {
                    None
                };
                SnPacket::Disconnect { duration }
            }
            SnMsgType::WillTopicUpd => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                let flags = body[0];
                let qos = (flags >> 5) & 0x03;
                let retain = (flags & 0x10) != 0;
                let will_topic = String::from_utf8_lossy(&body[1..]).to_string();
                SnPacket::WillTopicUpd {
                    qos,
                    retain,
                    will_topic,
                }
            }
            SnMsgType::WillTopicResp => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                SnPacket::WillTopicResp {
                    return_code: body[0],
                }
            }
            SnMsgType::WillMsgUpd => SnPacket::WillMsgUpd {
                will_msg: Bytes::copy_from_slice(body),
            },
            SnMsgType::WillMsgResp => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                SnPacket::WillMsgResp {
                    return_code: body[0],
                }
            }
            SnMsgType::EncapMsg => {
                if body.is_empty() {
                    return Err(SnError::InvalidLength(0));
                }
                let ctrl = body[0];
                let node_id_len = if body.len() >= 3 { 2 } else { 0 };
                let wireless_node_id = body[1..1 + node_id_len].to_vec();
                let payload = Bytes::copy_from_slice(&body[1 + node_id_len..]);
                SnPacket::EncapMsg {
                    ctrl,
                    wireless_node_id,
                    payload,
                }
            }
            _ => return Err(SnError::UnknownMsgType(msg_type_raw)),
        };

        src.advance(total_len);
        Ok(packet)
    }

    /// Encodes this MQTT-SN packet into destination buffer.
    pub fn encode(&self, dst: &mut BytesMut) {
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
                let mut flags = (*qos & 0x03) << 5;
                if *retain {
                    flags |= 0x10;
                }
                body.put_u8(flags);
                body.extend_from_slice(will_topic.as_bytes());
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
                let qos_bits = if *qos == -1 {
                    0b11
                } else {
                    (*qos as u8) & 0x03
                };
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
                    if let Some(ref name) = topic_name {
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
                let flags = (*qos & 0x03) << 5;
                body.put_u8(flags);
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
                let flags = (*topic_id_type as u8) & 0x03;
                body.put_u8(flags);
                body.put_u16(*msg_id);
                if *topic_id_type == TopicIdType::Normal {
                    if let Some(ref name) = topic_name {
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
                if let Some(ref cid) = client_id {
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
                let mut flags = (*qos & 0x03) << 5;
                if *retain {
                    flags |= 0x10;
                }
                body.put_u8(flags);
                body.extend_from_slice(will_topic.as_bytes());
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
                body.put_u8(*ctrl);
                body.extend_from_slice(wireless_node_id);
                body.extend_from_slice(payload);
                SnMsgType::EncapMsg
            }
        };

        let body_len = body.len();
        if body_len + 2 < 256 {
            // Short format: [Length: 1B] [MsgType: 1B] [Body...]
            dst.put_u8((body_len + 2) as u8);
            dst.put_u8(msg_type as u8);
            dst.extend_from_slice(&body);
        } else {
            // Long format: [0x01: 1B] [Length: 2B BE] [MsgType: 1B] [Body...]
            let total_len = body_len + 4;
            dst.put_u8(0x01);
            dst.put_u16(total_len as u16);
            dst.put_u8(msg_type as u8);
            dst.extend_from_slice(&body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advertise_roundtrip() {
        let pkt = SnPacket::Advertise {
            gw_id: 1,
            duration: 900,
        };
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), 5); // 1 (len) + 1 (mtype) + 1 (gw_id) + 2 (duration)

        let mut slice = &buf[..];
        let decoded = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn test_connect_connack_roundtrip() {
        let conn = SnPacket::Connect {
            will: false,
            clean_session: true,
            duration: 60,
            client_id: "drone-01".into(),
        };
        let mut buf = BytesMut::new();
        conn.encode(&mut buf);

        let mut slice = &buf[..];
        let decoded = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(conn, decoded);

        let connack = SnPacket::ConnAck { return_code: 0x00 };
        buf.clear();
        connack.encode(&mut buf);
        assert_eq!(buf.as_ref(), &[0x03, 0x05, 0x00]);
        let mut slice = &buf[..];
        let decoded_ack = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(connack, decoded_ack);
    }

    #[test]
    fn test_register_regack_roundtrip() {
        let reg = SnPacket::Register {
            topic_id: 0,
            msg_id: 42,
            topic_name: "uav/gps".into(),
        };
        let mut buf = BytesMut::new();
        reg.encode(&mut buf);

        let mut slice = &buf[..];
        let decoded = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(reg, decoded);

        let regack = SnPacket::RegAck {
            topic_id: 1,
            msg_id: 42,
            return_code: 0,
        };
        buf.clear();
        regack.encode(&mut buf);
        let mut slice = &buf[..];
        let decoded_ack = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(regack, decoded_ack);
    }

    #[test]
    fn test_publish_qos0_and_qos_minus1_roundtrip() {
        let pub_pkt = SnPacket::Publish {
            dup: false,
            qos: 0,
            retain: false,
            topic_id_type: TopicIdType::Predefined,
            topic_id: 1,
            msg_id: 0,
            data: Bytes::from_static(b"HELLO-RADIO"),
        };
        let mut buf = BytesMut::new();
        pub_pkt.encode(&mut buf);

        let mut slice = &buf[..];
        let decoded = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(pub_pkt, decoded);

        // Test QoS -1 (for ultra-fast beacons)
        let beacon = SnPacket::Publish {
            dup: false,
            qos: -1,
            retain: false,
            topic_id_type: TopicIdType::Short,
            topic_id: u16::from_be_bytes(*b"AB"),
            msg_id: 0,
            data: Bytes::from_static(b"FAST-DATA"),
        };
        buf.clear();
        beacon.encode(&mut buf);
        let mut slice = &buf[..];
        let decoded_beacon = SnPacket::decode(&mut slice).unwrap();
        assert_eq!(beacon, decoded_beacon);
    }
}
