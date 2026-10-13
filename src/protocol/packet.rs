use crate::protocol::vbi::{decode_variable_byte_integer, encode_variable_byte_integer};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QoS {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("Unsupported protocol version level: {0}")]
    UnsupportedProtocolVersion(u8),
    #[error("Invalid packet type: {0}")]
    InvalidPacketType(u8),
    #[error("Invalid QoS value: {0}")]
    InvalidQoS(u8),
    #[error("Malformed packet header")]
    MalformedHeader,
    #[error("UTF-8 string decoding error")]
    InvalidString,
    #[error("Buffer underflow while decoding packet")]
    BufferUnderflow,
    #[error("Protocol name is not 'MQTT'")]
    InvalidProtocolName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectPacket {
    pub version: ProtocolVersion,
    pub client_id: String,
    pub clean_start: bool,
    pub keep_alive_sec: u16,
    pub will: Option<PublishPacket>,
    pub username: Option<String>,
    pub password: Option<Bytes>,
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

    pub fn with_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<Bytes>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttPacket {
    Connect(ConnectPacket),
    ConnAck {
        session_present: bool,
        reason_code: u8,
    },
    Publish(PublishPacket),
    PubAck {
        packet_id: u16,
    },
    PingReq,
    PingResp,
    Disconnect,
    Subscribe {
        packet_id: u16,
        topics: Vec<(String, QoS)>,
    },
    SubAck {
        packet_id: u16,
        return_codes: Vec<u8>,
    },
    Unsubscribe {
        packet_id: u16,
        topics: Vec<String>,
    },
    UnsubAck {
        packet_id: u16,
    },
    PubRec {
        packet_id: u16,
    },
    PubRel {
        packet_id: u16,
    },
    PubComp {
        packet_id: u16,
    },
}

impl MqttPacket {
    /// Maximum allowed packet size (4 MB per broker config) to prevent resource exhaustion DoS
    pub const MAX_PACKET_SIZE: usize = 4 * 1024 * 1024;

    /// Serializes an MQTT packet tailored to the client's protocol version (e.g. MQTT v5 CONNACK, SUBACK, UNSUBACK, PUBLISH properties).
    pub fn encode_for_version(
        &self,
        dst: &mut BytesMut,
        version: ProtocolVersion,
    ) -> Result<(), PacketError> {
        if version == ProtocolVersion::V500 {
            match self {
                MqttPacket::ConnAck {
                    session_present,
                    reason_code,
                } => {
                    dst.put_u8(0x20); // PacketType::ConnAck << 4
                    dst.put_u8(0x03); // Remaining Length = 3 (Flags + ReasonCode + PropertyLength)
                    dst.put_u8(if *session_present { 0x01 } else { 0x00 });
                    dst.put_u8(*reason_code);
                    dst.put_u8(0x00); // 0 Properties length (MQTT 5.0 Section 3.2.2.3 compliant)
                    return Ok(());
                }
                MqttPacket::SubAck {
                    packet_id,
                    return_codes,
                } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // 0 Properties length (MQTT 5.0 Section 3.9.2 compliant)
                    for code in return_codes {
                        var_header.put_u8(*code);
                    }
                    dst.put_u8(0x90); // SubAck fixed header: type 9
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::UnsubAck { packet_id } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // 0 Properties length (MQTT 5.0 Section 3.11.2 compliant)
                    var_header.put_u8(0x00); // Reason code 0x00 (Success)
                    dst.put_u8(0xB0); // UnsubAck fixed header: type 11
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::Publish(pub_pkt) => {
                    let mut flags = 0u8;
                    if pub_pkt.dup {
                        flags |= 0x08;
                    }
                    flags |= (pub_pkt.qos as u8) << 1;
                    if pub_pkt.retain {
                        flags |= 0x01;
                    }
                    let first_byte = (PacketType::Publish as u8) << 4 | flags;

                    let mut variable_header = BytesMut::new();
                    variable_header.put_u16(pub_pkt.topic.len() as u16);
                    variable_header.put_slice(pub_pkt.topic.as_bytes());

                    if pub_pkt.qos != QoS::AtMostOnce {
                        if let Some(pid) = pub_pkt.packet_id {
                            variable_header.put_u16(pid);
                        } else {
                            return Err(PacketError::MalformedHeader);
                        }
                    }

                    // MQTT 5.0 Section 3.3.2.3: Properties Length = 0
                    variable_header.put_u8(0x00);

                    let remaining_len = variable_header.len() + pub_pkt.payload.len();
                    dst.put_u8(first_byte);
                    encode_variable_byte_integer(remaining_len as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(variable_header);
                    dst.put_slice(&pub_pkt.payload);
                    return Ok(());
                }
                MqttPacket::Subscribe { packet_id, topics } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // 0 Properties length (MQTT 5.0 Section 3.8.2 compliant)
                    for (topic, qos) in topics {
                        var_header.put_u16(topic.len() as u16);
                        var_header.put_slice(topic.as_bytes());
                        var_header.put_u8(*qos as u8);
                    }
                    dst.put_u8(0x82); // Subscribe fixed header: type 8, reserved flags 0x02
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::Unsubscribe { packet_id, topics } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // 0 Properties length (MQTT 5.0 Section 3.10.2 compliant)
                    for topic in topics {
                        var_header.put_u16(topic.len() as u16);
                        var_header.put_slice(topic.as_bytes());
                    }
                    dst.put_u8(0xA2); // Unsubscribe fixed header: type 10, reserved flags 0x02
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::PubAck { packet_id } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // Reason code 0x00 (Success)
                    var_header.put_u8(0x00); // 0 Properties length
                    dst.put_u8(0x40); // PubAck fixed header: type 4
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::PubRec { packet_id } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // Reason code 0x00 (Success)
                    var_header.put_u8(0x00); // 0 Properties length
                    dst.put_u8(0x50); // PubRec fixed header: type 5
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::PubRel { packet_id } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // Reason code 0x00 (Success)
                    var_header.put_u8(0x00); // 0 Properties length
                    dst.put_u8(0x62); // PubRel fixed header: type 6, flags 0x02
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::PubComp { packet_id } => {
                    let mut var_header = BytesMut::new();
                    var_header.put_u16(*packet_id);
                    var_header.put_u8(0x00); // Reason code 0x00 (Success)
                    var_header.put_u8(0x00); // 0 Properties length
                    dst.put_u8(0x70); // PubComp fixed header: type 7
                    encode_variable_byte_integer(var_header.len() as u32, dst)
                        .map_err(|_| PacketError::MalformedHeader)?;
                    dst.put(var_header);
                    return Ok(());
                }
                MqttPacket::Disconnect => {
                    dst.put_u8(0xE0); // Disconnect fixed header
                    dst.put_u8(0x02); // Remaining length = 2 (Reason code 0x00 + Props len 0x00)
                    dst.put_u8(0x00); // Normal disconnection
                    dst.put_u8(0x00); // 0 Properties
                    return Ok(());
                }
                _ => {}
            }
        }
        self.encode(dst)
    }

    /// Serializes an MQTT packet into an outgoing byte buffer.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), PacketError> {
        match self {
            MqttPacket::PingReq => {
                dst.put_u8(0xC0); // PacketType::PingReq << 4
                dst.put_u8(0x00); // Remaining Length = 0
                Ok(())
            }
            MqttPacket::PingResp => {
                dst.put_u8(0xD0); // PacketType::PingResp << 4
                dst.put_u8(0x00);
                Ok(())
            }
            MqttPacket::Disconnect => {
                dst.put_u8(0xE0); // PacketType::Disconnect << 4
                dst.put_u8(0x00);
                Ok(())
            }
            MqttPacket::ConnAck {
                session_present,
                reason_code,
            } => {
                dst.put_u8(0x20); // PacketType::ConnAck << 4
                dst.put_u8(0x02); // Remaining Length = 2
                dst.put_u8(if *session_present { 0x01 } else { 0x00 });
                dst.put_u8(*reason_code);
                Ok(())
            }
            MqttPacket::PubAck { packet_id } => {
                dst.put_u8(0x40); // PacketType::PubAck << 4
                dst.put_u8(0x02); // Remaining Length = 2
                dst.put_u16(*packet_id);
                Ok(())
            }
            MqttPacket::PubRec { packet_id } => {
                dst.put_u8(0x50); // PacketType::PubRec << 4
                dst.put_u8(0x02);
                dst.put_u16(*packet_id);
                Ok(())
            }
            MqttPacket::PubRel { packet_id } => {
                dst.put_u8(0x62); // PacketType::PubRel << 4, flags 0x02
                dst.put_u8(0x02);
                dst.put_u16(*packet_id);
                Ok(())
            }
            MqttPacket::PubComp { packet_id } => {
                dst.put_u8(0x70); // PacketType::PubComp << 4
                dst.put_u8(0x02);
                dst.put_u16(*packet_id);
                Ok(())
            }
            MqttPacket::Publish(pub_pkt) => {
                let mut flags = 0u8;
                if pub_pkt.dup {
                    flags |= 0x08;
                }
                flags |= (pub_pkt.qos as u8) << 1;
                if pub_pkt.retain {
                    flags |= 0x01;
                }
                let first_byte = (PacketType::Publish as u8) << 4 | flags;

                let mut variable_header = BytesMut::new();
                // Topic string length-prefixed
                variable_header.put_u16(pub_pkt.topic.len() as u16);
                variable_header.put_slice(pub_pkt.topic.as_bytes());

                // Packet ID if QoS > 0
                if pub_pkt.qos != QoS::AtMostOnce {
                    if let Some(pid) = pub_pkt.packet_id {
                        variable_header.put_u16(pid);
                    } else {
                        return Err(PacketError::MalformedHeader);
                    }
                }

                let remaining_len = variable_header.len() + pub_pkt.payload.len();
                dst.put_u8(first_byte);
                encode_variable_byte_integer(remaining_len as u32, dst)
                    .map_err(|_| PacketError::MalformedHeader)?;
                dst.put(variable_header);
                dst.put_slice(&pub_pkt.payload);
                Ok(())
            }
            MqttPacket::Connect(conn) => {
                let mut var_header = BytesMut::new();
                // Protocol Name "MQTT"
                var_header.put_u16(4);
                var_header.put_slice(b"MQTT");
                var_header.put_u8(conn.version as u8);

                let mut connect_flags = 0u8;
                if conn.clean_start {
                    connect_flags |= 0x02;
                }
                if let Some(ref will) = conn.will {
                    connect_flags |= 0x04; // Will Flag
                    connect_flags |= (will.qos as u8) << 3; // Will QoS (bits 3 & 4)
                    if will.retain {
                        connect_flags |= 0x20; // Will Retain (bit 5)
                    }
                }
                if conn.password.is_some() {
                    connect_flags |= 0x40; // Password Flag (bit 6)
                }
                if conn.username.is_some() {
                    connect_flags |= 0x80; // Username Flag (bit 7)
                }
                var_header.put_u8(connect_flags);
                var_header.put_u16(conn.keep_alive_sec);

                // MQTT v5.0 CONNECT variable header includes Properties (0 length here)
                if conn.version == ProtocolVersion::V500 {
                    var_header.put_u8(0x00);
                }

                // Payload: Client ID
                var_header.put_u16(conn.client_id.len() as u16);
                var_header.put_slice(conn.client_id.as_bytes());

                // Payload: Will Topic & Will Message
                if let Some(ref will) = conn.will {
                    if conn.version == ProtocolVersion::V500 {
                        var_header.put_u8(0x00); // 0 will properties
                    }
                    var_header.put_u16(will.topic.len() as u16);
                    var_header.put_slice(will.topic.as_bytes());
                    var_header.put_u16(will.payload.len() as u16);
                    var_header.put_slice(&will.payload);
                }

                // Payload: Username
                if let Some(ref username) = conn.username {
                    var_header.put_u16(username.len() as u16);
                    var_header.put_slice(username.as_bytes());
                }

                // Payload: Password
                if let Some(ref password) = conn.password {
                    var_header.put_u16(password.len() as u16);
                    var_header.put_slice(password);
                }

                dst.put_u8((PacketType::Connect as u8) << 4);
                encode_variable_byte_integer(var_header.len() as u32, dst)
                    .map_err(|_| PacketError::MalformedHeader)?;
                dst.put(var_header);
                Ok(())
            }
            MqttPacket::Subscribe { packet_id, topics } => {
                let mut var_header = BytesMut::new();
                var_header.put_u16(*packet_id);
                for (topic, qos) in topics {
                    var_header.put_u16(topic.len() as u16);
                    var_header.put_slice(topic.as_bytes());
                    var_header.put_u8(*qos as u8);
                }
                dst.put_u8(0x82); // Subscribe fixed header: type 8, reserved flags 0x02
                encode_variable_byte_integer(var_header.len() as u32, dst)
                    .map_err(|_| PacketError::MalformedHeader)?;
                dst.put(var_header);
                Ok(())
            }
            MqttPacket::SubAck {
                packet_id,
                return_codes,
            } => {
                let mut var_header = BytesMut::new();
                var_header.put_u16(*packet_id);
                for code in return_codes {
                    var_header.put_u8(*code);
                }
                dst.put_u8(0x90); // SubAck fixed header: type 9
                encode_variable_byte_integer(var_header.len() as u32, dst)
                    .map_err(|_| PacketError::MalformedHeader)?;
                dst.put(var_header);
                Ok(())
            }
            MqttPacket::Unsubscribe { packet_id, topics } => {
                let mut var_header = BytesMut::new();
                var_header.put_u16(*packet_id);
                for topic in topics {
                    var_header.put_u16(topic.len() as u16);
                    var_header.put_slice(topic.as_bytes());
                }
                dst.put_u8(0xA2); // Unsubscribe fixed header: type 10, reserved flags 0x02
                encode_variable_byte_integer(var_header.len() as u32, dst)
                    .map_err(|_| PacketError::MalformedHeader)?;
                dst.put(var_header);
                Ok(())
            }
            MqttPacket::UnsubAck { packet_id } => {
                let mut var_header = BytesMut::new();
                var_header.put_u16(*packet_id);
                dst.put_u8(0xB0); // UnsubAck fixed header: type 11
                encode_variable_byte_integer(var_header.len() as u32, dst)
                    .map_err(|_| PacketError::MalformedHeader)?;
                dst.put(var_header);
                Ok(())
            }
        }
    }

    /// Deserializes an MQTT packet from an incoming byte buffer.
    pub fn decode<B: Buf>(src: &mut B) -> Result<Self, PacketError> {
        Self::decode_with_version(src, ProtocolVersion::V500)
    }

    /// Deserializes an MQTT packet tailored to the client's negotiated protocol version.
    /// Properly parses and skips MQTT 5.0 properties so variable headers and payloads are not corrupted.
    pub fn decode_with_version<B: Buf>(
        src: &mut B,
        version: ProtocolVersion,
    ) -> Result<Self, PacketError> {
        if !src.has_remaining() {
            return Err(PacketError::BufferUnderflow);
        }

        let first_byte = src.get_u8();
        let packet_type_val = (first_byte >> 4) & 0x0F;
        let flags = first_byte & 0x0F;
        let packet_type = PacketType::try_from(packet_type_val)?;

        let remaining_len = match decode_variable_byte_integer(src) {
            Ok(len) => len as usize,
            Err(crate::protocol::vbi::VbiError::IncompleteBuffer) => {
                return Err(PacketError::BufferUnderflow);
            }
            Err(crate::protocol::vbi::VbiError::MalformedVbi) => {
                return Err(PacketError::MalformedHeader);
            }
        };

        if remaining_len > Self::MAX_PACKET_SIZE {
            return Err(PacketError::MalformedHeader);
        }

        if src.remaining() < remaining_len {
            return Err(PacketError::BufferUnderflow);
        }

        // Frame the packet strictly to remaining_len bytes to prevent boundary overflows
        let mut payload = src.copy_to_bytes(remaining_len);

        match packet_type {
            PacketType::PingReq => {
                if remaining_len != 0 {
                    return Err(PacketError::MalformedHeader);
                }
                Ok(MqttPacket::PingReq)
            }
            PacketType::PingResp => {
                if remaining_len != 0 {
                    return Err(PacketError::MalformedHeader);
                }
                Ok(MqttPacket::PingResp)
            }
            PacketType::Disconnect => {
                // OASIS MQTT v5.0 §3.14.2.1: Disconnect Reason Code & Properties
                if remaining_len > 0 {
                    let _reason_code = payload.get_u8();
                    if payload.has_remaining() {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }
                Ok(MqttPacket::Disconnect)
            }
            PacketType::Subscribe => {
                if flags != 0x02 || remaining_len < 3 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                if packet_id == 0 {
                    return Err(PacketError::MalformedHeader);
                }

                // OASIS MQTT v5.0 §3.8.2.1: Properties in Subscribe variable header
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let mut check = payload.clone();
                    let has_properties = if let Ok(props_len) = decode_variable_byte_integer(&mut check) {
                        let p_len = props_len as usize;
                        if check.remaining() >= p_len + 3 {
                            check.advance(p_len);
                            let topic_len = check.get_u16() as usize;
                            topic_len > 0 && check.remaining() >= topic_len + 1
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if has_properties {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }

                let mut topics = Vec::new();

                while payload.has_remaining() {
                    if payload.remaining() < 3 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let topic_len = payload.get_u16() as usize;
                    if payload.remaining() < topic_len + 1 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let mut topic_bytes = vec![0u8; topic_len];
                    payload.copy_to_slice(&mut topic_bytes);
                    let topic =
                        String::from_utf8(topic_bytes).map_err(|_| PacketError::InvalidString)?;
                    let raw_qos = payload.get_u8();
                    // In MQTT 5.0, lower 2 bits are QoS, upper bits are subscription options
                    let qos = QoS::try_from(raw_qos & 0x03)?;
                    topics.push((topic, qos));
                }

                if topics.is_empty() {
                    return Err(PacketError::MalformedHeader);
                }

                Ok(MqttPacket::Subscribe { packet_id, topics })
            }
            PacketType::SubAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                // OASIS MQTT v5.0 §3.9.2.1: Properties in SubAck variable header
                if payload.has_remaining() {
                    let mut check = payload.clone();
                    let has_v5_props = if let Ok(props_len) = decode_variable_byte_integer(&mut check) {
                        let p_len = props_len as usize;
                        if check.remaining() >= p_len {
                            if p_len == 0 {
                                // If props_len == 0, there must be at least one reason code following it
                                check.remaining() >= 1
                            } else {
                                // SubAck properties can only be 0x1F (Reason String) or 0x26 (User Property)
                                let first_prop = check.chunk()[0];
                                first_prop == 0x1F || first_prop == 0x26
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if has_v5_props {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        payload.advance(props_len);
                    }
                }
                let codes_len = payload.remaining();
                let mut return_codes = vec![0u8; codes_len];
                payload.copy_to_slice(&mut return_codes);
                Ok(MqttPacket::SubAck {
                    packet_id,
                    return_codes,
                })
            }
            PacketType::Unsubscribe => {
                if flags != 0x02 || remaining_len < 3 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                if packet_id == 0 {
                    return Err(PacketError::MalformedHeader);
                }

                // OASIS MQTT v5.0 §3.10.2.1: Properties in Unsubscribe variable header
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let mut check = payload.clone();
                    let has_properties = if let Ok(props_len) = decode_variable_byte_integer(&mut check) {
                        let p_len = props_len as usize;
                        if check.remaining() >= p_len + 2 {
                            check.advance(p_len);
                            let topic_len = check.get_u16() as usize;
                            topic_len > 0 && check.remaining() >= topic_len
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if has_properties {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }

                let mut topics = Vec::new();

                while payload.has_remaining() {
                    if payload.remaining() < 2 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let topic_len = payload.get_u16() as usize;
                    if payload.remaining() < topic_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    let mut topic_bytes = vec![0u8; topic_len];
                    payload.copy_to_slice(&mut topic_bytes);
                    let topic =
                        String::from_utf8(topic_bytes).map_err(|_| PacketError::InvalidString)?;
                    topics.push(topic);
                }

                if topics.is_empty() {
                    return Err(PacketError::MalformedHeader);
                }

                Ok(MqttPacket::Unsubscribe { packet_id, topics })
            }
            PacketType::UnsubAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                // OASIS MQTT v5.0 §3.11.2.1: Properties & Reason codes in UnsubAck
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let props_len = decode_variable_byte_integer(&mut payload)
                        .map_err(|_| PacketError::MalformedHeader)?
                        as usize;
                    if payload.remaining() < props_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    payload.advance(props_len);
                }
                Ok(MqttPacket::UnsubAck { packet_id })
            }
            PacketType::ConnAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let ack_flags = payload.get_u8();
                let reason_code = payload.get_u8();
                if payload.has_remaining() {
                    let props_len = decode_variable_byte_integer(&mut payload)
                        .map_err(|_| PacketError::MalformedHeader)?
                        as usize;
                    if payload.remaining() < props_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    payload.advance(props_len);
                }
                Ok(MqttPacket::ConnAck {
                    session_present: (ack_flags & 0x01) != 0,
                    reason_code,
                })
            }
            PacketType::PubAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                if payload.has_remaining() {
                    let _reason_code = payload.get_u8();
                    if payload.has_remaining() {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }
                Ok(MqttPacket::PubAck { packet_id })
            }
            PacketType::PubRec => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let _reason_code = payload.get_u8();
                    if payload.has_remaining() {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }
                Ok(MqttPacket::PubRec { packet_id })
            }
            PacketType::PubRel => {
                if flags != 0x02 || remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let _reason_code = payload.get_u8();
                    if payload.has_remaining() {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }
                Ok(MqttPacket::PubRel { packet_id })
            }
            PacketType::PubComp => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = payload.get_u16();
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let _reason_code = payload.get_u8();
                    if payload.has_remaining() {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(props_len);
                    }
                }
                Ok(MqttPacket::PubComp { packet_id })
            }
            PacketType::Publish => {
                let dup = (flags & 0x08) != 0;
                let qos = QoS::try_from((flags >> 1) & 0x03)?;
                let retain = (flags & 0x01) != 0;

                if qos == QoS::AtMostOnce && dup {
                    return Err(PacketError::MalformedHeader);
                }

                if payload.remaining() < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let topic_len = payload.get_u16() as usize;
                if payload.remaining() < topic_len {
                    return Err(PacketError::MalformedHeader);
                }
                let mut topic_bytes = vec![0u8; topic_len];
                payload.copy_to_slice(&mut topic_bytes);
                let topic =
                    String::from_utf8(topic_bytes).map_err(|_| PacketError::InvalidString)?;

                // Publish topic must not contain wildcard characters (+ or #)
                if topic.contains('+') || topic.contains('#') {
                    return Err(PacketError::MalformedHeader);
                }

                let packet_id = if qos != QoS::AtMostOnce {
                    if payload.remaining() < 2 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let pid = payload.get_u16();
                    if pid == 0 {
                        return Err(PacketError::MalformedHeader);
                    }
                    Some(pid)
                } else {
                    None
                };

                // OASIS MQTT v5.0 §3.3.2.3: Properties Length & Properties in Publish variable header
                if version == ProtocolVersion::V500 && payload.has_remaining() {
                    let mut check = payload.clone();
                    let has_valid_props = if let Ok(props_len) = decode_variable_byte_integer(&mut check) {
                        let p_len = props_len as usize;
                        if check.remaining() >= p_len {
                            if p_len == 0 {
                                true
                            } else {
                                let first_prop = check.chunk()[0];
                                matches!(
                                    first_prop,
                                    0x01 | 0x02 | 0x03 | 0x08 | 0x09 | 0x0B | 0x23 | 0x26
                                )
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if has_valid_props {
                        let props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        payload.advance(props_len);
                    }
                }

                Ok(MqttPacket::Publish(PublishPacket {
                    topic,
                    qos,
                    retain,
                    dup,
                    packet_id,
                    payload,
                }))
            }
            PacketType::Connect => {
                if payload.remaining() < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let proto_len = payload.get_u16() as usize;
                if payload.remaining() < proto_len {
                    return Err(PacketError::MalformedHeader);
                }
                let mut proto_name = vec![0u8; proto_len];
                payload.copy_to_slice(&mut proto_name);
                if proto_name != b"MQTT" {
                    return Err(PacketError::InvalidProtocolName);
                }

                // Bounds check for protocol version (1), connect flags (1), keep_alive (2)
                if payload.remaining() < 4 {
                    return Err(PacketError::MalformedHeader);
                }

                let version_byte = payload.get_u8();
                let version = ProtocolVersion::try_from(version_byte)?;

                let connect_flags = payload.get_u8();
                if (connect_flags & 0x01) != 0 {
                    // Reserved bit 0 must be 0
                    return Err(PacketError::MalformedHeader);
                }

                let username_flag = (connect_flags & 0x80) != 0;
                let password_flag = (connect_flags & 0x40) != 0;
                let will_retain = (connect_flags & 0x20) != 0;
                let will_qos_val = (connect_flags >> 3) & 0x03;
                let will_flag = (connect_flags & 0x04) != 0;
                let clean_start = (connect_flags & 0x02) != 0;

                if !will_flag && (will_retain || will_qos_val != 0) {
                    return Err(PacketError::MalformedHeader);
                }
                if will_qos_val == 3 {
                    return Err(PacketError::InvalidQoS(3));
                }
                if password_flag && !username_flag {
                    return Err(PacketError::MalformedHeader);
                }

                let keep_alive_sec = payload.get_u16();

                // If MQTT v5.0, parse/skip CONNECT properties
                if version == ProtocolVersion::V500 {
                    if !payload.has_remaining() {
                        return Err(PacketError::MalformedHeader);
                    }
                    let props_len = decode_variable_byte_integer(&mut payload)
                        .map_err(|_| PacketError::MalformedHeader)?
                        as usize;
                    if payload.remaining() < props_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    payload.advance(props_len);
                }

                if payload.remaining() < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let client_id_len = payload.get_u16() as usize;
                if payload.remaining() < client_id_len {
                    return Err(PacketError::MalformedHeader);
                }
                let mut client_id_bytes = vec![0u8; client_id_len];
                payload.copy_to_slice(&mut client_id_bytes);
                let client_id =
                    String::from_utf8(client_id_bytes).map_err(|_| PacketError::InvalidString)?;

                let will = if will_flag {
                    let will_qos = QoS::try_from(will_qos_val)?;
                    if version == ProtocolVersion::V500 {
                        if !payload.has_remaining() {
                            return Err(PacketError::MalformedHeader);
                        }
                        let will_props_len = decode_variable_byte_integer(&mut payload)
                            .map_err(|_| PacketError::MalformedHeader)?
                            as usize;
                        if payload.remaining() < will_props_len {
                            return Err(PacketError::MalformedHeader);
                        }
                        payload.advance(will_props_len);
                    }

                    if payload.remaining() < 2 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let topic_len = payload.get_u16() as usize;
                    if payload.remaining() < topic_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    let mut topic_bytes = vec![0u8; topic_len];
                    payload.copy_to_slice(&mut topic_bytes);
                    let topic =
                        String::from_utf8(topic_bytes).map_err(|_| PacketError::InvalidString)?;
                    if topic.contains('+') || topic.contains('#') {
                        return Err(PacketError::MalformedHeader);
                    }

                    if payload.remaining() < 2 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let will_payload_len = payload.get_u16() as usize;
                    if payload.remaining() < will_payload_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    let will_payload = payload.copy_to_bytes(will_payload_len);

                    Some(PublishPacket {
                        topic,
                        qos: will_qos,
                        retain: will_retain,
                        dup: false,
                        packet_id: None,
                        payload: will_payload,
                    })
                } else {
                    None
                };

                let username = if username_flag {
                    if payload.remaining() < 2 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let u_len = payload.get_u16() as usize;
                    if payload.remaining() < u_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    let mut u_bytes = vec![0u8; u_len];
                    payload.copy_to_slice(&mut u_bytes);
                    Some(String::from_utf8(u_bytes).map_err(|_| PacketError::InvalidString)?)
                } else {
                    None
                };

                let password = if password_flag {
                    if payload.remaining() < 2 {
                        return Err(PacketError::MalformedHeader);
                    }
                    let p_len = payload.get_u16() as usize;
                    if payload.remaining() < p_len {
                        return Err(PacketError::MalformedHeader);
                    }
                    Some(payload.copy_to_bytes(p_len))
                } else {
                    None
                };

                Ok(MqttPacket::Connect(ConnectPacket {
                    version,
                    client_id,
                    clean_start,
                    keep_alive_sec,
                    will,
                    username,
                    password,
                }))
            }
            _ => Err(PacketError::InvalidPacketType(packet_type_val)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pingreq_and_pingresp_roundtrip() {
        let mut buf = BytesMut::new();
        MqttPacket::PingReq.encode(&mut buf).unwrap();
        assert_eq!(&buf[..], &[0xC0, 0x00]);

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, MqttPacket::PingReq);

        let mut resp_buf = BytesMut::new();
        MqttPacket::PingResp.encode(&mut resp_buf).unwrap();
        assert_eq!(&resp_buf[..], &[0xD0, 0x00]);
    }

    #[test]
    fn test_subscribe_and_suback_roundtrip() {
        let sub = MqttPacket::Subscribe {
            packet_id: 42,
            topics: vec![
                ("sensors/temperature".into(), QoS::AtLeastOnce),
                ("sensors/pressure".into(), QoS::AtMostOnce),
            ],
        };

        let mut buf = BytesMut::new();
        sub.encode(&mut buf).unwrap();
        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, sub);

        let suback = MqttPacket::SubAck {
            packet_id: 42,
            return_codes: vec![0x01, 0x00],
        };
        let mut ack_buf = BytesMut::new();
        suback.encode(&mut ack_buf).unwrap();
        let mut read_ack = &ack_buf[..];
        let decoded_ack = MqttPacket::decode(&mut read_ack).unwrap();
        assert_eq!(decoded_ack, suback);
    }

    #[test]
    fn test_connack_roundtrip() {
        let mut buf = BytesMut::new();
        let pkt = MqttPacket::ConnAck {
            session_present: true,
            reason_code: 0x00,
        };
        pkt.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_publish_qos1_roundtrip() {
        let pub_pkt = PublishPacket {
            topic: "factory/sensor1/temp".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(1042),
            payload: Bytes::from_static(b"25.4"),
        };
        let pkt = MqttPacket::Publish(pub_pkt);

        let mut buf = BytesMut::new();
        pkt.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_connect_v5_roundtrip() {
        let conn_pkt = ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "edge-device-42".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        };
        let pkt = MqttPacket::Connect(conn_pkt);

        let mut buf = BytesMut::new();
        pkt.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_connect_with_will_roundtrip() {
        let will = PublishPacket {
            topic: "status/client-99/lwt".into(),
            qos: QoS::AtLeastOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"OFFLINE_UNEXPECTED"),
        };
        let conn_pkt = ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "edge-device-99".into(),
            clean_start: true,
            keep_alive_sec: 45,
            will: Some(will),
            username: None,
            password: None,
        };
        let pkt = MqttPacket::Connect(conn_pkt);

        let mut buf = BytesMut::new();
        pkt.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_connect_with_credentials_roundtrip() {
        let conn_pkt = ConnectPacket::new("client_secure")
            .with_credentials("admin_user", Bytes::from_static(b"s3cr3t_pass"));
        let pkt = MqttPacket::Connect(conn_pkt.clone());

        let mut buf = BytesMut::new();
        pkt.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, pkt);
        if let MqttPacket::Connect(c) = decoded {
            assert_eq!(c.username.as_deref(), Some("admin_user"));
            assert_eq!(c.password.as_deref(), Some(&b"s3cr3t_pass"[..]));
        } else {
            panic!("Expected Connect packet");
        }
    }

    #[test]
    fn test_malformed_protocol_name_rejected() {
        // Encode a connect packet with corrupted protocol name "XYZW" instead of "MQTT"
        let mut buf = BytesMut::new();
        buf.put_u8(0x10); // Connect
        buf.put_u8(15); // Exact remaining length of 15 bytes
        buf.put_u16(4); // Protocol name len
        buf.put_slice(b"XYZW"); // Invalid!
        buf.put_u8(5); // v5
        buf.put_u8(0x02);
        buf.put_u16(60);
        buf.put_u16(3);
        buf.put_slice(b"dev");

        let mut read_buf = &buf[..];
        assert_eq!(
            MqttPacket::decode(&mut read_buf),
            Err(PacketError::InvalidProtocolName)
        );
    }

    #[test]
    fn test_truncated_connect_does_not_panic() {
        // Test truncated CONNECT packets at every byte offset to ensure no panic occurs
        let full_connect = [
            0x10, 0x12, // Connect, remaining len = 18
            0x00, 0x04, b'M', b'Q', b'T', b'T', // Proto name
            0x04, // Version 3.1.1
            0x02, // Clean session
            0x00, 0x3C, // Keep alive 60
            0x00, 0x06, b'c', b'l', b'i', b'e', b'n', b't', // Client ID
        ];

        for len in 1..full_connect.len() {
            let mut slice = &full_connect[..len];
            let res = MqttPacket::decode(&mut slice);
            assert!(
                res == Err(PacketError::BufferUnderflow)
                    || res == Err(PacketError::MalformedHeader),
                "Failed at len {len}: got {res:?}"
            );
        }

        // Even with declared remaining_len but truncated internal fields (e.g., proto "MQTT" but no version/flags)
        let truncated_fields = [
            0x10, 0x06, // Connect, remaining len = 6
            0x00, 0x04, b'M', b'Q', b'T',
            b'T', // Proto name only, missing 4 bytes of flags/version/keepalive!
        ];
        let mut slice2 = &truncated_fields[..];
        let res2 = MqttPacket::decode(&mut slice2);
        assert_eq!(res2, Err(PacketError::MalformedHeader));
    }

    #[test]
    fn test_malformed_subscribe_rejected() {
        // SUBSCRIBE with remaining_len < 3
        let bad_sub1 = [0x82, 0x01, 0x00];
        let mut s1 = &bad_sub1[..];
        assert_eq!(
            MqttPacket::decode(&mut s1),
            Err(PacketError::MalformedHeader)
        );

        // SUBSCRIBE with invalid flags (not 0x02)
        let bad_flags = [0x80, 0x05, 0x00, 0x01, 0x00, 0x01, b'a'];
        let mut s2 = &bad_flags[..];
        assert_eq!(
            MqttPacket::decode(&mut s2),
            Err(PacketError::MalformedHeader)
        );

        // SUBSCRIBE with packet_id = 0
        let zero_id = [0x82, 0x06, 0x00, 0x00, 0x00, 0x01, b'a', 0x00];
        let mut s3 = &zero_id[..];
        assert_eq!(
            MqttPacket::decode(&mut s3),
            Err(PacketError::MalformedHeader)
        );
    }

    #[test]
    fn test_malformed_publish_rejected() {
        // PUBLISH with wildcard in topic
        let wildcard_pub = [
            0x30, 0x05, // Publish QoS 0, remaining len = 5
            0x00, 0x03, b'a', b'/', b'+', // Topic "a/+"
        ];
        let mut s1 = &wildcard_pub[..];
        assert_eq!(
            MqttPacket::decode(&mut s1),
            Err(PacketError::MalformedHeader)
        );

        // PUBLISH with remaining_len < header_len (saturating_sub vulnerability test)
        let truncated_header = [
            0x30, 0x02, // Remaining len = 2
            0x00, 0x05, b't', b'e', // Topic len declares 5 bytes, but buffer ended
        ];
        let mut s2 = &truncated_header[..];
        assert_eq!(
            MqttPacket::decode(&mut s2),
            Err(PacketError::MalformedHeader)
        );
    }

    #[test]
    fn test_unsubscribe_and_unsuback_roundtrip() {
        let unsub = MqttPacket::Unsubscribe {
            packet_id: 101,
            topics: vec!["sensors/temp".into(), "rooms/chat".into()],
        };

        let mut buf = BytesMut::new();
        unsub.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, unsub);

        let unsuback = MqttPacket::UnsubAck { packet_id: 101 };
        let mut ack_buf = BytesMut::new();
        unsuback.encode(&mut ack_buf).unwrap();

        let mut read_ack = &ack_buf[..];
        let decoded_ack = MqttPacket::decode(&mut read_ack).unwrap();
        assert_eq!(decoded_ack, unsuback);
    }

    #[test]
    fn test_mqtt5_connect_with_nonzero_properties() {
        // Construct raw MQTT 5 CONNECT frame with properties
        let mut raw = BytesMut::new();
        raw.put_u8(0x10); // Connect fixed header

        let mut payload = BytesMut::new();
        payload.put_u16(4);
        payload.put_slice(b"MQTT");
        payload.put_u8(5); // Protocol version 5
        payload.put_u8(0x02); // Clean start
        payload.put_u16(60); // Keep alive

        // MQTT v5 Properties: Length = 5 bytes
        // Property ID 0x11 (Session Expiry Interval) = 60s (0x00, 0x00, 0x00, 0x3C)
        payload.put_u8(5); // Properties length = 5
        payload.put_u8(0x11); // Prop ID: Session Expiry
        payload.put_u32(60);

        // Client ID: "mqtt5-client"
        payload.put_u16(12);
        payload.put_slice(b"mqtt5-client");

        encode_variable_byte_integer(payload.len() as u32, &mut raw).unwrap();
        raw.put(payload);

        let mut slice = &raw[..];
        let decoded =
            MqttPacket::decode(&mut slice).expect("MQTT 5 CONNECT with properties must succeed");
        if let MqttPacket::Connect(conn) = decoded {
            assert_eq!(conn.version, ProtocolVersion::V500);
            assert_eq!(conn.client_id, "mqtt5-client");
            assert!(conn.clean_start);
            assert_eq!(conn.keep_alive_sec, 60);
        } else {
            panic!("Expected Connect packet");
        }
    }

    #[test]
    fn test_mqtt5_connect_with_will_properties() {
        let mut raw = BytesMut::new();
        raw.put_u8(0x10);

        let mut payload = BytesMut::new();
        payload.put_u16(4);
        payload.put_slice(b"MQTT");
        payload.put_u8(5); // v5
        payload.put_u8(0x06); // Clean start (0x02) | Will Flag (0x04)
        payload.put_u16(30);

        // Connect properties: length 0
        payload.put_u8(0x00);

        // Client ID
        payload.put_u16(8);
        payload.put_slice(b"gateway1");

        // Will properties: length 5 (Will Delay Interval = 10s: 0x18 + 0x00, 0x00, 0x00, 0x0A)
        payload.put_u8(5);
        payload.put_u8(0x18);
        payload.put_u32(10);

        // Will topic: "gateways/lwt"
        payload.put_u16(12);
        payload.put_slice(b"gateways/lwt");

        // Will payload: "offline"
        payload.put_u16(7);
        payload.put_slice(b"offline");

        encode_variable_byte_integer(payload.len() as u32, &mut raw).unwrap();
        raw.put(payload);

        let mut slice = &raw[..];
        let decoded = MqttPacket::decode(&mut slice)
            .expect("MQTT 5 CONNECT with will properties must succeed");
        if let MqttPacket::Connect(conn) = decoded {
            assert_eq!(conn.version, ProtocolVersion::V500);
            assert_eq!(conn.client_id, "gateway1");
            let will = conn.will.expect("Will must be present");
            assert_eq!(will.topic, "gateways/lwt");
            assert_eq!(&will.payload[..], b"offline");
        } else {
            panic!("Expected Connect packet with will");
        }
    }

    #[test]
    fn test_mqtt5_connack_and_puback_with_properties() {
        // Raw MQTT 5 CONNACK with properties (Reason code 0x00, Session present false, Props length 0)
        let v5_connack_bytes = [
            0x20, 0x03, // CONNACK, Remaining Length = 3
            0x00, // Flags: session present = false
            0x00, // Reason code: Success
            0x00, // Properties length = 0
        ];
        let mut slice = &v5_connack_bytes[..];
        let decoded = MqttPacket::decode(&mut slice).expect("MQTT 5 CONNACK decode must succeed");
        assert_eq!(
            decoded,
            MqttPacket::ConnAck {
                session_present: false,
                reason_code: 0x00,
            }
        );

        // Raw MQTT 5 PUBACK with reason code & properties
        let v5_puback_bytes = [
            0x40, 0x04, // PUBACK, Remaining Length = 4
            0x00, 0x2A, // Packet ID = 42
            0x00, // Reason code = 0x00 Success
            0x00, // Properties length = 0
        ];
        let mut slice2 = &v5_puback_bytes[..];
        let decoded_puback =
            MqttPacket::decode(&mut slice2).expect("MQTT 5 PUBACK decode must succeed");
        assert_eq!(decoded_puback, MqttPacket::PubAck { packet_id: 42 });
    }

    #[test]
    fn test_mqtt5_subscribe_and_suback_with_properties() {
        // Raw MQTT 5 SUBSCRIBE frame:
        // Fixed header: 0x82, Remaining length = 18
        // Packet ID: 0x00, 0x05 (5)
        // Property Length: 0x03 (User Property: 0x26, string key/val etc., or simple prop)
        // Properties: 3 dummy bytes
        // Topic: "sensors/data" (len 12)
        // Subscription options byte: 0x01 (QoS 1)
        let mut raw = BytesMut::new();
        raw.put_u8(0x82);

        let mut payload = BytesMut::new();
        payload.put_u16(5); // Packet ID = 5
        payload.put_u8(2); // Property length = 2
        payload.put_slice(&[0x11, 0x00]); // Dummy property bytes
        payload.put_u16(12);
        payload.put_slice(b"sensors/data");
        payload.put_u8(0x01); // QoS 1

        encode_variable_byte_integer(payload.len() as u32, &mut raw).unwrap();
        raw.put(payload);

        let mut slice = &raw[..];
        let decoded = MqttPacket::decode_with_version(&mut slice, ProtocolVersion::V500)
            .expect("MQTT 5 SUBSCRIBE with properties must decode");
        assert_eq!(
            decoded,
            MqttPacket::Subscribe {
                packet_id: 5,
                topics: vec![("sensors/data".into(), QoS::AtLeastOnce)],
            }
        );

        // Test MQTT 5 SUBACK encoding
        let suback = MqttPacket::SubAck {
            packet_id: 5,
            return_codes: vec![0x01], // Granted QoS 1
        };
        let mut suback_buf = BytesMut::new();
        suback
            .encode_for_version(&mut suback_buf, ProtocolVersion::V500)
            .unwrap();
        // Fixed header: 0x90, Remaining length: 4 (packet_id 2 + props_len 1 + return_code 1)
        assert_eq!(&suback_buf[..], &[0x90, 0x04, 0x00, 0x05, 0x00, 0x01]);
    }

    #[test]
    fn test_mqtt5_publish_with_properties_preserves_payload() {
        // Raw MQTT 5 PUBLISH:
        // Topic: "device/status" (13 bytes)
        // Packet ID: 12 (2 bytes)
        // Properties: length 5 (0x05 + 5 bytes)
        // Payload: "ONLINE_V5" (9 bytes)
        let mut raw = BytesMut::new();
        raw.put_u8(0x32); // Publish QoS 1

        let mut var_header = BytesMut::new();
        var_header.put_u16(13);
        var_header.put_slice(b"device/status");
        var_header.put_u16(12); // Packet ID
        var_header.put_u8(5); // Property length = 5
        var_header.put_slice(&[0x02, 0x00, 0x00, 0x00, 0x3C]); // Message expiry interval prop
        var_header.put_slice(b"ONLINE_V5"); // Actual payload

        encode_variable_byte_integer(var_header.len() as u32, &mut raw).unwrap();
        raw.put(var_header);

        let mut slice = &raw[..];
        let decoded = MqttPacket::decode_with_version(&mut slice, ProtocolVersion::V500)
            .expect("MQTT 5 PUBLISH decode must succeed");
        if let MqttPacket::Publish(p) = decoded {
            assert_eq!(p.topic, "device/status");
            assert_eq!(p.qos, QoS::AtLeastOnce);
            assert_eq!(p.packet_id, Some(12));
            assert_eq!(&p.payload[..], b"ONLINE_V5"); // Crucial: payload MUST NOT be polluted by properties!
        } else {
            panic!("Expected Publish packet");
        }
    }

    #[test]
    fn test_mqtt5_unsubscribe_and_unsuback() {
        let mut raw = BytesMut::new();
        raw.put_u8(0xA2); // Unsubscribe fixed header

        let mut payload = BytesMut::new();
        payload.put_u16(77); // Packet ID = 77
        payload.put_u8(0); // 0 Properties
        payload.put_u16(4);
        payload.put_slice(b"test");

        encode_variable_byte_integer(payload.len() as u32, &mut raw).unwrap();
        raw.put(payload);

        let mut slice = &raw[..];
        let decoded = MqttPacket::decode_with_version(&mut slice, ProtocolVersion::V500)
            .expect("MQTT 5 UNSUBSCRIBE decode must succeed");
        assert_eq!(
            decoded,
            MqttPacket::Unsubscribe {
                packet_id: 77,
                topics: vec!["test".into()],
            }
        );

        let unsuback = MqttPacket::UnsubAck { packet_id: 77 };
        let mut ack_buf = BytesMut::new();
        unsuback
            .encode_for_version(&mut ack_buf, ProtocolVersion::V500)
            .unwrap();
        // Fixed header: 0xB0, Remaining length: 4 (packet_id 2 + props_len 1 + reason_code 1)
        assert_eq!(&ack_buf[..], &[0xB0, 0x04, 0x00, 0x4D, 0x00, 0x00]);
    }
}
