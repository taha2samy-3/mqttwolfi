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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl MqttPacket {
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
                var_header.put_u8(connect_flags);
                var_header.put_u16(conn.keep_alive_sec);

                // Payload: Client ID
                var_header.put_u16(conn.client_id.len() as u16);
                var_header.put_slice(conn.client_id.as_bytes());

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
        }
    }

    /// Deserializes an MQTT packet from an incoming byte buffer.
    pub fn decode<B: Buf>(src: &mut B) -> Result<Self, PacketError> {
        if !src.has_remaining() {
            return Err(PacketError::BufferUnderflow);
        }

        let first_byte = src.get_u8();
        let packet_type_val = (first_byte >> 4) & 0x0F;
        let flags = first_byte & 0x0F;
        let packet_type = PacketType::try_from(packet_type_val)?;

        let remaining_len =
            decode_variable_byte_integer(src).map_err(|_| PacketError::MalformedHeader)? as usize;

        if src.remaining() < remaining_len {
            return Err(PacketError::BufferUnderflow);
        }

        match packet_type {
            PacketType::PingReq => Ok(MqttPacket::PingReq),
            PacketType::PingResp => Ok(MqttPacket::PingResp),
            PacketType::Disconnect => Ok(MqttPacket::Disconnect),
            PacketType::Subscribe => {
                if remaining_len < 3 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = src.get_u16();
                let mut topics = Vec::new();
                let mut bytes_left = remaining_len - 2;

                while bytes_left > 0 {
                    if src.remaining() < 2 {
                        return Err(PacketError::BufferUnderflow);
                    }
                    let topic_len = src.get_u16() as usize;
                    if src.remaining() < topic_len + 1 {
                        return Err(PacketError::BufferUnderflow);
                    }
                    let mut topic_bytes = vec![0u8; topic_len];
                    src.copy_to_slice(&mut topic_bytes);
                    let topic =
                        String::from_utf8(topic_bytes).map_err(|_| PacketError::InvalidString)?;
                    let qos = QoS::try_from(src.get_u8())?;
                    topics.push((topic, qos));
                    bytes_left = bytes_left.saturating_sub(2 + topic_len + 1);
                }

                Ok(MqttPacket::Subscribe { packet_id, topics })
            }
            PacketType::SubAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = src.get_u16();
                let codes_len = remaining_len - 2;
                if src.remaining() < codes_len {
                    return Err(PacketError::BufferUnderflow);
                }
                let mut return_codes = vec![0u8; codes_len];
                src.copy_to_slice(&mut return_codes);
                Ok(MqttPacket::SubAck {
                    packet_id,
                    return_codes,
                })
            }
            PacketType::ConnAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let ack_flags = src.get_u8();
                let reason_code = src.get_u8();
                Ok(MqttPacket::ConnAck {
                    session_present: (ack_flags & 0x01) != 0,
                    reason_code,
                })
            }
            PacketType::PubAck => {
                if remaining_len < 2 {
                    return Err(PacketError::MalformedHeader);
                }
                let packet_id = src.get_u16();
                Ok(MqttPacket::PubAck { packet_id })
            }
            PacketType::Publish => {
                let dup = (flags & 0x08) != 0;
                let qos = QoS::try_from((flags >> 1) & 0x03)?;
                let retain = (flags & 0x01) != 0;

                if src.remaining() < 2 {
                    return Err(PacketError::BufferUnderflow);
                }
                let topic_len = src.get_u16() as usize;
                if src.remaining() < topic_len {
                    return Err(PacketError::BufferUnderflow);
                }
                let mut topic_bytes = vec![0u8; topic_len];
                src.copy_to_slice(&mut topic_bytes);
                let topic =
                    String::from_utf8(topic_bytes).map_err(|_| PacketError::InvalidString)?;

                let packet_id = if qos != QoS::AtMostOnce {
                    if src.remaining() < 2 {
                        return Err(PacketError::BufferUnderflow);
                    }
                    Some(src.get_u16())
                } else {
                    None
                };

                let header_len = 2 + topic_len + if packet_id.is_some() { 2 } else { 0 };
                let payload_len = remaining_len.saturating_sub(header_len);
                let mut payload_vec = vec![0u8; payload_len];
                src.copy_to_slice(&mut payload_vec);

                Ok(MqttPacket::Publish(PublishPacket {
                    topic,
                    qos,
                    retain,
                    dup,
                    packet_id,
                    payload: Bytes::from(payload_vec),
                }))
            }
            PacketType::Connect => {
                if src.remaining() < 2 {
                    return Err(PacketError::BufferUnderflow);
                }
                let proto_len = src.get_u16() as usize;
                if src.remaining() < proto_len {
                    return Err(PacketError::BufferUnderflow);
                }
                let mut proto_name = vec![0u8; proto_len];
                src.copy_to_slice(&mut proto_name);
                if proto_name != b"MQTT" {
                    return Err(PacketError::InvalidProtocolName);
                }

                let version_byte = src.get_u8();
                let version = ProtocolVersion::try_from(version_byte)?;

                let connect_flags = src.get_u8();
                let clean_start = (connect_flags & 0x02) != 0;
                let keep_alive_sec = src.get_u16();

                let client_id_len = src.get_u16() as usize;
                let mut client_id_bytes = vec![0u8; client_id_len];
                src.copy_to_slice(&mut client_id_bytes);
                let client_id =
                    String::from_utf8(client_id_bytes).map_err(|_| PacketError::InvalidString)?;

                Ok(MqttPacket::Connect(ConnectPacket {
                    version,
                    client_id,
                    clean_start,
                    keep_alive_sec,
                    will: None,
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
        };
        let pkt = MqttPacket::Connect(conn_pkt);

        let mut buf = BytesMut::new();
        pkt.encode(&mut buf).unwrap();

        let mut read_buf = &buf[..];
        let decoded = MqttPacket::decode(&mut read_buf).unwrap();
        assert_eq!(decoded, pkt);
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
}
