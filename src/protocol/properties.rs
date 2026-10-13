//! MQTT v5.0 properties (OASIS MQTT v5.0 §2.2.2).

use crate::protocol::codec::{put_binary, put_string, put_vbi, vbi_len, Reader};
use crate::protocol::packet::{PacketError, PacketType};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    PayloadFormatIndicator(u8),
    MessageExpiryInterval(u32),
    ContentType(String),
    ResponseTopic(String),
    CorrelationData(Bytes),
    SubscriptionIdentifier(u32),
    SessionExpiryInterval(u32),
    AssignedClientIdentifier(String),
    ServerKeepAlive(u16),
    AuthenticationMethod(String),
    AuthenticationData(Bytes),
    RequestProblemInformation(u8),
    WillDelayInterval(u32),
    RequestResponseInformation(u8),
    ResponseInformation(String),
    ServerReference(String),
    ReasonString(String),
    ReceiveMaximum(u16),
    TopicAliasMaximum(u16),
    TopicAlias(u16),
    MaximumQoS(u8),
    RetainAvailable(u8),
    UserProperty(String, String),
    MaximumPacketSize(u32),
    WildcardSubscriptionAvailable(u8),
    SubscriptionIdentifierAvailable(u8),
    SharedSubscriptionAvailable(u8),
}

impl Property {
    pub fn id(&self) -> u8 {
        match self {
            Property::PayloadFormatIndicator(_) => 0x01,
            Property::MessageExpiryInterval(_) => 0x02,
            Property::ContentType(_) => 0x03,
            Property::ResponseTopic(_) => 0x08,
            Property::CorrelationData(_) => 0x09,
            Property::SubscriptionIdentifier(_) => 0x0B,
            Property::SessionExpiryInterval(_) => 0x11,
            Property::AssignedClientIdentifier(_) => 0x12,
            Property::ServerKeepAlive(_) => 0x13,
            Property::AuthenticationMethod(_) => 0x15,
            Property::AuthenticationData(_) => 0x16,
            Property::RequestProblemInformation(_) => 0x17,
            Property::WillDelayInterval(_) => 0x18,
            Property::RequestResponseInformation(_) => 0x19,
            Property::ResponseInformation(_) => 0x1A,
            Property::ServerReference(_) => 0x1C,
            Property::ReasonString(_) => 0x1F,
            Property::ReceiveMaximum(_) => 0x21,
            Property::TopicAliasMaximum(_) => 0x22,
            Property::TopicAlias(_) => 0x23,
            Property::MaximumQoS(_) => 0x24,
            Property::RetainAvailable(_) => 0x25,
            Property::UserProperty(_, _) => 0x26,
            Property::MaximumPacketSize(_) => 0x27,
            Property::WildcardSubscriptionAvailable(_) => 0x28,
            Property::SubscriptionIdentifierAvailable(_) => 0x29,
            Property::SharedSubscriptionAvailable(_) => 0x2A,
        }
    }

    fn decode(r: &mut Reader) -> Result<Self, PacketError> {
        let id = r.vbi()?;
        let prop = match id {
            0x01 => Property::PayloadFormatIndicator(r.u8()?),
            0x02 => Property::MessageExpiryInterval(r.u32()?),
            0x03 => Property::ContentType(r.string()?),
            0x08 => Property::ResponseTopic(r.string()?),
            0x09 => Property::CorrelationData(r.binary()?),
            0x0B => Property::SubscriptionIdentifier(r.vbi()?),
            0x11 => Property::SessionExpiryInterval(r.u32()?),
            0x12 => Property::AssignedClientIdentifier(r.string()?),
            0x13 => Property::ServerKeepAlive(r.u16()?),
            0x15 => Property::AuthenticationMethod(r.string()?),
            0x16 => Property::AuthenticationData(r.binary()?),
            0x17 => Property::RequestProblemInformation(r.u8()?),
            0x18 => Property::WillDelayInterval(r.u32()?),
            0x19 => Property::RequestResponseInformation(r.u8()?),
            0x1A => Property::ResponseInformation(r.string()?),
            0x1C => Property::ServerReference(r.string()?),
            0x1F => Property::ReasonString(r.string()?),
            0x21 => Property::ReceiveMaximum(r.u16()?),
            0x22 => Property::TopicAliasMaximum(r.u16()?),
            0x23 => Property::TopicAlias(r.u16()?),
            0x24 => Property::MaximumQoS(r.u8()?),
            0x25 => Property::RetainAvailable(r.u8()?),
            0x26 => {
                let key = r.string()?;
                let value = r.string()?;
                Property::UserProperty(key, value)
            }
            0x27 => Property::MaximumPacketSize(r.u32()?),
            0x28 => Property::WildcardSubscriptionAvailable(r.u8()?),
            0x29 => Property::SubscriptionIdentifierAvailable(r.u8()?),
            0x2A => Property::SharedSubscriptionAvailable(r.u8()?),
            _ => return Err(PacketError::Malformed("unknown property identifier")),
        };
        Ok(prop)
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), PacketError> {
        dst.put_u8(self.id());
        match self {
            Property::PayloadFormatIndicator(v)
            | Property::RequestProblemInformation(v)
            | Property::RequestResponseInformation(v)
            | Property::MaximumQoS(v)
            | Property::RetainAvailable(v)
            | Property::WildcardSubscriptionAvailable(v)
            | Property::SubscriptionIdentifierAvailable(v)
            | Property::SharedSubscriptionAvailable(v) => dst.put_u8(*v),
            Property::MessageExpiryInterval(v)
            | Property::SessionExpiryInterval(v)
            | Property::WillDelayInterval(v)
            | Property::MaximumPacketSize(v) => dst.put_u32(*v),
            Property::ServerKeepAlive(v)
            | Property::ReceiveMaximum(v)
            | Property::TopicAliasMaximum(v)
            | Property::TopicAlias(v) => dst.put_u16(*v),
            Property::SubscriptionIdentifier(v) => put_vbi(dst, *v)?,
            Property::ContentType(s)
            | Property::ResponseTopic(s)
            | Property::AssignedClientIdentifier(s)
            | Property::AuthenticationMethod(s)
            | Property::ResponseInformation(s)
            | Property::ServerReference(s)
            | Property::ReasonString(s) => put_string(dst, s)?,
            Property::CorrelationData(b) | Property::AuthenticationData(b) => put_binary(dst, b)?,
            Property::UserProperty(k, v) => {
                put_string(dst, k)?;
                put_string(dst, v)?;
            }
        }
        Ok(())
    }

    /// Validates value ranges mandated by the specification.
    fn validate_value(&self) -> Result<(), PacketError> {
        let ok = match self {
            Property::PayloadFormatIndicator(v)
            | Property::RequestProblemInformation(v)
            | Property::RequestResponseInformation(v)
            | Property::RetainAvailable(v)
            | Property::WildcardSubscriptionAvailable(v)
            | Property::SubscriptionIdentifierAvailable(v)
            | Property::SharedSubscriptionAvailable(v) => *v <= 1,
            Property::MaximumQoS(v) => *v <= 1,
            Property::ReceiveMaximum(v) | Property::TopicAlias(v) => *v != 0,
            Property::MaximumPacketSize(v) => *v != 0,
            Property::SubscriptionIdentifier(v) => (1..=268_435_455).contains(v),
            _ => true,
        };
        if ok {
            Ok(())
        } else {
            Err(PacketError::ProtocolError("invalid property value"))
        }
    }
}

/// Where a property list appears; determines which identifiers are legal (§2.2.2.2 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyContext {
    Packet(PacketType),
    Will,
}

impl PropertyContext {
    fn allows(self, id: u8) -> bool {
        let allowed: &[u8] = match self {
            PropertyContext::Will => &[0x01, 0x02, 0x03, 0x08, 0x09, 0x18, 0x26],
            PropertyContext::Packet(t) => match t {
                PacketType::Connect => &[0x11, 0x15, 0x16, 0x17, 0x19, 0x21, 0x22, 0x26, 0x27],
                PacketType::ConnAck => &[
                    0x11, 0x12, 0x13, 0x15, 0x16, 0x1A, 0x1C, 0x1F, 0x21, 0x22, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2A,
                ],
                PacketType::Publish => &[0x01, 0x02, 0x03, 0x08, 0x09, 0x0B, 0x23, 0x26],
                PacketType::PubAck
                | PacketType::PubRec
                | PacketType::PubRel
                | PacketType::PubComp
                | PacketType::SubAck
                | PacketType::UnsubAck => &[0x1F, 0x26],
                PacketType::Subscribe => &[0x0B, 0x26],
                PacketType::Unsubscribe => &[0x26],
                PacketType::Disconnect => &[0x11, 0x1C, 0x1F, 0x26],
                PacketType::Auth => &[0x15, 0x16, 0x1F, 0x26],
                PacketType::PingReq | PacketType::PingResp => &[],
            },
        };
        allowed.contains(&id)
    }

    fn allows_repeat(self, id: u8) -> bool {
        // User Property may always repeat; Subscription Identifier may repeat in PUBLISH.
        id == 0x26 || (id == 0x0B && self == PropertyContext::Packet(PacketType::Publish))
    }
}

/// An ordered list of MQTT v5.0 properties.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Properties(pub Vec<Property>);

impl Properties {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, prop: Property) {
        self.0.push(prop);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Property> {
        self.0.iter()
    }

    pub fn retain(&mut self, f: impl FnMut(&Property) -> bool) {
        self.0.retain(f);
    }

    /// Decodes a property length followed by the properties and validates them for `ctx`.
    pub fn decode(r: &mut Reader, ctx: PropertyContext) -> Result<Self, PacketError> {
        let len = r.vbi()? as usize;
        if r.remaining() < len {
            return Err(PacketError::Malformed("property length exceeds packet"));
        }
        let mut inner = Reader::new(r.bytes(len)?);
        let mut props = Vec::new();
        while inner.has_remaining() {
            let prop = Property::decode(&mut inner)?;
            let id = prop.id();
            if !ctx.allows(id) {
                return Err(PacketError::ProtocolError(
                    "property not allowed in this packet",
                ));
            }
            if !ctx.allows_repeat(id) && props.iter().any(|p: &Property| p.id() == id) {
                return Err(PacketError::ProtocolError(
                    "property included more than once",
                ));
            }
            prop.validate_value()?;
            props.push(prop);
        }
        Ok(Self(props))
    }

    /// Encodes the property length followed by the properties.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), PacketError> {
        let mut body = BytesMut::new();
        for p in &self.0 {
            p.encode(&mut body)?;
        }
        put_vbi(dst, body.len() as u32)?;
        dst.put(body);
        Ok(())
    }

    /// Size of the encoded property list including its length prefix.
    pub fn encoded_len(&self) -> Result<usize, PacketError> {
        let mut body = BytesMut::new();
        for p in &self.0 {
            p.encode(&mut body)?;
        }
        Ok(vbi_len(body.len()) + body.len())
    }

    pub fn message_expiry_interval(&self) -> Option<u32> {
        self.0.iter().find_map(|p| match p {
            Property::MessageExpiryInterval(v) => Some(*v),
            _ => None,
        })
    }

    pub fn session_expiry_interval(&self) -> Option<u32> {
        self.0.iter().find_map(|p| match p {
            Property::SessionExpiryInterval(v) => Some(*v),
            _ => None,
        })
    }

    pub fn will_delay_interval(&self) -> Option<u32> {
        self.0.iter().find_map(|p| match p {
            Property::WillDelayInterval(v) => Some(*v),
            _ => None,
        })
    }

    pub fn topic_alias(&self) -> Option<u16> {
        self.0.iter().find_map(|p| match p {
            Property::TopicAlias(v) => Some(*v),
            _ => None,
        })
    }

    pub fn receive_maximum(&self) -> Option<u16> {
        self.0.iter().find_map(|p| match p {
            Property::ReceiveMaximum(v) => Some(*v),
            _ => None,
        })
    }

    pub fn maximum_packet_size(&self) -> Option<u32> {
        self.0.iter().find_map(|p| match p {
            Property::MaximumPacketSize(v) => Some(*v),
            _ => None,
        })
    }

    pub fn topic_alias_maximum(&self) -> Option<u16> {
        self.0.iter().find_map(|p| match p {
            Property::TopicAliasMaximum(v) => Some(*v),
            _ => None,
        })
    }

    pub fn authentication_method(&self) -> Option<&str> {
        self.0.iter().find_map(|p| match p {
            Property::AuthenticationMethod(v) => Some(v.as_str()),
            _ => None,
        })
    }

    pub fn assigned_client_identifier(&self) -> Option<&str> {
        self.0.iter().find_map(|p| match p {
            Property::AssignedClientIdentifier(v) => Some(v.as_str()),
            _ => None,
        })
    }

    pub fn subscription_identifiers(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().filter_map(|p| match p {
            Property::SubscriptionIdentifier(v) => Some(*v),
            _ => None,
        })
    }

    pub fn reason_string(&self) -> Option<&str> {
        self.0.iter().find_map(|p| match p {
            Property::ReasonString(v) => Some(v.as_str()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(props: Properties, ctx: PropertyContext) -> Properties {
        let mut buf = BytesMut::new();
        props.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), props.encoded_len().unwrap());
        let mut r = Reader::new(buf.freeze());
        Properties::decode(&mut r, ctx).unwrap()
    }

    #[test]
    fn publish_properties_roundtrip() {
        let props = Properties(vec![
            Property::PayloadFormatIndicator(1),
            Property::MessageExpiryInterval(60),
            Property::ContentType("application/json".into()),
            Property::ResponseTopic("reply/to".into()),
            Property::CorrelationData(Bytes::from_static(b"\x00\x01")),
            Property::UserProperty("k".into(), "v".into()),
            Property::UserProperty("k".into(), "v2".into()),
            Property::SubscriptionIdentifier(300),
            Property::SubscriptionIdentifier(7),
        ]);
        let ctx = PropertyContext::Packet(PacketType::Publish);
        assert_eq!(roundtrip(props.clone(), ctx), props);
    }

    #[test]
    fn rejects_property_not_allowed_in_packet() {
        let props = Properties(vec![Property::SessionExpiryInterval(10)]);
        let mut buf = BytesMut::new();
        props.encode(&mut buf).unwrap();
        let mut r = Reader::new(buf.freeze());
        assert!(matches!(
            Properties::decode(&mut r, PropertyContext::Packet(PacketType::Publish)),
            Err(PacketError::ProtocolError(_))
        ));
    }

    #[test]
    fn rejects_duplicate_single_value_property() {
        let props = Properties(vec![
            Property::MessageExpiryInterval(1),
            Property::MessageExpiryInterval(2),
        ]);
        let mut buf = BytesMut::new();
        props.encode(&mut buf).unwrap();
        let mut r = Reader::new(buf.freeze());
        assert!(Properties::decode(&mut r, PropertyContext::Packet(PacketType::Publish)).is_err());
    }

    #[test]
    fn rejects_zero_receive_maximum_and_topic_alias() {
        for prop in [Property::ReceiveMaximum(0), Property::TopicAlias(0)] {
            let ctx = if prop.id() == 0x21 {
                PropertyContext::Packet(PacketType::Connect)
            } else {
                PropertyContext::Packet(PacketType::Publish)
            };
            let mut buf = BytesMut::new();
            Properties(vec![prop]).encode(&mut buf).unwrap();
            let mut r = Reader::new(buf.freeze());
            assert!(Properties::decode(&mut r, ctx).is_err());
        }
    }

    #[test]
    fn rejects_unknown_property_identifier() {
        let raw = Bytes::from_static(&[0x02, 0x7F, 0x00]);
        let mut r = Reader::new(raw);
        assert!(matches!(
            Properties::decode(&mut r, PropertyContext::Packet(PacketType::Publish)),
            Err(PacketError::Malformed(_))
        ));
    }
}
