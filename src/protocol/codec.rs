//! Low-level wire primitives shared by the MQTT codecs (OASIS MQTT v3.1.1 §1.5, v5.0 §1.5).

use crate::protocol::packet::PacketError;
use crate::protocol::vbi::{decode_variable_byte_integer, encode_variable_byte_integer};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Bounds-checked reader over one packet body. Every read past the end of the body is reported
/// as a malformed packet: the fixed header already told us how long the body is, so running out
/// of bytes can never mean "wait for more data".
pub struct Reader {
    buf: Bytes,
}

impl Reader {
    pub fn new(buf: Bytes) -> Self {
        Self { buf }
    }

    pub fn remaining(&self) -> usize {
        self.buf.remaining()
    }

    pub fn has_remaining(&self) -> bool {
        self.buf.has_remaining()
    }

    pub fn u8(&mut self) -> Result<u8, PacketError> {
        if self.buf.remaining() < 1 {
            return Err(PacketError::Malformed("unexpected end of packet"));
        }
        Ok(self.buf.get_u8())
    }

    pub fn u16(&mut self) -> Result<u16, PacketError> {
        if self.buf.remaining() < 2 {
            return Err(PacketError::Malformed("unexpected end of packet"));
        }
        Ok(self.buf.get_u16())
    }

    pub fn u32(&mut self) -> Result<u32, PacketError> {
        if self.buf.remaining() < 4 {
            return Err(PacketError::Malformed("unexpected end of packet"));
        }
        Ok(self.buf.get_u32())
    }

    pub fn vbi(&mut self) -> Result<u32, PacketError> {
        decode_variable_byte_integer(&mut self.buf)
            .map_err(|_| PacketError::Malformed("invalid variable byte integer"))
    }

    pub fn bytes(&mut self, len: usize) -> Result<Bytes, PacketError> {
        if self.buf.remaining() < len {
            return Err(PacketError::Malformed("unexpected end of packet"));
        }
        Ok(self.buf.split_to(len))
    }

    /// Two-byte length prefixed binary data (§1.5.6).
    pub fn binary(&mut self) -> Result<Bytes, PacketError> {
        let len = self.u16()? as usize;
        self.bytes(len)
    }

    /// Two-byte length prefixed UTF-8 string (§1.5.4). Rejects invalid UTF-8 and U+0000.
    pub fn string(&mut self) -> Result<String, PacketError> {
        let raw = self.binary()?;
        let s = std::str::from_utf8(&raw).map_err(|_| PacketError::InvalidString)?;
        if s.contains('\0') {
            return Err(PacketError::InvalidString);
        }
        Ok(s.to_owned())
    }

    /// Returns all bytes not consumed yet.
    pub fn rest(&mut self) -> Bytes {
        let len = self.buf.remaining();
        self.buf.split_to(len)
    }
}

pub fn put_string(dst: &mut BytesMut, s: &str) -> Result<(), PacketError> {
    put_binary(dst, s.as_bytes())
}

pub fn put_binary(dst: &mut BytesMut, data: &[u8]) -> Result<(), PacketError> {
    let len = u16::try_from(data.len()).map_err(|_| PacketError::EncodeTooLong)?;
    dst.put_u16(len);
    dst.put_slice(data);
    Ok(())
}

pub fn put_vbi(dst: &mut BytesMut, value: u32) -> Result<(), PacketError> {
    encode_variable_byte_integer(value, dst).map_err(|_| PacketError::EncodeTooLong)?;
    Ok(())
}

/// Number of bytes a value occupies when encoded as a variable byte integer.
pub fn vbi_len(value: usize) -> usize {
    match value {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}
