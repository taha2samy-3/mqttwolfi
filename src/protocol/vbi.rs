use bytes::{Buf, BufMut};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VbiError {
    #[error("Variable byte integer exceeds 4 bytes maximum limit")]
    MalformedVbi,
    #[error("Buffer exhausted before variable byte integer was fully decoded")]
    IncompleteBuffer,
}

/// Decodes an MQTT variable-byte integer from a buffer.
/// Returns (decoded_value, bytes_consumed).
pub fn decode_variable_byte_integer<B: Buf>(buf: &mut B) -> Result<u32, VbiError> {
    let mut multiplier: u32 = 1;
    let mut value: u32 = 0;
    let mut bytes_read = 0;

    loop {
        if !buf.has_remaining() {
            return Err(VbiError::IncompleteBuffer);
        }

        let encoded_byte = buf.get_u8();
        bytes_read += 1;

        value += ((encoded_byte & 0x7F) as u32) * multiplier;

        if (encoded_byte & 0x80) == 0 {
            break;
        }

        multiplier *= 128;
        if bytes_read >= 4 {
            return Err(VbiError::MalformedVbi);
        }
    }

    Ok(value)
}

/// Encodes an MQTT variable-byte integer into a buffer.
pub fn encode_variable_byte_integer<B: BufMut>(mut value: u32, buf: &mut B) -> Result<usize, VbiError> {
    if value > 268_435_455 {
        return Err(VbiError::MalformedVbi);
    }

    let mut bytes_written = 0;
    loop {
        let mut encoded_byte = (value % 128) as u8;
        value /= 128;

        if value > 0 {
            encoded_byte |= 0x80;
        }

        buf.put_u8(encoded_byte);
        bytes_written += 1;

        if value == 0 {
            break;
        }
    }

    Ok(bytes_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_vbi_boundary_values() {
        let test_cases: &[(u32, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xFF, 0x7F]),
            (16_384, &[0x80, 0x80, 0x01]),
            (2_097_151, &[0xFF, 0xFF, 0x7F]),
            (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
            (268_435_455, &[0xFF, 0xFF, 0xFF, 0x7F]),
        ];

        for &(value, expected_bytes) in test_cases {
            // Test Encoding
            let mut buf = BytesMut::new();
            let written = encode_variable_byte_integer(value, &mut buf).unwrap();
            assert_eq!(written, expected_bytes.len());
            assert_eq!(&buf[..], expected_bytes);

            // Test Decoding
            let mut read_buf = &buf[..];
            let decoded = decode_variable_byte_integer(&mut read_buf).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn test_vbi_incomplete_buffer() {
        // Multi-byte value with truncated trailing byte
        let data = [0x80]; // Indicates more bytes follow, but buffer terminates
        let mut buf = &data[..];
        assert_eq!(
            decode_variable_byte_integer(&mut buf),
            Err(VbiError::IncompleteBuffer)
        );
    }

    #[test]
    fn test_vbi_malformed_overflow() {
        // 5 bytes with high bit set exceeds MQTT 4-byte specification limit
        let data = [0x80, 0x80, 0x80, 0x80, 0x01];
        let mut buf = &data[..];
        assert_eq!(
            decode_variable_byte_integer(&mut buf),
            Err(VbiError::MalformedVbi)
        );
    }
}
