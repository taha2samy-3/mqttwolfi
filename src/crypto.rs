//! Cryptographic primitives used outside TLS, all provided by wolfCrypt (the crypto layer of
//! the linked wolfSSL), so that wolfSSL remains the only cryptographic implementation in the
//! broker.

use std::ffi::{c_int, c_void};
use std::ptr::NonNull;

extern "C" {
    fn wc_ShaHash(data: *const u8, len: u32, hash: *mut u8) -> c_int;
    fn wc_rng_new(nonce: *mut u8, nonce_sz: u32, heap: *mut c_void) -> *mut c_void;
    fn wc_rng_free(rng: *mut c_void);
    fn wc_RNG_GenerateBlock(rng: *mut c_void, output: *mut u8, sz: u32) -> c_int;
}

/// wolfCrypt's DRBG (Hash_DRBG, seeded from the operating system).
pub struct Rng(NonNull<c_void>);

// SAFETY: a WC_RNG has no thread affinity; `&mut self` keeps it to one thread at a time.
unsafe impl Send for Rng {}

impl Rng {
    pub fn new() -> Self {
        // SAFETY: no nonce, default heap; returns NULL on failure.
        let raw = unsafe { wc_rng_new(std::ptr::null_mut(), 0, std::ptr::null_mut()) };
        Self(NonNull::new(raw).expect("wolfCrypt RNG initialisation failed"))
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        let len = u32::try_from(out.len()).expect("random block too large");
        // SAFETY: the RNG is valid and `out` holds `len` bytes.
        let rc = unsafe { wc_RNG_GenerateBlock(self.0.as_ptr(), out.as_mut_ptr(), len) };
        assert_eq!(rc, 0, "wolfCrypt RNG failed ({rc})");
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        // SAFETY: allocated by wc_rng_new and freed exactly once.
        unsafe { wc_rng_free(self.0.as_ptr()) };
    }
}

/// SHA-1 digest. Only for protocol checksums that require it (the WebSocket handshake,
/// RFC 6455 §4.2.2), never for security decisions.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    let len = u32::try_from(data.len()).expect("SHA-1 input larger than 4 GiB");
    // SAFETY: `data` is valid for `len` bytes and `out` holds the 20-byte digest.
    let rc = unsafe { wc_ShaHash(data.as_ptr(), len, out.as_mut_ptr()) };
    assert_eq!(rc, 0, "wolfCrypt SHA-1 failed ({rc})");
    out
}

/// Standard Base64 with padding (RFC 4648 §4). Not cryptographic.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_known_vectors() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn rng_produces_distinct_blocks() {
        let mut rng = Rng::new();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        rng.fill(&mut a);
        rng.fill(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected);
        }
    }
}
