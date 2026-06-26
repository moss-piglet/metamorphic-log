//! Minimal, dependency-free encodings used by the C2SP wire formats.
//!
//! The `tlog-tiles` / `checkpoint` / `signed-note` specs use two textual
//! encodings:
//!
//! - **Standard Base64** ([RFC 4648] §4, with `+` / `/` and `=` padding) for
//!   root hashes and signature blobs.
//! - **Lowercase, fixed-width, zero-padded hex** for verifier-key key ids.
//!
//! These are implemented here directly rather than pulling a third-party
//! encoding crate, keeping the dependency surface to `metamorphic-crypto`
//! (primitives) and `thiserror` (errors) only. Both decoders are strict: they
//! reject any input the reference Go implementation
//! (`encoding/base64.StdEncoding`) would reject, which matters for byte-exact
//! witness interoperability.
//!
//! [RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648

use crate::error::{Error, Result};

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Encode `input` as standard (padded) Base64.
#[must_use]
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(STD_ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(STD_ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            STD_ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            PAD as char
        });
        out.push(if chunk.len() > 2 {
            STD_ALPHABET[n as usize & 0x3f] as char
        } else {
            PAD as char
        });
    }
    out
}

/// Map a single Base64 alphabet byte to its 6-bit value, or `None`.
#[inline]
fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard (padded) Base64. Strict: the input length must be a multiple
/// of four, padding must be canonical, and no stray characters are allowed.
///
/// # Errors
/// Returns [`Error::MalformedNote`] for any structurally invalid input. (This
/// helper is only used while parsing notes/checkpoints, so the note error
/// variant is the meaningful context.)
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(Error::MalformedNote(
            "base64 length is not a multiple of 4".into(),
        ));
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    // Count canonical trailing padding (0, 1, or 2 `=`).
    let pad = bytes.iter().rev().take_while(|&&c| c == PAD).count();
    if pad > 2 {
        return Err(Error::MalformedNote("too much base64 padding".into()));
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for group in bytes.chunks(4) {
        let mut acc = 0u32;
        let mut real = 0usize;
        for (i, &c) in group.iter().enumerate() {
            if c == PAD {
                // Padding may only occur in the last group's last two slots.
                acc <<= 6;
            } else {
                let v = b64_value(c)
                    .ok_or_else(|| Error::MalformedNote("invalid base64 character".into()))?;
                acc = (acc << 6) | u32::from(v);
                real = i + 1;
            }
        }
        match real {
            4 => {
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
                out.push(acc as u8);
            }
            3 => {
                // One pad: 2 output bytes; the low 2 bits of the 3rd symbol
                // must be zero for canonical encoding.
                if acc & 0xff != 0 {
                    return Err(Error::MalformedNote("non-canonical base64".into()));
                }
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
            }
            2 => {
                // Two pads: 1 output byte; the low 4 bits must be zero.
                if acc & 0xffff != 0 {
                    return Err(Error::MalformedNote("non-canonical base64".into()));
                }
                out.push((acc >> 16) as u8);
            }
            _ => return Err(Error::MalformedNote("invalid base64 group".into())),
        }
    }
    Ok(out)
}

/// Encode `bytes` as lowercase, fixed-width hex (two chars per byte).
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a lowercase/uppercase hex string into bytes.
///
/// # Errors
/// Returns [`Error::MalformedNote`] if the length is odd or a non-hex character
/// is present.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(Error::MalformedNote("odd-length hex".into()));
    }
    let val = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::MalformedNote("invalid hex character".into())),
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn base64_known_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn base64_rejects_bad_input() {
        assert!(base64_decode("Zg=").is_err()); // not multiple of 4
        assert!(base64_decode("Z===").is_err()); // too much padding
        assert!(base64_decode("Zm9*").is_err()); // invalid char
        assert!(base64_decode("Zh==").is_err()); // non-canonical low bits
    }

    #[test]
    fn hex_roundtrip_and_width() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa3, 0xff]), "000fa3ff");
        assert_eq!(
            hex_decode("000fa3ff").unwrap(),
            vec![0x00, 0x0f, 0xa3, 0xff]
        );
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }

    proptest! {
        #[test]
        fn base64_roundtrip(data: Vec<u8>) {
            let encoded = base64_encode(&data);
            prop_assert_eq!(base64_decode(&encoded).unwrap(), data);
        }

        #[test]
        fn hex_roundtrip(data: Vec<u8>) {
            let encoded = hex_encode(&data);
            prop_assert_eq!(hex_decode(&encoded).unwrap(), data);
        }
    }
}
