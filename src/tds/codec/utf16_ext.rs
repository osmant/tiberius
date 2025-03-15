use std::string::FromUtf16Error;

pub(crate) trait ToUtf16BytesLe {
    fn to_utf16_bytes_le(&self) -> Vec<u8>;
}

impl ToUtf16BytesLe for str {
    #[inline]
    /// Creates a UTF-16 little-endian byte representation of a `&str`.
    fn to_utf16_bytes_le(&self) -> Vec<u8> {
        self
            .encode_utf16()
            .flat_map(|word| [(word & 0xFF) as u8, ((word & 0xFF00) >> 8) as u8])
            .collect()
    }
}

pub(crate) trait FromUtf16BytesLe {
    fn from_utf16_bytes_le(bytes: &[u8]) -> Result<Self, FromUtf16Error> where Self: Sized;
}

#[cfg(target_endian="little")]
impl FromUtf16BytesLe for String {
    #[inline]
    /// Attempts to create a `String` based on UTF-16 little-endian bytes, 
    /// returning [`Err`] if `bytes` contains any invalid data.
    fn from_utf16_bytes_le(bytes: &[u8]) -> Result<Self, FromUtf16Error> {
        Self::from_utf16(
            unsafe {
                std::slice::from_raw_parts(bytes.as_ptr() as *const u16, bytes.len() / 2)
            }
        )
    }
}

#[cfg(target_endian="big")]
impl FromUtf16BytesLe for String {
    #[inline]
    /// Attempts to create a `String` based on UTF-16 little-endian bytes, 
    /// returning [`Err`] if `bytes` contains any invalid data.
    fn from_utf16_bytes_le(bytes: &[u8]) -> Result<String, FromUtf16Error> {
        // invert endianness
        let bytes_be = 
            bytes
                .chunks_exact(2)
                .flat_map(|c| [c[1], c[0]])
                .collect::<Vec<_>>();
        String::from_utf16(
            unsafe {
                std::slice::from_raw_parts(bytes_be.as_ptr() as *const u16, bytes_be.len() / 2)
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ToUtf16BytesLe, FromUtf16BytesLe};

    const HELLO_WORLD_UTF16_BYTES_LE: [u8; 30] = [104, 0, 101, 0, 108, 0, 108, 0, 111, 0, 44, 0, 32, 0, 119, 0, 111, 0, 114, 0, 108, 0, 100, 0, 33, 0, 61, 216, 128, 222];

    #[test]
    fn to_utf16_bytes_le_succeeds() {
        let text = "hello, world!🚀";

        let text_utf16_bytes = text.to_utf16_bytes_le();

        assert_eq!(HELLO_WORLD_UTF16_BYTES_LE.as_ref(), &text_utf16_bytes)
    }

    #[test]
    fn from_utf16_bytes_le_succeeds() {
        let text = String::from_utf16_bytes_le(&HELLO_WORLD_UTF16_BYTES_LE);

        assert!(text.is_ok());
        assert_eq!(String::from("hello, world!🚀"), text.unwrap());
    }

    #[test]
    fn roundtrip_from_utf16_bytes_le_to_utf16_bytes_le() {
        let text = "hello, world!🚀";

        let text_utf16_bytes = text.to_utf16_bytes_le();
        let text_again = String::from_utf16_bytes_le(&text_utf16_bytes);

        assert!(text_again.is_ok());
        assert_eq!(String::from("hello, world!🚀"), text_again.unwrap());
    }
}