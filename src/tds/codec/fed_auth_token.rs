use std::io::{Cursor, Write};
use std::mem;
use byteorder::{WriteBytesExt, LittleEndian};
use bytes::BytesMut;
use super::{Encode, ToUtf16BytesLe};

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct FedAuthToken<'a> {
    access_token: &'a str
}

impl<'a> FedAuthToken<'a> {
    pub fn new(access_token: &'a str) -> Self {
        Self {
            access_token
        }
    }
}

impl<'a> Encode<BytesMut> for FedAuthToken<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let access_token_bytes = self.access_token.to_utf16_bytes_le();
        let token_length = access_token_bytes.len();
        let data_length = token_length + mem::size_of::<u32>(); // include size of token_length
        let mut cursor = Cursor::new(Vec::with_capacity(data_length + mem::size_of::<u32>()));
        cursor.write_u32::<LittleEndian>(data_length as u32)?;
        cursor.write_u32::<LittleEndian>(token_length as u32)?;
        cursor.write(&access_token_bytes)?;

        dst.extend(cursor.into_inner());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BytesMut, Buf};
    use crate::tds::codec::{Encode, FromUtf16BytesLe};
    use super::FedAuthToken;

    #[test]
    fn encode_fed_auth_token() {
        let fed_auth_token = FedAuthToken {
            access_token: "testtoken"
        };

        let mut bytes = BytesMut::new();
        let result = fed_auth_token.encode(&mut bytes);

        assert!(result.is_ok());
        let data_length = bytes.get_u32_le();
        assert_eq!(2 * 9 + 4, data_length);
        let access_token_length = bytes.get_u32_le();
        assert_eq!(2 * 9, access_token_length);
        let access_token = String::from_utf16_bytes_le(bytes.get(0..).unwrap()).unwrap();
        assert_eq!("testtoken", access_token)
    }
}