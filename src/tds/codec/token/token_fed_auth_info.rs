use crate::{error::Error, sql_read_bytes::SqlReadBytes, tds::codec::FromUtf16BytesLe};
use byteorder::{LittleEndian, ReadBytesExt};
use futures_util::AsyncReadExt;
use std::{io::Cursor, mem};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/0e4486d6-d407-4962-9803-0c1a4d4d87ce
const FED_AUTH_INFOID_STSURL: u8 = 0x01;
const FED_AUTH_INFOID_SPN: u8 = 0x02;

/// Federated authentication information provided by the server.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct TokenFedAuthInfo {
    sts_url: String,
    spn: String,
}

impl TokenFedAuthInfo {
    pub(crate) fn sts_url(&self) -> &str {
        &self.sts_url
    }

    pub(crate) fn spn(&self) -> &str {
        &self.spn
    }

    pub(crate) async fn decode_async<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let token_length = src.read_u32_le().await? as usize - 4; // skip optionCount
        let option_count = src.read_u32_le().await?; //mandatory, can be 0
        let mut bytes = vec![0; token_length];
        src.read_exact(&mut bytes[0..token_length]).await?;

        // infoId + infoDataLen + infoDataOffset
        const OPTION_SIZE: u32 = (mem::size_of::<u8>() + 2 * mem::size_of::<u32>()) as u32;
        let total_option_size = option_count * OPTION_SIZE;

        let mut option_cursor = Cursor::new(&bytes[..total_option_size as usize]);

        let mut sts_url = None;
        let mut spn = None;

        for _ in 0..option_count as usize {
            let info_id = option_cursor.read_u8()?;
            let info_data_len = option_cursor.read_u32::<LittleEndian>()? as usize;
            let info_data_offset = option_cursor.read_u32::<LittleEndian>()? as usize - 4; // from optionCount
            let data_bytes = &bytes[info_data_offset..info_data_offset + info_data_len];
            let data = String::from_utf16_bytes_le(data_bytes)?;
            match info_id {
                FED_AUTH_INFOID_STSURL => sts_url = Some(data),
                FED_AUTH_INFOID_SPN => spn = Some(data),
                _ => {}
            };
        }

        match (sts_url, spn) {
            (Some(sts_url), Some(spn)) => Ok(Self { sts_url, spn }),
            _ => Err(Error::Protocol("Failed to read FedAuthInfo".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sql_read_bytes::test_utils::IntoSqlReadBytes, tds::codec::ToUtf16BytesLe};
    use bytes::{BufMut, BytesMut};

    #[tokio::test]
    async fn decode_token_fed_auth_info() {
        let mut fed_auth_info_bytes = BytesMut::new();

        let spn = "https://database.windows.net";
        let spn_bytes = spn.to_utf16_bytes_le();
        let sts_url = "https://login.microsoft.com/tenant";
        let sts_url_bytes = sts_url.to_utf16_bytes_le();

        let option_count = 2;
        let total_option_size = option_count * 9;
        let token_length =
            4 + total_option_size + spn_bytes.len() as u32 + sts_url_bytes.len() as u32;
        fed_auth_info_bytes.put_u32_le(token_length);
        fed_auth_info_bytes.put_u32_le(option_count);

        let data_start_index = total_option_size + 4;

        // option 1: sts url
        fed_auth_info_bytes.put_u8(FED_AUTH_INFOID_STSURL); // info id
        fed_auth_info_bytes.put_u32_le(sts_url_bytes.len() as u32); // info data length
        fed_auth_info_bytes.put_u32_le(data_start_index); // info data offset

        // option 2: spn
        fed_auth_info_bytes.put_u8(FED_AUTH_INFOID_SPN); // info id
        fed_auth_info_bytes.put_u32_le(spn_bytes.len() as u32); // info data length
        fed_auth_info_bytes.put_u32_le(data_start_index + sts_url_bytes.len() as u32); // info data offset

        // option 1 data
        fed_auth_info_bytes.put(sts_url_bytes.as_ref());

        // option 2 data
        fed_auth_info_bytes.put(spn_bytes.as_ref());

        let fed_auth_info =
            TokenFedAuthInfo::decode_async(&mut fed_auth_info_bytes.into_sql_read_bytes()).await;

        assert_eq!(
            Ok(TokenFedAuthInfo {
                spn: String::from("https://database.windows.net"),
                sts_url: String::from("https://login.microsoft.com/tenant")
            }),
            fed_auth_info
        )
    }
}
