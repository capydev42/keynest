use super::kdf::KdfParams;
use crate::crypto::{MAGIC_LEN, MEM_LEN, NONCE_LEN, PAR_LEN, SALT_LEN, TIME_LEN, VER_LEN};
use anyhow::{Context, Result, bail};

pub const VERSION_V1: u8 = 1;
pub const MAGIC: &[u8; MAGIC_LEN] = b"KNST";

#[derive(Debug)]
pub struct Header {
    version: u8,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    pub const LEN: usize =
        MAGIC_LEN + VER_LEN + MEM_LEN + TIME_LEN + PAR_LEN + SALT_LEN + NONCE_LEN;

    pub fn new(kdf: KdfParams, salt: [u8; SALT_LEN], nonce: [u8; NONCE_LEN]) -> Result<Self> {
        Ok(Self {
            version: VERSION_V1,
            kdf,
            salt,
            nonce,
        })
    }

    pub fn kdf(&self) -> &KdfParams {
        &self.kdf
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::LEN);

        buf.extend_from_slice(MAGIC);
        buf.push(self.version);

        buf.extend_from_slice(&self.kdf.mem_cost_kib().to_le_bytes());
        buf.extend_from_slice(&self.kdf.time_cost().to_le_bytes());
        buf.extend_from_slice(&self.kdf.parallelism().to_le_bytes());

        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < Self::LEN {
            bail!("keynest file too short");
        }

        if &data[..MAGIC_LEN] != MAGIC {
            bail!("invalid keynest file");
        }

        let version = data[MAGIC_LEN];
        if version != VERSION_V1 {
            bail!("unsupported keynest version: {version}");
        }

        let mut offset = MAGIC_LEN + 1;
        let mem_cost_kib = u32::from_le_bytes(data[offset..offset + MEM_LEN].try_into()?);
        offset += MEM_LEN;

        let time_cost = u32::from_le_bytes(data[offset..offset + TIME_LEN].try_into()?);
        offset += TIME_LEN;

        let parallelism = u32::from_le_bytes(data[offset..offset + PAR_LEN].try_into()?);
        offset += PAR_LEN;

        let salt: [u8; SALT_LEN] = data[offset..offset + SALT_LEN]
            .try_into()
            .context("invalid salt length")?;
        offset += SALT_LEN;

        let nonce: [u8; NONCE_LEN] = data[offset..offset + NONCE_LEN]
            .try_into()
            .context("invalid nonce length")?;
        offset += NONCE_LEN;

        Ok((
            Header {
                version,
                kdf: KdfParams::new(mem_cost_kib, time_cost, parallelism)?,
                salt,
                nonce,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        use crate::crypto::header::VERSION_V1;
        use crate::crypto::{Header, KdfParams};

        let header =
            Header::new(KdfParams::new(65536, 3, 2).unwrap(), [1u8; 16], [2u8; 24]).unwrap();

        let bytes = header.to_bytes();
        let (parsed, offset) = Header::from_bytes(&bytes).unwrap();

        assert_eq!(offset, Header::LEN);
        assert_eq!(parsed.version, VERSION_V1);
        assert_eq!(parsed.kdf.mem_cost_kib(), 65536);
        assert_eq!(parsed.kdf.time_cost(), 3);
        assert_eq!(parsed.kdf.parallelism(), 2);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(parsed.nonce, header.nonce);
    }

    #[test]
    fn header_invalid_magic_fails() {
        let mut data = vec![0u8; Header::LEN];
        data[..4].copy_from_slice(b"FAIL");

        assert!(Header::from_bytes(&data).is_err());
    }

    #[test]
    fn header_unsupported_version_fails() {
        let mut data = vec![0u8; Header::LEN];
        data[..4].copy_from_slice(b"KNST");
        data[4] = 99;

        assert!(Header::from_bytes(&data).is_err());
    }

    #[test]
    fn header_too_short_fails() {
        let data = vec![0u8; Header::LEN - 1];
        assert!(Header::from_bytes(&data).is_err());
    }
}
