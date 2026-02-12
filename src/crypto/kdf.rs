use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};

use super::KEY_LEN;

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    mem_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            // default memory cost
            mem_cost_kib: 64 * 1024, // 64 MiB
            // default number of itereations
            time_cost: 3,
            // default number of threads
            parallelism: 1,
        }
    }
}

impl KdfParams {
    pub fn new(mem_cost_kib: u32, time_cost: u32, parallelism: u32) -> anyhow::Result<Self> {
        let params = Self {
            mem_cost_kib,
            time_cost,
            parallelism,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn mem_cost_kib(&self) -> u32 {
        self.mem_cost_kib
    }

    pub fn time_cost(&self) -> u32 {
        self.time_cost
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.mem_cost_kib < 8 {
            anyhow::bail!("argon2 memory cost too low");
        }
        if self.time_cost < 1 {
            anyhow::bail!("argon2 time cost must be >= 1");
        }
        if self.parallelism < 1 {
            anyhow::bail!("argon2 parallelism must be >= 1");
        }
        if self.mem_cost_kib < 8 * self.parallelism {
            anyhow::bail!("argon2 memory cost must be at least 8 * parallelism");
        }
        Ok(())
    }
}

pub fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Result<[u8; KEY_LEN]> {
    kdf.validate().context("invalid Argon2 parameters")?;

    let params = Params::new(
        kdf.mem_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| anyhow::anyhow!("failed to construct Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed {e}"))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;

    #[test]
    fn kdf_is_deterministic() {
        let salt = [42u8; 16];
        let kdf = KdfParams::default();

        let k1 = derive_key("password", &salt, kdf).unwrap();
        let k2 = derive_key("password", &salt, kdf).unwrap();

        assert_eq!(k1, k2);
    }
    #[test]
    fn kdf_params_affect_output() {
        use crate::crypto::{derive_key, KdfParams};

        let salt = [7u8; 16];

        let kdf1 = KdfParams {
            mem_cost_kib: 32768,
            time_cost: 2,
            parallelism: 1,
        };

        let kdf2 = KdfParams {
            mem_cost_kib: 65536,
            time_cost: 2,
            parallelism: 1,
        };

        let k1 = derive_key("pw", &salt, kdf1).unwrap();
        let k2 = derive_key("pw", &salt, kdf2).unwrap();

        assert_ne!(k1, k2);
    }

    #[test]
    fn kdf_invalid_params_fail_gracefully() {
        use crate::crypto::KdfParams;
        assert!(KdfParams::new(0, 0, 0).is_err());
    }
}
