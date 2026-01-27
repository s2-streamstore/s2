use bytes::Bytes;

/// BLAKE3 hash (32 bytes) of any number of fields.
///
/// Default SerDe implementation uses hex representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bash(blake3::Hash);

impl Bash {
    pub const LEN: usize = 32;
    const SEPARATOR: u8 = 0_u8;

    pub fn new(components: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for component in components {
            hasher.update(component);
            hasher.update(&[Self::SEPARATOR]);
        }
        Self(hasher.finalize())
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Bash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.to_hex().as_str())
    }
}

impl AsRef<[u8]> for Bash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Bash> for [u8; Bash::LEN] {
    fn from(bash: Bash) -> Self {
        bash.0.into()
    }
}

impl From<[u8; Self::LEN]> for Bash {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }
}

impl From<Bash> for Bytes {
    fn from(bash: Bash) -> Self {
        Self::copy_from_slice(bash.as_bytes())
    }
}

impl serde::Serialize for Bash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Bash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let hash = blake3::Hash::from_hex(s.as_bytes()).map_err(serde::de::Error::custom)?;
        Ok(Self(hash))
    }
}
