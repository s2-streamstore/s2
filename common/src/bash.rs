use bytes::Bytes;

/// BLAKE3 hash (32 bytes) of any number of fields.
///
/// Default SerDe implementation uses hex representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bash(blake3::Hash);

impl Bash {
    pub const LEN: usize = 32;

    /// Hashes components separated by a delimiter byte.
    /// Callers must ensure components do not contain the delimiter.
    pub fn delimited(components: &[&[u8]], delimiter: u8) -> Self {
        let mut hasher = blake3::Hasher::new();
        for component in components {
            hasher.update(component);
            hasher.update(&[delimiter]);
        }
        Self(hasher.finalize())
    }

    /// Hashes components with length prefixes to avoid separator ambiguity.
    pub fn length_prefixed(components: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for component in components {
            hasher.update(&(component.len() as u64).to_le_bytes());
            hasher.update(component);
        }
        Self(hasher.finalize())
    }

    pub fn as_bytes(&self) -> &[u8; Bash::LEN] {
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

impl From<[u8; Bash::LEN]> for Bash {
    fn from(bytes: [u8; Bash::LEN]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }
}

impl From<Bash> for Bytes {
    fn from(bash: Bash) -> Self {
        Bytes::copy_from_slice(bash.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::Bash;

    #[test]
    fn bash_len_prefixed_components_are_unambiguous() {
        let bash1 = Bash::length_prefixed(&[b"a\0", b"b"]);
        let bash2 = Bash::length_prefixed(&[b"a", b"\0b"]);

        assert_ne!(bash1, bash2);
    }
}
