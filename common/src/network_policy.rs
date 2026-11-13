//! Network policies restrict the networks an access token may be used from.
//!
//! A policy is immutable. It is addressed by a user-chosen slug plus a nonce generated at
//! creation, written `<slug>.<nonce>`, so that a recreated slug never binds to an old reference.

use std::{
    fmt,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    str::FromStr,
};

use compact_str::{CompactString, ToCompactString};

use crate::{
    ValidationError, caps,
    resources::ListItemsRequest,
    strings::{PrefixProps, SlugProps, StartAfterProps, StrProps},
};

const NONCE_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn is_slug_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct NetworkPolicySlugStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> NetworkPolicySlugStr<T> {
    fn validate_str(slug: &str) -> Result<(), ValidationError> {
        if !T::IS_PREFIX && slug.is_empty() {
            return Err(format!("network policy {} must not be empty", T::FIELD_NAME).into());
        }

        if slug.len() > caps::MAX_NETWORK_POLICY_SLUG_LEN {
            return Err(format!(
                "network policy {} must not exceed {} bytes in length",
                T::FIELD_NAME,
                caps::MAX_NETWORK_POLICY_SLUG_LEN
            )
            .into());
        }

        if !slug.chars().all(is_slug_char) {
            return Err(format!(
                "network policy {} must comprise ASCII letters, numbers, hyphens, and underscores",
                T::FIELD_NAME
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(feature = "utoipa")]
impl<T: StrProps> utoipa::PartialSchema for NetworkPolicySlugStr<T> {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length((!T::IS_PREFIX).then_some(1))
            .max_length(Some(caps::MAX_NETWORK_POLICY_SLUG_LEN))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl<T: StrProps> utoipa::ToSchema for NetworkPolicySlugStr<T> {}

impl<T: StrProps> serde::Serialize for NetworkPolicySlugStr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, T: StrProps> serde::Deserialize<'de> for NetworkPolicySlugStr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl<T: StrProps> AsRef<str> for NetworkPolicySlugStr<T> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: StrProps> Deref for NetworkPolicySlugStr<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: StrProps> TryFrom<CompactString> for NetworkPolicySlugStr<T> {
    type Error = ValidationError;

    fn try_from(slug: CompactString) -> Result<Self, Self::Error> {
        Self::validate_str(&slug)?;
        Ok(Self(slug, PhantomData))
    }
}

impl<T: StrProps> FromStr for NetworkPolicySlugStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate_str(s)?;
        Ok(Self(s.to_compact_string(), PhantomData))
    }
}

impl<T: StrProps> fmt::Debug for NetworkPolicySlugStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> fmt::Display for NetworkPolicySlugStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub type NetworkPolicySlug = NetworkPolicySlugStr<SlugProps>;

pub type NetworkPolicySlugPrefix = NetworkPolicySlugStr<PrefixProps>;

impl Default for NetworkPolicySlugPrefix {
    fn default() -> Self {
        Self(CompactString::default(), PhantomData)
    }
}

pub type NetworkPolicySlugStartAfter = NetworkPolicySlugStr<StartAfterProps>;

impl Default for NetworkPolicySlugStartAfter {
    fn default() -> Self {
        Self(CompactString::default(), PhantomData)
    }
}

impl From<NetworkPolicySlug> for NetworkPolicySlugStartAfter {
    fn from(value: NetworkPolicySlug) -> Self {
        Self(value.0, PhantomData)
    }
}

/// Random suffix that distinguishes successive policies created under the same slug.
/// It is not a secret.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct NetworkPolicyNonce(CompactString);

impl NetworkPolicyNonce {
    /// The modulo bias is irrelevant: the nonce only has to differ between versions of a slug.
    pub fn from_random_bytes(bytes: [u8; caps::NETWORK_POLICY_NONCE_LEN]) -> Self {
        Self(
            bytes
                .iter()
                .map(|b| NONCE_ALPHABET[*b as usize % NONCE_ALPHABET.len()] as char)
                .collect(),
        )
    }
}

impl FromStr for NetworkPolicyNonce {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != caps::NETWORK_POLICY_NONCE_LEN
            || !s.bytes().all(|b| NONCE_ALPHABET.contains(&b))
        {
            return Err(format!(
                "network policy nonce must be {} lowercase letters or digits",
                caps::NETWORK_POLICY_NONCE_LEN
            )
            .into());
        }
        Ok(Self(s.to_compact_string()))
    }
}

impl Deref for NetworkPolicyNonce {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for NetworkPolicyNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for NetworkPolicyNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Full reference to one version of a policy, written `<slug>.<nonce>`.
///
/// Tokens are bound to the full reference. A request made with it fails if the slug has since
/// been recreated, so a caller holding a stale copy cannot bind a token to, or delete, rules it
/// never saw.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct NetworkPolicyRef {
    slug: NetworkPolicySlug,
    nonce: NetworkPolicyNonce,
}

impl NetworkPolicyRef {
    pub fn new(slug: NetworkPolicySlug, nonce: NetworkPolicyNonce) -> Self {
        Self { slug, nonce }
    }

    pub fn slug(&self) -> &NetworkPolicySlug {
        &self.slug
    }

    pub fn nonce(&self) -> &NetworkPolicyNonce {
        &self.nonce
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for NetworkPolicyRef {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .description(Some("Network policy reference, `<slug>.<nonce>`."))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for NetworkPolicyRef {}

impl FromStr for NetworkPolicyRef {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((slug, nonce)) = s.rsplit_once('.') else {
            return Err("network policy reference must be of the form <slug>.<nonce>".into());
        };
        Ok(Self {
            slug: slug.parse()?,
            nonce: nonce.parse()?,
        })
    }
}

impl serde::Serialize for NetworkPolicyRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for NetworkPolicyRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for NetworkPolicyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for NetworkPolicyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.slug, self.nonce)
    }
}

/// How a request names a policy. A bare slug selects whichever policy currently holds it; a
/// full reference selects only that version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicySelector {
    Slug(NetworkPolicySlug),
    Ref(NetworkPolicyRef),
}

impl From<NetworkPolicySlug> for NetworkPolicySelector {
    fn from(slug: NetworkPolicySlug) -> Self {
        Self::Slug(slug)
    }
}

impl From<NetworkPolicyRef> for NetworkPolicySelector {
    fn from(reference: NetworkPolicyRef) -> Self {
        Self::Ref(reference)
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for NetworkPolicySelector {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .description(Some(
                "Network policy slug, or full `<slug>.<nonce>` reference.",
            ))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for NetworkPolicySelector {}

impl NetworkPolicySelector {
    pub fn slug(&self) -> &NetworkPolicySlug {
        match self {
            Self::Slug(slug) => slug,
            Self::Ref(reference) => reference.slug(),
        }
    }

    pub fn nonce(&self) -> Option<&NetworkPolicyNonce> {
        match self {
            Self::Slug(_) => None,
            Self::Ref(reference) => Some(reference.nonce()),
        }
    }

    pub fn selects(&self, id: &NetworkPolicyRef) -> bool {
        match self {
            Self::Slug(slug) => slug == id.slug(),
            Self::Ref(reference) => reference == id,
        }
    }
}

impl FromStr for NetworkPolicySelector {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('.') {
            s.parse().map(Self::Ref)
        } else {
            s.parse().map(Self::Slug)
        }
    }
}

impl fmt::Display for NetworkPolicySelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Slug(slug) => fmt::Display::fmt(slug, f),
            Self::Ref(reference) => fmt::Display::fmt(reference, f),
        }
    }
}

impl serde::Serialize for NetworkPolicySelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for NetworkPolicySelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An IP network in CIDR notation. Host bits must be zero: `203.0.113.5/24` is rejected rather
/// than silently widened.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, ValidationError> {
        let max_prefix_len = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix_len {
            return Err(format!("CIDR prefix length must be at most {max_prefix_len}").into());
        }
        let cidr = Self { addr, prefix_len };
        if cidr.network_of(addr) != addr {
            return Err(format!("CIDR {cidr} has host bits set").into());
        }
        // Client addresses are matched in canonical form, where an IPv4-mapped address is IPv4,
        // so a range inside `::ffff:0:0/96` would never match.
        if let IpAddr::V6(v6) = addr
            && prefix_len >= 96
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            return Err(format!(
                "CIDR {cidr} is an IPv4-mapped IPv6 range; write it as {v4}/{}",
                prefix_len - 96
            )
            .into());
        }
        Ok(cidr)
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `ip` falls within this network. An address of the other IP version never does.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                self.network_of(ip) == self.addr
            }
            _ => false,
        }
    }

    fn network_of(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(ip) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from_bits(ip.to_bits() & mask))
            }
            IpAddr::V6(ip) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from_bits(ip.to_bits() & mask))
            }
        }
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for Cidr {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .description(Some("IP network in CIDR notation, e.g. `203.0.113.0/24`."))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for Cidr {}

impl FromStr for Cidr {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((addr, prefix_len)) = s.split_once('/') else {
            return Err(format!("CIDR {s:?} must be of the form <address>/<prefix length>").into());
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|e| format!("CIDR {s:?} has an invalid address: {e}"))?;
        let prefix_len: u8 = prefix_len
            .parse()
            .map_err(|e| format!("CIDR {s:?} has an invalid prefix length: {e}"))?;
        Self::new(addr, prefix_len)
    }
}

impl serde::Serialize for Cidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// AWS VPC endpoint ID, e.g. `vpce-0a1b2c3d4e5f67890`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct VpcEndpointId(CompactString);

impl FromStr for VpcEndpointId {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = s
            .strip_prefix("vpce-")
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()));
        if !valid {
            return Err(format!(
                "VPC endpoint ID {s:?} must be \"vpce-\" followed by hexadecimal digits"
            )
            .into());
        }
        Ok(Self(s.to_compact_string()))
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for VpcEndpointId {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .description(Some("AWS VPC endpoint ID, e.g. `vpce-0a1b2c3d4e5f67890`."))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for VpcEndpointId {}

impl serde::Serialize for VpcEndpointId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for VpcEndpointId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Deref for VpcEndpointId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for VpcEndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for VpcEndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The source addresses a token may be used from over the public path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct CidrPolicy {
    allow: Vec<Cidr>,
}

impl CidrPolicy {
    pub fn new(allow: Vec<Cidr>) -> Result<Self, ValidationError> {
        if allow.is_empty() {
            return Err("CIDR policy must allow at least one CIDR".into());
        }
        if allow.len() > caps::MAX_NETWORK_POLICY_CIDRS {
            return Err(format!(
                "network policy must not have more than {} CIDRs",
                caps::MAX_NETWORK_POLICY_CIDRS
            )
            .into());
        }
        Ok(Self { allow })
    }

    pub fn allow(&self) -> &[Cidr] {
        &self.allow
    }
}

/// The VPC endpoints a token may be used through.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PrivateNetPolicy {
    vpce_ids: Vec<VpcEndpointId>,
}

impl PrivateNetPolicy {
    pub fn new(vpce_ids: Vec<VpcEndpointId>) -> Result<Self, ValidationError> {
        if vpce_ids.is_empty() {
            return Err("private network policy must list at least one VPC endpoint ID".into());
        }
        if vpce_ids.len() > caps::MAX_NETWORK_POLICY_VPC_ENDPOINTS {
            return Err(format!(
                "network policy must not have more than {} VPC endpoint IDs",
                caps::MAX_NETWORK_POLICY_VPC_ENDPOINTS
            )
            .into());
        }
        Ok(Self { vpce_ids })
    }

    pub fn vpce_ids(&self) -> &[VpcEndpointId] {
        &self.vpce_ids
    }
}

/// A network policy lists what is allowed on each path a request can arrive by, and at least
/// one path is listed. A path that is not listed is closed.
///
/// Every part of a policy only ever allows. A new kind of rule must do the same, opening a path
/// of its own, so that a server which does not know it enforces a narrower policy, never a wider
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct NetworkPolicy {
    cidr: Option<CidrPolicy>,
    private_net: Option<PrivateNetPolicy>,
}

impl NetworkPolicy {
    pub fn new(
        cidr: Option<CidrPolicy>,
        private_net: Option<PrivateNetPolicy>,
    ) -> Result<Self, ValidationError> {
        if cidr.is_none() && private_net.is_none() {
            return Err(
                "network policy must have a CIDR policy or a private network policy".into(),
            );
        }
        Ok(Self { cidr, private_net })
    }

    /// Governs requests arriving over the public path.
    pub fn cidr(&self) -> Option<&CidrPolicy> {
        self.cidr.as_ref()
    }

    /// Governs requests arriving through a private network.
    pub fn private_net(&self) -> Option<&PrivateNetPolicy> {
        self.private_net.as_ref()
    }

    /// Whether a client at `ip`, connected through `private_net_id` if any, may use a token
    /// carrying this policy.
    ///
    /// A private connection is matched by its endpoint alone: its source address is a private
    /// address in the customer's own VPC, which many customers share.
    pub fn permits(&self, ip: IpAddr, private_net_id: Option<&str>) -> bool {
        match private_net_id {
            None => self
                .cidr
                .as_ref()
                .is_some_and(|policy| policy.allow.iter().any(|cidr| cidr.contains(ip))),
            Some(private_net_id) => self.private_net.as_ref().is_some_and(|policy| {
                policy
                    .vpce_ids
                    .iter()
                    .any(|vpce_id| vpce_id.deref() == private_net_id)
            }),
        }
    }
}

impl From<CidrPolicy> for NetworkPolicy {
    fn from(cidr: CidrPolicy) -> Self {
        Self {
            cidr: Some(cidr),
            private_net: None,
        }
    }
}

impl From<PrivateNetPolicy> for NetworkPolicy {
    fn from(private_net: PrivateNetPolicy) -> Self {
        Self {
            cidr: None,
            private_net: Some(private_net),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPolicyInfo {
    pub id: NetworkPolicyRef,
    pub created_at: time::OffsetDateTime,
    pub policy: NetworkPolicy,
}

#[derive(Debug, Clone)]
pub struct CreateNetworkPolicyRequest {
    pub slug: NetworkPolicySlug,
    pub policy: NetworkPolicy,
}

pub type ListNetworkPoliciesRequest =
    ListItemsRequest<NetworkPolicySlugPrefix, NetworkPolicySlugStartAfter>;

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_rejects_host_bits_and_bad_prefixes() {
        assert!("203.0.113.5/24".parse::<Cidr>().is_err());
        assert!("203.0.113.0/33".parse::<Cidr>().is_err());
        assert!("2001:db8::1/64".parse::<Cidr>().is_err());
        assert!("203.0.113.0".parse::<Cidr>().is_err());
        assert!("::ffff:203.0.113.0/120".parse::<Cidr>().is_err());
        assert_eq!(cidr("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert!(cidr("0.0.0.0/0").contains("198.51.100.1".parse().unwrap()));
        assert!(!cidr("0.0.0.0/0").contains("2001:db8::1".parse().unwrap()));
        assert!(cidr("2001:db8::/32").contains("2001:db8:1::1".parse().unwrap()));
    }

    #[test]
    fn each_path_is_governed_by_its_own_kind_and_closed_without_one() {
        const LISTED: &str = "vpce-0123456789abcdef0";
        let public = CidrPolicy::new(vec![cidr("10.0.0.0/8")]).unwrap();
        let private_net = PrivateNetPolicy::new(vec![LISTED.parse().unwrap()]).unwrap();
        let both = NetworkPolicy::new(Some(public.clone()), Some(private_net.clone())).unwrap();
        let cidr_only = NetworkPolicy::from(public);
        let private_net_only = NetworkPolicy::from(private_net);

        let allowed_ip: IpAddr = "10.7.7.7".parse().unwrap();
        let other_ip: IpAddr = "192.0.2.1".parse().unwrap();
        let unlisted = "vpce-0fedcba9876543210";

        // (public allowed IP, public other IP, listed endpoint, unlisted endpoint from allowed IP)
        for (policy, expected) in [
            (&both, [true, false, true, false]),
            (&cidr_only, [true, false, false, false]),
            (&private_net_only, [false, false, true, false]),
        ] {
            let actual = [
                policy.permits(allowed_ip, None),
                policy.permits(other_ip, None),
                policy.permits(other_ip, Some(LISTED)),
                policy.permits(allowed_ip, Some(unlisted)),
            ];
            assert_eq!(actual, expected, "{policy:?}");
        }

        assert!(NetworkPolicy::new(None, None).is_err());
        assert!(CidrPolicy::new(vec![]).is_err());
        assert!(CidrPolicy::new(vec![cidr("10.0.0.0/8"); 33]).is_err());
        assert!(PrivateNetPolicy::new(vec![]).is_err());
        assert!("vpce-".parse::<VpcEndpointId>().is_err());
        assert!("vpc-0123".parse::<VpcEndpointId>().is_err());
    }

    #[test]
    fn references_round_trip_and_reject_bare_slugs() {
        let reference: NetworkPolicyRef = "office.k3j9x2qa".parse().unwrap();
        assert_eq!(reference.slug().as_ref(), "office");
        assert_eq!(reference.to_string(), "office.k3j9x2qa");
        assert!("office".parse::<NetworkPolicyRef>().is_err());
        assert!("office.K3J9X2QA".parse::<NetworkPolicyRef>().is_err());
        assert!("off.ice.k3j9x2qa".parse::<NetworkPolicyRef>().is_err());
        assert!(matches!(
            "office".parse::<NetworkPolicySelector>().unwrap(),
            NetworkPolicySelector::Slug(_)
        ));
        assert!(matches!(
            "office.k3j9x2qa".parse::<NetworkPolicySelector>().unwrap(),
            NetworkPolicySelector::Ref(_)
        ));
        assert_eq!(
            NetworkPolicyNonce::from_random_bytes([0, 1, 25, 26, 35, 36, 255, 7]).to_string(),
            "abz09adh"
        );
    }
}
