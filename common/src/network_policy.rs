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
/// Issuing a token against a policy and deleting a policy take the full reference, so a
/// recreated slug cannot silently bind a token to rules nobody reviewed.
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

/// How a read-only request names a policy. Reads accept a bare slug, since reading cannot
/// bind a token to the wrong version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicySelector {
    Slug(NetworkPolicySlug),
    Ref(NetworkPolicyRef),
}

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

/// Restricts a token to public clients by source address.
///
/// At least one set is present and no present set is empty. Deny wins, so "allow 10.0.0.0/8
/// except 10.1.2.0/24" is expressible. Connections through a private network are rejected: their
/// source address is a private address in the customer's own VPC, which many customers share.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct CidrPolicy {
    allow: Option<Vec<Cidr>>,
    deny: Option<Vec<Cidr>>,
}

impl CidrPolicy {
    pub fn new(allow: Option<Vec<Cidr>>, deny: Option<Vec<Cidr>>) -> Result<Self, ValidationError> {
        if allow.as_ref().is_some_and(Vec::is_empty) || deny.as_ref().is_some_and(Vec::is_empty) {
            return Err("CIDR policy sets must not be empty; omit a set instead".into());
        }
        if allow.is_none() && deny.is_none() {
            return Err("CIDR policy must have an allow set or a deny set".into());
        }
        let identifiers = allow.as_ref().map_or(0, Vec::len) + deny.as_ref().map_or(0, Vec::len);
        if identifiers > caps::MAX_NETWORK_POLICY_IDENTIFIERS {
            return Err(format!(
                "network policy must not have more than {} CIDRs",
                caps::MAX_NETWORK_POLICY_IDENTIFIERS
            )
            .into());
        }
        Ok(Self { allow, deny })
    }

    pub fn allow(&self) -> Option<&[Cidr]> {
        self.allow.as_deref()
    }

    pub fn deny(&self) -> Option<&[Cidr]> {
        self.deny.as_deref()
    }

    fn permits(&self, ip: IpAddr) -> bool {
        let denied = self
            .deny
            .as_ref()
            .is_some_and(|deny| deny.iter().any(|cidr| cidr.contains(ip)));
        let allowed = self
            .allow
            .as_ref()
            .is_none_or(|allow| allow.iter().any(|cidr| cidr.contains(ip)));
        !denied && allowed
    }
}

/// Restricts a token to connections arriving through one of the listed VPC endpoints.
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
        if vpce_ids.len() > caps::MAX_NETWORK_POLICY_IDENTIFIERS {
            return Err(format!(
                "network policy must not have more than {} VPC endpoint IDs",
                caps::MAX_NETWORK_POLICY_IDENTIFIERS
            )
            .into());
        }
        Ok(Self { vpce_ids })
    }

    pub fn vpce_ids(&self) -> &[VpcEndpointId] {
        &self.vpce_ids
    }
}

/// A network policy is exactly one kind of restriction. New kinds are added as new variants,
/// never as extra restricting fields on an existing variant, so an older server that recognizes
/// a variant also enforces all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum NetworkPolicy {
    Cidr(CidrPolicy),
    PrivateNet(PrivateNetPolicy),
}

impl NetworkPolicy {
    /// Whether a client at `ip`, connected through `private_net_id` if any, may use a token
    /// carrying this policy.
    pub fn permits(&self, ip: IpAddr, private_net_id: Option<&str>) -> bool {
        match (self, private_net_id) {
            (Self::Cidr(policy), None) => policy.permits(ip),
            (Self::Cidr(_), Some(_)) => false,
            (Self::PrivateNet(_), None) => false,
            (Self::PrivateNet(policy), Some(private_net_id)) => policy
                .vpce_ids
                .iter()
                .any(|vpce_id| vpce_id.deref() == private_net_id),
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
        assert_eq!(cidr("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert!(cidr("0.0.0.0/0").contains("198.51.100.1".parse().unwrap()));
        assert!(!cidr("0.0.0.0/0").contains("2001:db8::1".parse().unwrap()));
        assert!(cidr("2001:db8::/32").contains("2001:db8:1::1".parse().unwrap()));
    }

    #[test]
    fn cidr_policy_deny_wins_and_rejects_private_connections() {
        let policy = NetworkPolicy::Cidr(
            CidrPolicy::new(
                Some(vec![cidr("10.0.0.0/8")]),
                Some(vec![cidr("10.1.2.0/24")]),
            )
            .unwrap(),
        );
        assert!(policy.permits("10.7.7.7".parse().unwrap(), None));
        assert!(!policy.permits("10.1.2.3".parse().unwrap(), None));
        assert!(!policy.permits("192.0.2.1".parse().unwrap(), None));
        assert!(!policy.permits("10.7.7.7".parse().unwrap(), Some("vpce-0123456789abcdef0")));

        let deny_only =
            NetworkPolicy::Cidr(CidrPolicy::new(None, Some(vec![cidr("10.1.2.0/24")])).unwrap());
        assert!(deny_only.permits("192.0.2.1".parse().unwrap(), None));
        assert!(!deny_only.permits("10.1.2.3".parse().unwrap(), None));

        assert!(CidrPolicy::new(None, None).is_err());
        assert!(CidrPolicy::new(Some(vec![]), Some(vec![cidr("10.1.2.0/24")])).is_err());
    }

    #[test]
    fn private_net_policy_requires_a_listed_endpoint() {
        let policy = NetworkPolicy::PrivateNet(
            PrivateNetPolicy::new(vec!["vpce-0123456789abcdef0".parse().unwrap()]).unwrap(),
        );
        assert!(policy.permits("10.0.0.1".parse().unwrap(), Some("vpce-0123456789abcdef0")));
        assert!(!policy.permits("10.0.0.1".parse().unwrap(), Some("vpce-0fedcba9876543210")));
        assert!(!policy.permits("203.0.113.1".parse().unwrap(), None));
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
