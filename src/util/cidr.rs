use cidr::{Ipv4Cidr, Ipv6Cidr};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::str::FromStr;

#[derive(Clone, PartialEq)]
pub struct Ipv4CidrWrapper(pub Ipv4Cidr);
struct Ipv4CidrVisitor;

impl Visitor<'_> for Ipv4CidrVisitor {
    type Value = Ipv4CidrWrapper;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("an ipv4 cidr")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Ipv4CidrWrapper(Ipv4Cidr::from_str(v).unwrap()))
    }
}

impl<'de> Deserialize<'de> for Ipv4CidrWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Ipv4CidrWrapper, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(Ipv4CidrVisitor)
    }
}

impl Serialize for Ipv4CidrWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl Deref for Ipv4CidrWrapper {
    type Target = Ipv4Cidr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Ipv4CidrWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, PartialEq)]
pub struct Ipv6CidrWrapper(pub Ipv6Cidr);
struct Ipv6CidrVisitor;

impl Visitor<'_> for Ipv6CidrVisitor {
    type Value = Ipv6CidrWrapper;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("an ipv4 cidr")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Ipv6CidrWrapper(Ipv6Cidr::from_str(v).unwrap()))
    }
}

impl<'de> Deserialize<'de> for Ipv6CidrWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Ipv6CidrWrapper, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(Ipv6CidrVisitor)
    }
}

impl Serialize for Ipv6CidrWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl Deref for Ipv6CidrWrapper {
    type Target = Ipv6Cidr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Ipv6CidrWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
