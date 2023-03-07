use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Domain {
    pub domain: String,
    pub description: Option<String>,
    pub ns: Vec<NS>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NS {
    pub server: String,
    pub a: Option<std::net::Ipv4Addr>,
    pub aaaa: Option<std::net::Ipv6Addr>,
}
