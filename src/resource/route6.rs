use crate::util::cidr::Ipv6CidrWrapper;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Route6 {
    pub cidr: Ipv6CidrWrapper,
    pub description: Option<String>,
    pub origin: Vec<String>,
}
