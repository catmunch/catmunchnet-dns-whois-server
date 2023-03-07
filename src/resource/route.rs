use crate::util::cidr::Ipv4CidrWrapper;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Route {
    pub cidr: Ipv4CidrWrapper,
    pub description: Option<String>,
    pub origin: Vec<String>,
}
