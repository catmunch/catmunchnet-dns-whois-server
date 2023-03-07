use crate::resource::domain::NS;
use crate::util::cidr::Ipv6CidrWrapper;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Inet6num {
    pub cidr: Ipv6CidrWrapper,
    pub description: Option<String>,
    pub ns: Option<Vec<NS>>,
}
