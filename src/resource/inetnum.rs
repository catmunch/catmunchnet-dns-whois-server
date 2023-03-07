use crate::resource::domain::NS;
use crate::util::cidr::Ipv4CidrWrapper;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Inetnum {
    pub cidr: Ipv4CidrWrapper,
    pub description: Option<String>,
    pub ns: Option<Vec<NS>>,
}
