use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Autnum {
    pub autnum: String,
    pub name: String,
    pub description: Option<String>,
}
