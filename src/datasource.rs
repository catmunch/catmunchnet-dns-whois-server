use crate::resource::Resource;

pub mod git;
pub trait DataSource: Send + Sync {
    fn update(&mut self) -> bool;
    fn get_resources(&self) -> Vec<Resource>;
}
