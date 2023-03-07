use crate::resource::autnum::Autnum;
use crate::resource::domain::Domain;
use crate::resource::inet6num::Inet6num;
use crate::resource::inetnum::Inetnum;
use crate::resource::route::Route;
use crate::resource::route6::Route6;
use crate::resource::Resource;
use cidr::{Ipv4Cidr, Ipv6Cidr};

pub mod memory;

pub trait Store: Send + Sync {
    fn set(&mut self, resources: &Vec<Resource>);
    fn get_autnum(&self, autnum: String) -> Option<Autnum>;
    fn get_domain(&self, domain: String) -> Option<Domain>;
    fn get_inetnum_prefixes(&self, inetnum: Ipv4Cidr) -> (Vec<Inetnum>, Vec<Route>);
    fn get_inet6num_prefixes(&self, inet6num: Ipv6Cidr) -> (Vec<Inet6num>, Vec<Route6>);
    fn clone_dyn(&self) -> Box<dyn Store>;
}

impl Clone for Box<dyn Store> {
    fn clone(&self) -> Self {
        self.clone_dyn()
    }
}
