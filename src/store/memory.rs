use crate::resource::autnum::Autnum;
use crate::resource::domain::Domain;
use crate::resource::inet6num::Inet6num;
use crate::resource::inetnum::Inetnum;
use crate::resource::route::Route;
use crate::resource::route6::Route6;
use crate::resource::Resource;
use crate::store::Store;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use iptrie::IPTrie;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

mod iptrie;

#[derive(Clone)]
pub struct MemoryStore {
    autnums: Arc<RwLock<HashMap<String, Autnum>>>,
    domains: Arc<RwLock<HashMap<String, Domain>>>,
    trie4: Arc<RwLock<IPTrie>>,
    trie6: Arc<RwLock<IPTrie>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            autnums: Arc::new(RwLock::new(HashMap::new())),
            domains: Arc::new(RwLock::new(HashMap::new())),
            trie4: Arc::new(RwLock::new(IPTrie::new())),
            trie6: Arc::new(RwLock::new(IPTrie::new())),
        }
    }
}
impl Store for MemoryStore {
    fn set(&mut self, resources: &Vec<Resource>) {
        let mut autnums: HashMap<String, Autnum> = HashMap::new();
        let mut domains: HashMap<String, Domain> = HashMap::new();
        let mut trie4 = IPTrie::new();
        let mut trie6 = IPTrie::new();
        for resource in resources {
            match resource {
                Resource::Autnum(autnum) => {
                    autnums.insert(autnum.autnum.clone(), autnum.clone());
                }
                Resource::Domain(domain) => {
                    domains.insert(domain.domain.clone(), domain.clone());
                }
                Resource::Inetnum(_) | Resource::Route(_) => {
                    trie4.add(&resource);
                }
                Resource::Inet6num(_) | Resource::Route6(_) => {
                    trie6.add(&resource);
                }
            }
        }
        *self.autnums.write().unwrap() = autnums;
        *self.domains.write().unwrap() = domains;
        *self.trie4.write().unwrap() = trie4;
        *self.trie6.write().unwrap() = trie6;
    }

    fn get_autnum(&self, autnum: String) -> Option<Autnum> {
        let autnums = self.autnums.read().unwrap();
        match autnums.get(autnum.as_str()) {
            Some(autnum) => Some(autnum.clone()),
            None => None,
        }
    }

    fn get_domain(&self, domain: String) -> Option<Domain> {
        let domains = self.domains.read().unwrap();
        match domains.get(domain.as_str()) {
            Some(domain) => Some(domain.clone()),
            None => None,
        }
    }

    fn get_inetnum_prefixes(&self, inetnum: Ipv4Cidr) -> (Vec<Inetnum>, Vec<Route>) {
        let mut inetnums: Vec<Inetnum> = Vec::new();
        let mut routes: Vec<Route> = Vec::new();
        let address = &inetnum.first_address().octets();
        let target_bit = inetnum.network_length() as usize;
        self.trie4
            .read()
            .unwrap()
            .traverse(address, 8, target_bit, |node, _| {
                match &node.inetnum {
                    Some(Resource::Inetnum(inetnum)) => {
                        inetnums.push(inetnum.clone());
                    }
                    _ => {}
                }
                match &node.route {
                    Some(Resource::Route(route)) => {
                        routes.push(route.clone());
                    }
                    _ => {}
                }
            });
        (inetnums, routes)
    }

    fn get_inet6num_prefixes(&self, inetnum: Ipv6Cidr) -> (Vec<Inet6num>, Vec<Route6>) {
        let mut inetnums: Vec<Inet6num> = Vec::new();
        let mut routes: Vec<Route6> = Vec::new();
        let address = &inetnum.first_address().octets();
        let target_bit = inetnum.network_length() as usize;
        self.trie6
            .read()
            .unwrap()
            .traverse(address, 16, target_bit, |node, _| {
                match &node.inetnum {
                    Some(Resource::Inet6num(inetnum)) => {
                        inetnums.push(inetnum.clone());
                    }
                    _ => {}
                }
                match &node.route {
                    Some(Resource::Route6(route)) => {
                        routes.push(route.clone());
                    }
                    _ => {}
                }
            });
        (inetnums, routes)
    }

    fn clone_dyn(&self) -> Box<dyn Store> {
        Box::new(self.clone())
    }
}
