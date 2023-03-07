use crate::resource::Resource;

pub struct IPTrie {
    children: [Option<Box<IPTrie>>; 2],
    pub inetnum: Option<Resource>,
    pub route: Option<Resource>,
}

impl IPTrie {
    pub(crate) fn new() -> Self {
        Self {
            children: [None, None],
            inetnum: None,
            route: None,
        }
    }
    pub fn traverse<const LEN: usize, F>(
        &self,
        address: &[u8; LEN],
        current_bit: usize,
        target_bit: usize,
        mut callback: F,
    ) where
        F: FnMut(&IPTrie, usize),
    {
        callback(self, current_bit);
        if current_bit == target_bit {
            return;
        }
        if current_bit > LEN * 8 {
            panic!("target_bit is out of address length")
        }
        let side: usize = ((address[current_bit / 8] >> (7 - current_bit % 8)) & 1) as usize;
        if self.children[side].is_none() {
            return;
        }
        self.children[side].as_ref().unwrap().traverse(
            address,
            current_bit + 1,
            target_bit,
            callback,
        );
    }
    pub fn traverse_mut<const LEN: usize, F>(
        &mut self,
        address: &[u8; LEN],
        current_bit: usize,
        target_bit: usize,
        callback: F,
    ) where
        F: Fn(&mut IPTrie, usize),
    {
        callback(self, current_bit);
        if current_bit == target_bit {
            return;
        }
        if current_bit > LEN * 8 {
            panic!("target_bit is out of address length")
        }
        let side: usize = ((address[current_bit / 8] >> (7 - current_bit % 8)) & 1) as usize;
        if self.children[side].is_none() {
            self.children[side] = Option::from(Box::new(IPTrie::new()))
        }
        self.children[side].as_mut().unwrap().traverse_mut(
            address,
            current_bit + 1,
            target_bit,
            callback,
        );
    }
    pub fn add(&mut self, resource: &Resource) {
        match resource {
            Resource::Inetnum(inetnum) => {
                let address = &inetnum.cidr.first_address().octets();
                let target_bit = inetnum.cidr.network_length() as usize;
                self.traverse_mut(address, 8, target_bit, |node, current_bit| {
                    if current_bit == target_bit {
                        node.inetnum = Option::from(Resource::Inetnum(inetnum.clone()));
                    }
                });
            }
            Resource::Inet6num(inet6num) => {
                let address = &inet6num.cidr.first_address().octets();
                let target_bit = inet6num.cidr.network_length() as usize;
                self.traverse_mut(address, 16, target_bit, |node, current_bit| {
                    if current_bit == target_bit {
                        node.inetnum = Option::from(Resource::Inet6num(inet6num.clone()));
                    }
                });
            }
            Resource::Route(route) => {
                let address = &route.cidr.first_address().octets();
                let target_bit = route.cidr.network_length() as usize;
                self.traverse_mut(address, 8, target_bit, |node, current_bit| {
                    if current_bit == target_bit {
                        node.route = Option::from(Resource::Route(route.clone()));
                    }
                });
            }
            Resource::Route6(route6) => {
                let address = &route6.cidr.first_address().octets();
                let target_bit = route6.cidr.network_length() as usize;
                self.traverse_mut(address, 16, target_bit, |node, current_bit| {
                    if current_bit == target_bit {
                        node.route = Option::from(Resource::Route6(route6.clone()));
                    }
                });
            }
            _ => {
                panic!("Invalid Resource Type!")
            }
        }
        return;
    }
}
