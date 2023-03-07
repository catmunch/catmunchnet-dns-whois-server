pub mod autnum;
pub mod domain;
pub mod inet6num;
pub mod inetnum;
pub mod route;
pub mod route6;

#[derive(Debug)]
pub enum Resource {
    Autnum(autnum::Autnum),
    Domain(domain::Domain),
    Inetnum(inetnum::Inetnum),
    Inet6num(inet6num::Inet6num),
    Route(route::Route),
    Route6(route6::Route6),
}
