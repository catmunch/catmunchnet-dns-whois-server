use crate::config::Config;
use crate::store::Store;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use lazy_static::lazy_static;
use std::io::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use log::info;
use tokio::net::UdpSocket;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::client::rr::LowerName;
use trust_dns_server::proto::op::{Header, MessageType, OpCode, ResponseCode};
use trust_dns_server::proto::rr::{IntoName, Name, RData, Record};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use trust_dns_server::ServerFuture;

pub async fn run_dns_server(config: &Config, store: Box<dyn Store>) -> Result<(), Error> {
    let handler = Handler::new(store);
    let mut server = ServerFuture::new(handler);
    for addr in &config.dns {
        server.register_socket(UdpSocket::bind(addr).await?);
    }
    info!("DNS server started.");
    server.block_until_done().await?;
    Ok(())
}
struct Handler {
    store: Box<dyn Store>,
}
fn convert_name_to_vec(name: &LowerName) -> Vec<String> {
    name.into_name()
        .unwrap()
        .iter()
        .map(|v| String::from_utf8_lossy(&v.to_vec()).to_string())
        .collect()
}
impl Handler {
    fn new(store: Box<dyn Store>) -> Self {
        Self { store }
    }
    async fn do_handle_request_code<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
        code: ResponseCode,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(code);
        let response = builder.build_no_records(header);
        response_handle.send_response(response).await
    }
    async fn do_handle_request_domain<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> Result<ResponseInfo, Error> {
        let name = request.query().name();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let domain_name = name.into_name().unwrap().trim_to(2);
        let mut domain_str = domain_name.to_string();
        domain_str.pop(); // remove the '.'
        match self.store.get_domain(domain_str) {
            Some(domain) => {
                let mut nameservers: Vec<Record> = vec![];
                let mut additional_records: Vec<Record> = vec![];
                domain.ns.iter().for_each(|ns| {
                    let name = Name::from_str(ns.server.as_str()).unwrap();
                    nameservers.push(Record::from_rdata(
                        domain_name.clone(),
                        300,
                        RData::NS(name.clone()),
                    ));
                    if ns.a.is_some() {
                        additional_records.push(Record::from_rdata(
                            name.clone(),
                            300,
                            RData::A(ns.a.unwrap()),
                        ));
                    }
                    if ns.aaaa.is_some() {
                        additional_records.push(Record::from_rdata(
                            name.clone(),
                            300,
                            RData::AAAA(ns.aaaa.unwrap()),
                        ));
                    }
                });
                let response = builder.build(
                    header,
                    &[],
                    nameservers.iter(),
                    &[],
                    additional_records.iter(),
                );
                response_handle.send_response(response).await
            }
            None => {
                self.do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                    .await
            }
        }
    }
    async fn do_handle_request_ipv4<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> Result<ResponseInfo, Error> {
        let name = request.query().name();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let mut parts = convert_name_to_vec(name);
        parts.pop(); // pop arpa
        parts.pop(); // pop in-addr
        if parts.len() < 1 || parts.len() > 4 {
            // invalid length
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                .await;
        }
        let mut digits: u32 = 0;
        for i in (0..parts.len()).rev() {
            match parts[i].parse::<u8>() {
                Ok(num) => digits = (digits << 8) + num as u32,
                Err(_) => {
                    return self
                        .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                        .await
                }
            }
        }
        let mut mask_len = 32;
        for _ in parts.len()..4 {
            digits <<= 8;
            mask_len -= 8;
        }
        let cidr = Ipv4Cidr::new(Ipv4Addr::from(digits), mask_len);
        if cidr.is_err() {
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                .await;
        }
        let cidr = cidr.unwrap();
        let (prefixes, _) = self.store.get_inetnum_prefixes(cidr);
        if prefixes.len() == 0 {
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                .await;
        }
        let mut nameservers: Vec<Record> = vec![];
        let mut additional_records: Vec<Record> = vec![];
        if prefixes[0].ns.is_some() {
            prefixes[0].ns.as_ref().unwrap().iter().for_each(|ns| {
                let cidr_domain_name = name
                    .into_name()
                    .unwrap()
                    .trim_to(((prefixes[0].cidr.network_length() + 7) / 8 + 2) as usize);
                let ns_name = Name::from_str(ns.server.as_str()).unwrap();
                nameservers.push(Record::from_rdata(
                    cidr_domain_name.clone(),
                    300,
                    RData::NS(ns_name.clone()),
                ));
                if ns.a.is_some() {
                    additional_records.push(Record::from_rdata(
                        ns_name.clone(),
                        300,
                        RData::A(ns.a.unwrap()),
                    ));
                }
                if ns.aaaa.is_some() {
                    additional_records.push(Record::from_rdata(
                        ns_name.clone(),
                        300,
                        RData::AAAA(ns.aaaa.unwrap()),
                    ));
                }
            });
        }
        let response = builder.build(
            header,
            &[],
            nameservers.iter(),
            &[],
            additional_records.iter(),
        );
        response_handle.send_response(response).await
    }
    async fn do_handle_request_ipv6<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> Result<ResponseInfo, Error> {
        let name = request.query().name();
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let mut parts = convert_name_to_vec(name);
        parts.pop(); // pop arpa
        parts.pop(); // pop ip6
        if parts.len() < 1 || parts.len() > 32 {
            // invalid length
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                .await;
        }
        let mut digits: u128 = 0;
        for i in (0..parts.len()).rev() {
            match u8::from_str_radix(parts[i].as_str(), 16) {
                Ok(num) => {
                    if num >= 16 {
                        return self
                            .do_handle_request_code(
                                request,
                                response_handle,
                                ResponseCode::NXDomain,
                            )
                            .await;
                    }
                    digits = (digits << 4) + num as u128
                }
                Err(_) => {
                    return self
                        .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                        .await
                }
            }
        }
        let mut mask_len = 128;
        for _ in parts.len()..32 {
            digits <<= 4;
            mask_len -= 4;
        }
        let cidr = Ipv6Cidr::new(Ipv6Addr::from(digits), mask_len);
        if cidr.is_err() {
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                .await;
        }
        let cidr = cidr.unwrap();
        let (prefixes, _) = self.store.get_inet6num_prefixes(cidr);
        if prefixes.len() == 0 {
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::NXDomain)
                .await;
        }
        let mut nameservers: Vec<Record> = vec![];
        let mut additional_records: Vec<Record> = vec![];
        if prefixes[0].ns.is_some() {
            prefixes[0].ns.as_ref().unwrap().iter().for_each(|ns| {
                let cidr_domain_name = name
                    .into_name()
                    .unwrap()
                    .trim_to(((prefixes[0].cidr.network_length() + 3) / 4 + 2) as usize);
                let ns_name = Name::from_str(ns.server.as_str()).unwrap();
                nameservers.push(Record::from_rdata(
                    cidr_domain_name.clone(),
                    300,
                    RData::NS(ns_name.clone()),
                ));
                if ns.a.is_some() {
                    additional_records.push(Record::from_rdata(
                        ns_name.clone(),
                        300,
                        RData::A(ns.a.unwrap()),
                    ));
                }
                if ns.aaaa.is_some() {
                    additional_records.push(Record::from_rdata(
                        ns_name.clone(),
                        300,
                        RData::AAAA(ns.aaaa.unwrap()),
                    ));
                }
            });
        }
        let response = builder.build(
            header,
            &[],
            nameservers.iter(),
            &[],
            additional_records.iter(),
        );
        response_handle.send_response(response).await
    }
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> Result<ResponseInfo, Error> {
        lazy_static! {
            static ref TLD_ROOT: LowerName = LowerName::from_str("catmunch").unwrap();
            static ref RDNS_IPV4: LowerName = LowerName::from_str("in-addr.arpa").unwrap();
            static ref RDNS_IPV6: LowerName = LowerName::from_str("ip6.arpa").unwrap();
        }
        if request.op_code() != OpCode::Query {
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::ServFail)
                .await;
        }
        if request.message_type() != MessageType::Query {
            return self
                .do_handle_request_code(request, response_handle, ResponseCode::ServFail)
                .await;
        }
        match request.query().name() {
            name if TLD_ROOT.zone_of(name) => {
                self.do_handle_request_domain(request, response_handle)
                    .await
            }
            name if RDNS_IPV4.zone_of(name) => {
                self.do_handle_request_ipv4(request, response_handle).await
            }
            name if RDNS_IPV6.zone_of(name) => {
                self.do_handle_request_ipv6(request, response_handle).await
            }
            _ => {
                self.do_handle_request_code(request, response_handle, ResponseCode::ServFail)
                    .await
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        match self.do_handle_request(request, &mut response_handle).await {
            Ok(response) => response,
            Err(_) => {
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
