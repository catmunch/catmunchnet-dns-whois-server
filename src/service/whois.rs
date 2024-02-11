use std::io;
use crate::config::Config;
use crate::store::Store;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use futures_util::future;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::str::FromStr;
use log::info;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio_util::sync::CancellationToken;

#[derive(Serialize)]
struct IPResponse<S, T>
where
    S: Serialize,
    T: Serialize,
{
    inetnums: Vec<S>,
    routes: Vec<T>,
}

static WHOIS_REQUEST_MAX_LENGTH: u64 = 128;
async fn handle_whois_request(mut socket: TcpStream, store: Box<dyn Store>, config: Box<Config>) {
    lazy_static! {
        static ref ASN_REGEX: Regex = Regex::new(r"^as(\d+)$").unwrap();
        static ref DOMAIN_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9-_]+\.catmunch$").unwrap();
    }
    let reader = BufReader::new(&mut socket);
    let mut reader = reader.take(WHOIS_REQUEST_MAX_LENGTH);
    let mut request = String::new();
    if reader.read_line(&mut request).await.is_err() {
        let _ = socket
            .write("An error occurred when reading the request, please try again.\r\n".as_bytes())
            .await;
        return;
    }
    let request = request.trim().to_lowercase();
    let mut response = format!("No match for {}\r\n", request);
    if request == "whoami" {
        response = config.node_name.clone();
    } else if ASN_REGEX.is_match(request.as_str()) {
        let result = store.get_autnum(request.to_uppercase());
        if result.is_some() {
            response = serde_yaml::to_string(&result.unwrap()).unwrap();
        }
    } else if DOMAIN_REGEX.is_match(request.as_str()) {
        let result = store.get_domain(request);
        if result.is_some() {
            response = serde_yaml::to_string(&result.unwrap()).unwrap();
        }
    } else if Ipv4Cidr::from_str(request.as_str()).is_ok() {
        let cidr = Ipv4Cidr::from_str(request.as_str()).unwrap();
        let (inetnums, routes) = store.get_inetnum_prefixes(cidr);
        let _ = socket
            .write(
                serde_yaml::to_string(&IPResponse { inetnums, routes })
                    .unwrap()
                    .as_bytes(),
            )
            .await;
        return;
    } else if Ipv6Cidr::from_str(request.as_str()).is_ok() {
        let cidr = Ipv6Cidr::from_str(request.as_str()).unwrap();
        let (inetnums, routes) = store.get_inet6num_prefixes(cidr);
        let _ = socket
            .write(
                serde_yaml::to_string(&IPResponse { inetnums, routes })
                    .unwrap()
                    .as_bytes(),
            )
            .await;
        return;
    } else {
        let _ = socket.write("Supported type: autnum (e.g. AS64601), domain (e.g. meow.catmunch), inetnum/route (e.g. 10.0.0.1, 10.0.0.0/16, fc75:adfb:1234::1, fc75:adfb:1234::/48)\r\n".as_bytes()).await;
    }
    let _ = socket.write(response.as_bytes()).await;
}

pub async fn run_whois_server(config: &Config, store: Box<dyn Store>, cancellation_token: CancellationToken) -> io::Result<()> {
    let mut loops = Vec::new();
    let config_box = Box::new(config.clone());
    for addr in &config.whois {
        let listener = TcpListener::bind(addr).await?;
        let store = store.clone();
        let config_box = config_box.clone();
        let token_copy = cancellation_token.clone();
        loops.push(tokio::spawn(async move {
            loop {
                let store = store.clone();
                let config_box = config_box.clone();
                select! {
                    res = listener.accept() => {
                        match res {
                            Ok(_) => {
                                let (stream, _) = res.unwrap();
                                tokio::spawn(async move { handle_whois_request(stream, store, config_box).await });
                            }
                            Err(_) => {}
                        }
                    }
                    _ = token_copy.cancelled() => {
                        break
                    }
                }
            }
        }))
    }
    info!("WHOIS server started.");
    let _ = future::select_all(loops).await;
    info!("WHOIS server shut down.");
    Ok(())
}
