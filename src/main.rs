use crate::datasource::git::GitDataSource;
use crate::datasource::DataSource;
use crate::service::dns::run_dns_server;
use crate::service::whois::run_whois_server;
use crate::store::memory::MemoryStore;
use crate::store::Store;
use clap::Parser;
use config::Config;
use log::info;
use std::io::Error;
use std::time::Duration;
use tokio::{select, signal};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use crate::service::healthcheck::run_health_check_server;

mod config;
mod datasource;
mod resource;
mod service;
mod store;
mod util;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let config: &'static Config = Box::leak(Box::new(Config::parse()));
    let mut source: Box<dyn DataSource> = Box::new(GitDataSource::new(config.clone()));
    source.update();
    let mut store: Box<dyn Store> = Box::new(MemoryStore::new());
    store.set(&source.get_resources());
    let mut services = vec![];
    let token = CancellationToken::new();
    let store_copy = store.clone();
    let token_copy = token.clone();
    services.push(tokio::spawn(async move {
        run_dns_server(config, store_copy, token_copy)
            .await
            .expect("Unable to start DNS server");
    }));
    let store_copy = store.clone();
    let token_copy = token.clone();
    services.push(tokio::spawn(async move {
        run_whois_server(config, store_copy, token_copy)
            .await
            .expect("Unable to start WHOIS server");
    }));
    let store_copy = store.clone();
    let token_copy = token.clone();
    services.push(tokio::spawn(async move {
        run_health_check_server(config, store_copy, token_copy)
            .await
            .expect("Unable to start health check server")
    }));
    let token_copy = token.clone();
    services.push(tokio::spawn(async move {
        loop {
            info!("Checking update...");
            if source.update() {
                info!("Updating...");
                store.set(&source.get_resources());
                info!("Updated.");
            } else {
                info!("No update available.");
            }
            select! {
                _ = sleep(Duration::from_secs(config.interval)) => {
                    continue
                }
                _ = token_copy.cancelled() => {
                    break
                }
            }
        }
    }));
    let futures = futures_util::future::join_all(services);
    signal::ctrl_c().await.expect("Failed to listen for shutdown signal");
    info!("Gracefully shutting down...");
    token.cancel();
    futures.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::inetnum::Inetnum;
    use crate::resource::Resource;
    use crate::store::Store;
    use crate::util::cidr::Ipv4CidrWrapper;
    use cidr::Ipv4Cidr;
    use std::str::FromStr;
    #[test]
    fn test_mem_store() {
        let mut store = MemoryStore::new();
        store.set(&Vec::from([
            Resource::Inetnum(Inetnum {
                cidr: Ipv4CidrWrapper(Ipv4Cidr::from_str("10.1.0.0/16").unwrap()),
                description: None,
                ns: Some(Vec::new()),
            }),
            Resource::Inetnum(Inetnum {
                cidr: Ipv4CidrWrapper(Ipv4Cidr::from_str("10.2.0.0/16").unwrap()),
                description: None,
                ns: Some(Vec::new()),
            }),
        ]));
        let x = store.get_inetnum_prefixes(Ipv4Cidr::from_str("10.1.2.3/32").unwrap());
        assert_eq!(x.0.len(), 1);
        assert_eq!(x.1.len(), 0);
        assert_eq!(
            x.0.get(0).unwrap().cidr,
            Ipv4CidrWrapper(Ipv4Cidr::from_str("10.1.0.0/16").unwrap())
        )
    }
}
