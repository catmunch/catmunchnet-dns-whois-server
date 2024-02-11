use std::error::Error;
use std::io;
use std::str::FromStr;
use actix_web::{App, HttpServer, Responder, web, get, http};
use log::info;
use serde::Serialize;
use simple_error::SimpleError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::net::TcpSocket;
use tokio_util::sync::CancellationToken;
use hickory_client::client::AsyncClient;
use hickory_client::op::Query;
use hickory_client::proto::DnsHandle;
use hickory_client::proto::xfer::{DnsRequestOptions, FirstAnswer};
use hickory_client::rr::{DNSClass, Name, RecordType};
use hickory_client::udp::UdpClientStream;
use crate::config::Config;
use crate::store::Store;

struct AppState {
    config: &'static Config,
    store: Box<dyn Store>,
}

#[derive(Serialize)]
struct HealthCheckResult {
    store_ready: bool,
    dns_ready: bool,
    whois_ready: bool
}

type Result<T> = std::result::Result<T, Box<dyn Error>>;

async fn dns_ready(config: &Config) -> Result<()> {
    if config.dns.len() == 0 {
        return Err(Box::from(SimpleError::new("no dns listening address found")))
    }
    let addr = config.dns[0];
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(([127,0,0,1], addr.port()).into());
    let (client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);
    let mut query = Query::query(Name::from_str("ns.catmunch.").unwrap(), RecordType::A);
    query.set_query_class(DNSClass::IN);
    let mut options = DnsRequestOptions::default();
    options.recursion_desired = false;
    let _ = client.lookup(query, options).first_answer().await?;
    Ok(())
}

async fn whois_ready(config: &Config) -> Result<()> {
    if config.whois.len() == 0 {
        return Err(Box::from(SimpleError::new("no whois listening address found")))
    }
    let addr = config.whois[0];
    let conn = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let mut stream = conn.connect(addr).await?;
    stream.write("whoami\n".as_bytes()).await?;
    let mut result = String::new();
    stream.read_to_string(&mut result).await?;
    if result != config.node_name {
        return Err(Box::from(SimpleError::new("invalid whois result")));
    }
    Ok(())
}

#[get("/healthz")]
async fn health_check(data: web::Data<AppState>) -> Result<impl Responder> {
    let result = HealthCheckResult {
        store_ready: data.store.is_ready(),
        dns_ready: dns_ready(data.config).await.is_ok(),
        whois_ready: whois_ready(data.config).await.is_ok(),
    };
    if result.store_ready && result.whois_ready && result.dns_ready {
        Ok((web::Json(result), http::StatusCode::OK))
    } else {
        Ok((web::Json(result), http::StatusCode::SERVICE_UNAVAILABLE))
    }
}

pub async fn run_health_check_server(config: &'static Config, store: Box<dyn Store>, cancellation_token: CancellationToken) -> io::Result<()> {
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                config,
                store: store.clone()
            }))
            .service(health_check)
    })
        .bind(("0.0.0.0", config.health_check_port))?
        .run();
    info!("Health check server started.");
    let server_handle = server.handle();
    select! {
        _ = cancellation_token.cancelled() => {
            server_handle.stop(true).await;
        }
        res = server => {
            match res {
                Err(e) => {
                    panic!("Health check server stopped with error: {}", e)
                }
                Ok(_) => {}
            }
        }
    }
    info!("Health check server shut down.");
    Ok(())
}