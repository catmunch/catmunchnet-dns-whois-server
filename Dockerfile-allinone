FROM rustlang/rust:nightly as builder

WORKDIR /src

COPY src /src/src
COPY Cargo* /src/
RUN CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libgit2-dev unbound supervisor && rm -rf /var/lib/apt/lists/* && mkdir -p /var/log/supervisor
COPY --from=builder /src/target/release/dns-whois-server /app/dns-whois-server
COPY docker/unbound.conf /etc/unbound/
COPY docker/supervisord.conf /etc/supervisor/

CMD ["/usr/bin/supervisord"]
