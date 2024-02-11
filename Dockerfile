FROM rustlang/rust:nightly as builder

ARG TARGETARCH
WORKDIR /src

RUN apt-get update && apt-get install -y musl-tools ca-certificates
RUN if [ "x$TARGETARCH" = "xamd64" ] ; \
    then rustup target add x86_64-unknown-linux-musl ; \
    else rustup target add aarch64-unknown-linux-musl ; \
    fi
COPY src /src/src
COPY Cargo* /src/
RUN if [ "x$TARGETARCH" = "xamd64" ] ; \
    then export TARGET=x86_64-unknown-linux-musl ; \
    else export TARGET=aarch64-unknown-linux-musl ; \
    fi && CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo build --release --target $TARGET && cp /src/target/$TARGET/release/dns-whois-server /src/

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/dns-whois-server /app/dns-whois-server

ENV DNS_ADDR "127.0.0.1:1053"
ENV WHOIS_ADDR "0.0.0.0:43"
ENV RUST_LOG "info"

EXPOSE 1053
EXPOSE 43
EXPOSE 8080

CMD ["/app/dns-whois-server"]
