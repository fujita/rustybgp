FROM rust as builder

ENV HOME /root
WORKDIR /root

RUN curl -OL https://github.com/osrg/gobgp/releases/download/v2.11.0/gobgp_2.11.0_linux_amd64.tar.gz
RUN tar xzf gobgp_2.11.0_linux_amd64.tar.gz

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    curl \
    musl-dev \
    musl-tools

RUN rustup target add x86_64-unknown-linux-musl
RUN rustup component add rustfmt
RUN cargo build --release --target x86_64-unknown-linux-musl


FROM alpine
WORKDIR /root
EXPOSE 50051

RUN apk add --no-cache --update supervisor
ADD tests/integration/functional/supervisord.conf /etc/

COPY --from=builder /root/rustybgp/target/x86_64-unknown-linux-musl/release/daemon /usr/bin/rustybgpd
COPY --from=builder /root/gobgpd /usr/bin
COPY --from=builder /root/gobgp /usr/bin

ENTRYPOINT ["/usr/bin/supervisord"]
