FROM rust:1.48-alpine AS build

ARG REV=master

RUN apk add --no-cache \
    clang-libs \
    curl \
    libc-dev \
    libnice-dev \
    openssl-dev \
    ;
WORKDIR /src
RUN curl https://codeload.github.com/Johni0702/mumble-web-proxy/tar.gz/$REV \
    | tar -xzf - --strip-components 1
RUN echo -e '\n[dependencies."async-trait"]\ndefault-features = false' >> Cargo.toml
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo install --path .

FROM alpine

RUN apk add --no-cache \
    bash \
    libgcc \
    libnice \
    ;
COPY --from=build /usr/local/cargo/bin/mumble-web-proxy /mumble-web-proxy
COPY entrypoint.sh /entrypoint.sh

ENV MWP_LISTEN_WS=64737
ENV MWP_SERVER=mumble-server:64738
ENV MWP_ACCEPT_INVALID_CERTIFICATE=
ENV MWP_ICE_PORT_MIN=
ENV MWP_ICE_PORT_MAX=
ENV MWP_ICE_IPV4=
ENV MWP_ICE_IPV6=

CMD ["/entrypoint.sh"]
USER 1000
EXPOSE 64737
