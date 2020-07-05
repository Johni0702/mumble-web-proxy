// TODO For some reason, reconnecting without reloading the page and without disconnecting the
//      previous connection (i.e. multiple simultaneous connections) causes FF to reject our DTLS
//      cert. Works in Chrome, or in different tabs or when properly closing the old connection.
use argparse::StoreOption;
use argparse::StoreTrue;
use argparse::{ArgumentParser, Store};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{future, SinkExt, StreamExt, TryFutureExt, TryStreamExt};
use http::HeaderValue;
use mumble_protocol::control::ClientControlCodec;
use mumble_protocol::control::ControlPacket;
use mumble_protocol::control::RawControlPacket;
use mumble_protocol::Clientbound;
use serde::Deserialize;
use std::convert::Into;
use std::convert::TryInto;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::ToSocketAddrs;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_tls::TlsConnector;
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_util::codec::Decoder;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::protocol::Message;
use tungstenite::protocol::WebSocketConfig;

mod connection;
mod error;
use connection::Connection;
use error::Error;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Config {
    pub file: Option<String>,
    #[serde(rename = "listen-ws")]
    pub ws_port: u16,
    #[serde(rename = "server")]
    pub upstream: String,
    #[serde(rename = "accept-invalid-certificate")]
    pub accept_invalid_certs: bool,
    pub ice_min_port: u16,
    pub ice_max_port: u16,
    pub ice_public_v4: Option<Ipv4Addr>,
    pub ice_public_v6: Option<Ipv6Addr>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            file: None,
            ws_port: 0_u16,
            upstream: "".to_string(),
            accept_invalid_certs: false,
            ice_min_port: 1,
            ice_max_port: u16::max_value(),
            ice_public_v4: None,
            ice_public_v6: None,
        }
    }
}

fn create_argparser(config: &mut Config) -> ArgumentParser {
    let mut ap = ArgumentParser::new();
    ap.set_description("Run the Mumble-WebRTC proxy");
    ap.refer(&mut config.file).add_option(
        &["--config"],
        StoreOption,
        "Toml file to read options from",
    );
    ap.refer(&mut config.ws_port).add_option(
        &["--listen-ws"],
        Store,
        "Port to listen for WebSocket (non TLS) connections on",
    );
    ap.refer(&mut config.upstream).add_option(
        &["--server"],
        Store,
        "Hostname and (optionally) port of the upstream Mumble server",
    );
    ap.refer(&mut config.accept_invalid_certs).add_option(
        &["--accept-invalid-certificate"],
        StoreTrue,
        "Connect to upstream server even when its certificate is invalid.
                 Only ever use this if know that your server is using a self-signed certificate!",
    );
    ap.refer(&mut config.ice_min_port).add_option(
        &["--ice-port-min"],
        Store,
        "Minimum port number to use for ICE host candidates.",
    );
    ap.refer(&mut config.ice_max_port).add_option(
        &["--ice-port-max"],
        Store,
        "Maximum port number to use for ICE host candidates.",
    );
    ap.refer(&mut config.ice_public_v4).add_option(
        &["--ice-ipv4"],
        StoreOption,
        "Set a public IPv4 address to be used for ICE host candidates.",
    );
    ap.refer(&mut config.ice_public_v6).add_option(
        &["--ice-ipv6"],
        StoreOption,
        "Set a public IPv6 address to be used for ICE host candidates.",
    );
    ap
}

fn error_missing_arg(arg: &str) {
    let args: Vec<String> = std::env::args().collect();
    let name = if args.len() > 0 {
        &args[0][..]
    } else {
        "unknown"
    };
    let mut config = Config::default();
    let ap = create_argparser(&mut config);
    ap.error(
        name,
        &format!("Option [\"--{}\"] is required", arg),
        &mut std::io::stderr(),
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut config = Config::default();

    // First pass to get the config file path
    create_argparser(&mut config).parse_args_or_exit();
    if let Some(file) = config.file {
        // Then read in the config defaults
        config = toml::from_str(&std::fs::read_to_string(file)?)?;
        // Second pass to allow for overwrites
        create_argparser(&mut config).parse_args_or_exit();
    }

    if config.ws_port == 0 {
        error_missing_arg("listen-ws");
    }
    if config.upstream == "" {
        error_missing_arg("server");
    }

    let Config {
        ws_port,
        upstream,
        accept_invalid_certs,
        ..
    } = config.clone();

    // Try parsing as raw IPv6 address first
    let (upstream_host, upstream_port) = match upstream.parse::<Ipv6Addr>() {
        Ok(_) => (upstream.as_ref(), 64738),
        Err(_) => {
            // Otherwise split off port from end
            let mut upstream_parts = upstream.rsplitn(2, ':');
            let right = upstream_parts.next().expect("Empty upstream address");
            match upstream_parts.next() {
                Some(host) => (host, right.parse().expect("Failed to parse upstream port")),
                None => (right, 64738),
            }
        }
    };
    let upstream_host = Box::leak(Box::new(upstream_host.to_owned())).as_str();
    println!("Resolving upstream address {:?}", (upstream_host, upstream_port));
    let upstream_addr = (upstream_host, upstream_port)
        .to_socket_addrs()
        .expect("Failed to parse upstream address")
        .next()
        .expect("Failed to resolve upstream address");
    println!("Resolved upstream address: {}", upstream_addr);

    println!("Binding to port {}", ws_port);
    let socket_addr = (Ipv6Addr::from(0), ws_port);
    let mut server = TcpListener::bind(&socket_addr).await?;

    println!("Waiting for client connections..");
    loop {
        let (client, _) = server.accept().await?;
        let addr = match client.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                if err.kind() != ErrorKind::NotConnected {
                    println!("Error getting address of new connection: {:?}", err);
                }
                continue;
            }
        };
        println!("New connection from {}", addr);

        // Connect to server
        let server = async move {
            let stream = TcpStream::connect(&upstream_addr).await?;
            let connector: TlsConnector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(accept_invalid_certs)
                .build()
                .unwrap()
                .into();
            let stream = connector.connect(upstream_host, stream).await?;
            Ok::<_, Error>(ClientControlCodec::new().framed(stream))
        };

        // Accept client
        let websocket_config = WebSocketConfig {
            max_send_queue: Some(10), // can be fairly small as voice is using WebRTC instead
            max_message_size: Some(0x7f_ffff), // maximum size accepted by Murmur
            max_frame_size: Some(0x7f_ffff), // maximum size accepted by Murmur
        };
        fn header_callback(
            _req: &Request,
            mut response: Response,
        ) -> Result<Response, ErrorResponse> {
            response
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
            Ok(response)
        }
        let client = accept_hdr_async_with_config(client, header_callback, Some(websocket_config))
            .err_into();

        // Once both are done, begin proxy duty
        let config = config.clone();
        tokio::spawn(async move {
            let (client, server) = future::try_join(client, server).await?;
            let (client_sink, client_stream) = client.split();
            let client_sink = client_sink.with(|m: ControlPacket<Clientbound>| {
                let m = RawControlPacket::from(m);
                let mut header = BytesMut::with_capacity(6);
                header.put_u16(m.id);
                header.put_u32(m.bytes.len() as u32);
                let mut buf = Vec::new();
                buf.extend(header);
                buf.extend(m.bytes);
                future::ready(Ok::<_, Error>(Message::Binary(buf)))
            });
            let client_stream = client_stream.err_into().try_filter_map(|m| {
                future::ok(match m {
                    Message::Binary(b) if b.len() >= 6 => {
                        let id = BigEndian::read_u16(&b);
                        // b[2..6] is length which is implicit in websocket msgs
                        let bytes = Bytes::from(b).slice(6..);
                        RawControlPacket { id, bytes }.try_into().ok()
                    }
                    _ => None,
                })
            });

            let (server_sink, server_stream) = server.split();
            let server_sink = server_sink.sink_err_into();
            let server_stream = server_stream.err_into();

            Connection::new(
                config,
                client_sink,
                client_stream,
                server_sink,
                server_stream,
            ).await?;

            println!("Client connection closed: {}", addr);

            Ok::<_, Error>(())
        }.unwrap_or_else(move |err| {
            if !err.is_connection_closed() {
                println!("Error on connection {}: {:?}", addr, err);
            }
        }));
    }
}
