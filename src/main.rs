#![feature(try_from)]
// TODO For some reason, reconnecting without reloading the page and without disconnecting the
//      previous connection (i.e. multiple simultaneous connections) causes FF to reject our DTLS
//      cert. Works in Chrome, or in different tabs or when properly closing the old connection.
extern crate argparse;
extern crate byteorder;
extern crate bytes;
extern crate futures;
extern crate libnice;
extern crate mumble_protocol;
extern crate native_tls;
extern crate openssl;
extern crate rtp;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_core;
extern crate tokio_tls;
extern crate tokio_tungstenite;
extern crate tungstenite;
extern crate webrtc_sdp;

use argparse::StoreOption;
use argparse::StoreTrue;
use argparse::{ArgumentParser, Store};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BufMut, BytesMut, IntoBuf};
use futures::{Future, Sink, Stream};
use mumble_protocol::control::ClientControlCodec;
use mumble_protocol::control::ControlPacket;
use mumble_protocol::control::RawControlPacket;
use mumble_protocol::Clientbound;
use std::convert::Into;
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::ToSocketAddrs;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_codec::Decoder;
use tokio_core::reactor::Core;
use tokio_tls::TlsConnector;
use tokio_tungstenite::accept_hdr_async_with_config;
use tungstenite::handshake::server::Request;
use tungstenite::protocol::Message;
use tungstenite::protocol::WebSocketConfig;

mod connection;
mod error;
mod utils;
use connection::Connection;
use error::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub min_port: u16,
    pub max_port: u16,
    pub public_v4: Option<Ipv4Addr>,
    pub public_v6: Option<Ipv6Addr>,
}

fn main() {
    let mut ws_port = 0_u16;
    let mut upstream = "".to_string();
    let mut accept_invalid_certs = false;
    let mut config = Config {
        min_port: 1,
        max_port: u16::max_value(),
        public_v4: None,
        public_v6: None,
    };

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Run the Mumble-WebRTC proxy");
        ap.refer(&mut ws_port)
            .add_option(
                &["--listen-ws"],
                Store,
                "Port to listen for WebSocket (non TLS) connections on",
            )
            .required();
        ap.refer(&mut upstream)
            .add_option(
                &["--server"],
                Store,
                "Hostname and (optionally) port of the upstream Mumble server",
            )
            .required();
        ap.refer(&mut accept_invalid_certs).add_option(
            &["--accept-invalid-certificate"],
            StoreTrue,
            "Connect to upstream server even when its certificate is invalid.
                 Only ever use this if know that your server is using a self-signed certificate!",
        );
        ap.refer(&mut config.min_port).add_option(
            &["--ice-port-min"],
            Store,
            "Minimum port number to use for ICE host candidates.",
        );
        ap.refer(&mut config.max_port).add_option(
            &["--ice-port-max"],
            Store,
            "Maximum port number to use for ICE host candidates.",
        );
        ap.refer(&mut config.public_v4).add_option(
            &["--ice-ipv4"],
            StoreOption,
            "Set a public IPv4 address to be used for ICE host candidates.",
        );
        ap.refer(&mut config.public_v6).add_option(
            &["--ice-ipv6"],
            StoreOption,
            "Set a public IPv6 address to be used for ICE host candidates.",
        );
        ap.parse_args_or_exit();
    }

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
    let upstream_addr = (upstream_host, upstream_port)
        .to_socket_addrs()
        .expect("Failed to parse upstream address")
        .next()
        .expect("Failed to resolve upstream address");

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let socket_addr = (Ipv6Addr::from(0), ws_port).into();
    let server = TcpListener::bind(&socket_addr).unwrap();
    let f = server.incoming().for_each(move |client| {
        let addr = client.peer_addr().expect("peer to have an address");
        println!("New connection from {}", addr);

        // Connect to server
        let server = TcpStream::connect(&upstream_addr)
            .from_err()
            .and_then(move |stream| {
                let connector: TlsConnector = native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(accept_invalid_certs)
                    .build()
                    .unwrap()
                    .into();
                connector.connect(upstream_host, stream).from_err()
            })
            .map(|stream| ClientControlCodec::new().framed(stream));

        // Accept client
        let websocket_config = WebSocketConfig {
            max_send_queue: Some(10), // can be fairly small as voice is using WebRTC instead
            max_message_size: Some(0x7f_ffff), // maximum size accepted by Murmur
            max_frame_size: Some(0x7f_ffff), // maximum size accepted by Murmur
        };
        fn header_callback(
            _req: &Request,
        ) -> tungstenite::error::Result<Option<Vec<(String, String)>>> {
            Ok(Some(vec![(
                "Sec-WebSocket-Protocol".to_string(),
                "binary".to_string(),
            )]))
        }
        let client = accept_hdr_async_with_config(client, header_callback, Some(websocket_config))
            .from_err();

        // Once both are done, begin proxy duty
        let config = config.clone();
        let f = client
            .join(server)
            .and_then(move |(client, server)| {
                let (client_sink, client_stream) = client.split();
                let client_sink = client_sink.with(|m: ControlPacket<Clientbound>| {
                    let m = RawControlPacket::from(m);
                    let mut header = BytesMut::with_capacity(6);
                    header.put_u16_be(m.id);
                    header.put_u32_be(m.bytes.len() as u32);
                    let buf = header.into_buf().chain(m.bytes);
                    Ok::<_, Error>(Message::Binary(buf.collect()))
                });
                let client_stream = client_stream.from_err().filter_map(|m| match m {
                    Message::Binary(ref b) if b.len() >= 6 => {
                        let id = BigEndian::read_u16(b);
                        // b[2..6] is length which is implicit in websocket msgs
                        let bytes = b[6..].into();
                        RawControlPacket { id, bytes }.try_into().ok()
                    }
                    _ => None,
                });

                let (server_sink, server_stream) = server.split();
                let server_sink = server_sink.sink_from_err();
                let server_stream = server_stream.from_err();

                Connection::new(
                    config,
                    client_sink,
                    client_stream,
                    server_sink,
                    server_stream,
                )
            })
            .or_else(move |err| {
                if err.is_connection_closed() {
                    Ok(())
                } else {
                    println!("Error on connection {}: {:?}", addr, err);
                    Err(())
                }
            })
            .map(move |()| println!("Client connection closed: {}", addr));
        handle.spawn(f);
        Ok(())
    });
    core.run(f).unwrap();
}
