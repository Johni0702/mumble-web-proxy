#![feature(try_from)]
// FIXME don't just unwrap protobuf results
// FIXME for some reason, reconnecting without reloading the page fails DTLS handshake (FF)
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

fn main() {
    let mut ws_port = 0_u16;
    let mut upstream = "".to_string();

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
                "Hostname and port of upstream mumble server",
            )
            .required();
        ap.parse_args_or_exit();
    }

    let mut upstream_parts = upstream.rsplitn(2, ':');
    let upstream_port: u16 = upstream_parts
        .next()
        .expect("Missing upstream port")
        .parse()
        .expect("Failed to parse upstream port");
    let upstream_host = upstream_parts.next().expect("Missing upstream host name");
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
                    //.danger_accept_invalid_certs(true)
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

                Connection::new(client_sink, client_stream, server_sink, server_stream)
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
