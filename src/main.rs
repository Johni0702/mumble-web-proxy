// FIXME don't just unwrap protobuf results
// FIXME for some reason, reconnecting without reloading the page fails DTLS handshake (FF)
extern crate argparse;
extern crate byteorder;
extern crate bytes;
extern crate futures;
extern crate native_tls;
extern crate nice;
extern crate openssl;
extern crate protobuf;
extern crate rtp;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_core;
extern crate tokio_tls;
extern crate websocket;

use argparse::{ArgumentParser, Store};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::{Future, Sink, Stream};
use std::convert::Into;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio_codec::Decoder;
use tokio_core::reactor::Core;
use tokio_tls::TlsConnector;
use websocket::async::Server;
use websocket::message::OwnedMessage;
use websocket::server::InvalidConnection;

mod connection;
mod error;
mod ice;
mod mumble;
mod utils;
mod protos {
    pub mod Mumble;
}
use connection::Connection;
use error::Error;
use mumble::{MumbleCodec, MumbleFrame};

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
    let server = Server::bind(("0.0.0.0", ws_port), &handle).unwrap();
    let f = server
        .incoming()
        .map_err(|InvalidConnection { error, .. }| error)
        .for_each(move |(upgrade, addr)| {
            println!("New connection from {}", addr);
            let server_sock = TcpStream::connect(&upstream_addr);
            let f = upgrade
                .use_protocol("binary") // FIXME can we be more specific? *looks at chrome*
                .accept()
                .from_err()
                .join(server_sock.from_err().and_then(move |stream| {
                    let connector: TlsConnector = native_tls::TlsConnector::builder()
                        //.danger_accept_invalid_certs(true)
                        .build()
                        .unwrap()
                        .into();
                    connector.connect(upstream_host, stream).from_err()
                }))
                .and_then(move |((client, _), server)| {
                    let (client_sink, client_stream) = client.split();
                    // buffered client sink to prevent temporary lag on the control
                    // channel from lagging the otherwise independent audio channel
                    let client_sink = client_sink.buffer(10).with(|m: MumbleFrame| {
                        let bytes = &m.bytes;
                        let len = bytes.len();
                        let mut buf = BytesMut::with_capacity(6 + len);
                        buf.put_u16_be(m.id);
                        buf.put_u32_be(len as u32);
                        buf.put(bytes);
                        Ok::<OwnedMessage, Error>(OwnedMessage::Binary(buf.freeze().to_vec()))
                    });
                    let client_stream = client_stream
                        .from_err()
                        .take_while(|m| Ok(!m.is_close()))
                        .filter_map(|m| {
                            match m {
                                OwnedMessage::Binary(ref b) if b.len() >= 6 => {
                                    let id = BigEndian::read_u16(b);
                                    // b[2..6] is length which is implicit in websocket msgs
                                    let bytes = b[6..].into();
                                    Some(MumbleFrame { id, bytes })
                                }
                                _ => None,
                            }
                        });

                    let server = MumbleCodec::new().framed(server);
                    let (server_sink, server_stream) = server.split();
                    let server_sink = server_sink.sink_from_err();
                    let server_stream = server_stream.from_err();

                    Connection::new(client_sink, client_stream, server_sink, server_stream)
                })
                .map_err(move |e: Error| println!("Error on connection {}: {:?}", addr, e))
                .map(move |_| println!("Client connection closed: {}", addr));
            handle.spawn(f);
            Ok(())
        });
    core.run(f).unwrap();
}

macro_rules! define_packet_mappings {
    ( $id:expr, $head:ident ) => {
        #[allow(dead_code)]
        const $head: u16 = $id;
    };
    ( $id:expr, $head:ident, $( $tail:ident ),* ) => {
        #[allow(dead_code)]
        const $head: u16 = $id;
        define_packet_mappings!($id + 1, $($tail),*);
    };
}

define_packet_mappings![
    0,
    MSG_VERSION,
    MSG_UDP_TUNNEL,
    MSG_AUTHENTICATE,
    MSG_PING,
    MSG_REJECT,
    MSG_SERVER_SYNC,
    MSG_CHANNEL_REMOVE,
    MSG_CHANNEL_STATE,
    MSG_USER_REMOVE,
    MSG_USER_STATE,
    MSG_BAN_LIST,
    MSG_TEXT_MESSAGE,
    MSG_PERMISSION_DENIED,
    MSG_ACL,
    MSG_QUERY_USERS,
    MSG_CRYPT_SETUP,
    MSG_CONTEXT_ACTION_MODIFY,
    MSG_CONTEXT_ACTION,
    MSG_USER_LIST,
    MSG_VOICE_TARGET,
    MSG_PERMISSION_QUERY,
    MSG_CODEC_VERSION,
    MSG_USER_STATS,
    MSG_REQUEST_BLOB,
    MSG_SERVER_CONFIG,
    MSG_SUGGEST_CONFIG,
    MSG_WEBRTC,
    MSG_ICE_CANDIDATE,
    MSG_TALKING_STATE
];
