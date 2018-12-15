use futures::stream;
use futures::{Future, Sink, Stream};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use openssl::x509::X509;
use protobuf::Message;
use rtp::rfc3550::{
    RtcpCompoundPacket, RtcpPacket, RtcpPacketReader, RtcpPacketWriter, RtpFixedHeader, RtpPacket,
    RtpPacketReader, RtpPacketWriter,
};
use rtp::rfc5761::{MuxPacketReader, MuxPacketWriter, MuxedPacket};
use rtp::rfc5764::{DtlsSrtp, DtlsSrtpHandshakeResult};
use rtp::traits::{ReadPacket, WritePacket};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::io;
use tokio::prelude::*;
use tokio::timer::Delay;

use error::Error;
use ice::{IceAgent, IceStream};
use mumble;
use mumble::MumbleFrame;
use protos::Mumble;
use utils::{read_varint, write_varint32, EitherS};

type SessionId = u32;

struct User {
    session: u32,           // mumble session id
    ssrc: u32,              // ssrc id
    active: bool,           // whether the user is currently transmitting audio
    timeout: Option<Delay>, // assume end of transmission if silent until then
    start_voice_seq_num: u64,
    highest_voice_seq_num: u64,
    rtp_seq_num_offset: u32, // u32 because we also derive the timestamp from it
}

impl User {
    fn set_inactive(&mut self) -> impl Stream<Item = Frame, Error = Error> {
        self.timeout = None;

        if self.active {
            self.active = false;

            self.rtp_seq_num_offset = self
                .rtp_seq_num_offset
                .wrapping_add((self.highest_voice_seq_num - self.start_voice_seq_num) as u32 + 1);
            self.start_voice_seq_num = 0;
            self.highest_voice_seq_num = 0;

            let mut msg = Mumble::TalkingState::new();
            msg.set_session(self.session);
            EitherS::A(stream::once(Ok(Frame::Client(MumbleFrame {
                id: mumble::MSG_TALKING_STATE,
                bytes: msg.write_to_bytes().unwrap().into(),
            }))))
        } else {
            EitherS::B(stream::empty())
        }
    }

    fn set_active(&mut self, target: u8) -> impl Stream<Item = Frame, Error = Error> {
        let when = Instant::now() + Duration::from_millis(400);
        self.timeout = Some(Delay::new(when));

        if self.active {
            EitherS::A(stream::empty())
        } else {
            self.active = true;

            let mut msg = Mumble::TalkingState::new();
            msg.set_session(self.session);
            msg.set_target(target.into());
            EitherS::B(stream::once(Ok(Frame::Client(MumbleFrame {
                id: mumble::MSG_TALKING_STATE,
                bytes: msg.write_to_bytes().unwrap().into(),
            }))))
        }
    }
}

pub struct Connection {
    inbound_client: Box<Stream<Item = MumbleFrame, Error = Error>>,
    outbound_client: Box<Sink<SinkItem = MumbleFrame, SinkError = Error>>,
    inbound_server: Box<Stream<Item = MumbleFrame, Error = Error>>,
    outbound_server: Box<Sink<SinkItem = MumbleFrame, SinkError = Error>>,
    next_clientbound_frame: Option<MumbleFrame>,
    next_serverbound_frame: Option<MumbleFrame>,
    next_rtp_frame: Option<Vec<u8>>,
    stream_to_be_sent: Option<Box<Stream<Item = Frame, Error = Error>>>,

    ice_future: Option<Box<Future<Item = (IceAgent, IceStream), Error = Error>>>,
    ice: Option<IceAgent>,

    dtls_srtp_future: Option<DtlsSrtpHandshakeResult<IceStream, SslAcceptorBuilder>>,
    dtls_srtp: Option<DtlsSrtp<IceStream, SslAcceptorBuilder>>,
    dtls_key: PKey<Private>,
    dtls_cert: X509,

    rtp_reader: MuxPacketReader<RtpPacketReader, RtcpPacketReader>,
    rtp_writer: MuxPacketWriter<RtpPacketWriter, RtcpPacketWriter>,

    target: Option<u8>, // only if client is talking
    next_ssrc: u32,
    free_ssrcs: Vec<u32>,
    sessions: BTreeMap<SessionId, User>,
}

impl Connection {
    pub fn new<CSi, CSt, SSi, SSt>(
        client_sink: CSi,
        client_stream: CSt,
        server_sink: SSi,
        server_stream: SSt,
    ) -> Self
    where
        CSi: Sink<SinkItem = MumbleFrame, SinkError = Error> + 'static,
        CSt: Stream<Item = MumbleFrame, Error = Error> + 'static,
        SSi: Sink<SinkItem = MumbleFrame, SinkError = Error> + 'static,
        SSt: Stream<Item = MumbleFrame, Error = Error> + 'static,
    {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut cert_builder = X509::builder().unwrap();
        cert_builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert_builder.set_pubkey(&key).unwrap();
        cert_builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert_builder.build();

        Self {
            inbound_client: Box::new(client_stream),
            outbound_client: Box::new(client_sink),
            inbound_server: Box::new(server_stream),
            outbound_server: Box::new(server_sink),
            next_clientbound_frame: None,
            next_serverbound_frame: None,
            next_rtp_frame: None,
            stream_to_be_sent: None,
            ice_future: None,
            ice: None,
            dtls_srtp_future: None,
            dtls_srtp: None,
            dtls_key: key,
            dtls_cert: cert,
            rtp_reader: MuxPacketReader::new(RtpPacketReader, RtcpPacketReader),
            rtp_writer: MuxPacketWriter::new(RtpPacketWriter, RtcpPacketWriter),
            target: None,
            next_ssrc: 1,
            free_ssrcs: Vec::new(),
            sessions: BTreeMap::new(),
        }
    }

    fn allocate_ssrc(&mut self, session_id: SessionId) -> &mut User {
        let ssrc = self.free_ssrcs.pop().unwrap_or_else(|| {
            let ssrc = self.next_ssrc;
            self.next_ssrc += 1;
            if let Some(ref mut dtls_srtp) = self.dtls_srtp {
                dtls_srtp.add_incoming_unknown_ssrcs(1);
                dtls_srtp.add_outgoing_unknown_ssrcs(1);
            }
            ssrc
        });
        let user = User {
            session: session_id,
            ssrc,
            active: false,
            timeout: None,
            start_voice_seq_num: 0,
            highest_voice_seq_num: 0,
            rtp_seq_num_offset: 0,
        };
        self.sessions.insert(session_id, user);
        self.sessions.get_mut(&session_id).unwrap()
    }

    fn free_ssrc(&mut self, session_id: SessionId) {
        if let Some(user) = self.sessions.remove(&session_id) {
            self.free_ssrcs.push(user.ssrc)
        }
    }

    fn setup_ice(
        &mut self,
        agent: IceAgent,
        stream: IceStream,
    ) -> impl Stream<Item = Frame, Error = Error> {
        // Send WebRTC details to the client
        let mut msg = Mumble::WebRTC::new();
        msg.set_dtls_fingerprint(
            self.dtls_cert
                .digest(MessageDigest::sha256())
                .unwrap()
                .iter()
                .map(|byte| format!("{:02X}", byte))
                .collect::<Vec<_>>()
                .join(":"),
        );
        msg.set_ice_pwd(agent.pwd().to_owned());
        msg.set_ice_ufrag(agent.ufrag().to_owned());
        let webrtc_msg = Frame::Client(MumbleFrame {
            id: mumble::MSG_WEBRTC,
            bytes: msg.write_to_bytes().unwrap().into(),
        });

        // Parse ICE candidates and send them to the client
        let candidate_msgs = agent
            .sdp()
            .lines()
            .filter(|line| line.starts_with("a=candidate"))
            .map(|line| line[2..].to_owned())
            .map(move |candidate| {
                let mut msg = Mumble::IceCandidate::new();
                msg.set_content(candidate);
                Frame::Client(MumbleFrame {
                    id: mumble::MSG_ICE_CANDIDATE,
                    bytes: msg.write_to_bytes().unwrap().into(),
                })
            })
            .collect::<Vec<Frame>>();

        // Store ice agent for later use
        self.ice = Some(agent);

        // Prepare to accept the DTLS connection
        let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls()).unwrap();
        acceptor.set_certificate(&self.dtls_cert).unwrap();
        acceptor.set_private_key(&self.dtls_key).unwrap();
        // FIXME: verify remote fingerprint
        self.dtls_srtp_future = Some(DtlsSrtp::handshake(stream, acceptor));

        stream::iter_ok(Some(webrtc_msg).into_iter().chain(candidate_msgs))
    }

    fn handle_voice_packet(&mut self, buf: &[u8]) -> impl Stream<Item = Frame, Error = Error> {
        let (header, buf) = match buf.split_first() {
            Some(t) => t,
            None => return EitherS::B(stream::empty()),
        };
        if (header >> 5_u8) != 4_u8 {
            // only opus
            return EitherS::B(stream::empty());
        }
        let target = header & 0x1f;
        let (session_id, buf) = match read_varint(buf) {
            Some(t) => t,
            None => return EitherS::B(stream::empty()),
        };
        let (seq_num, buf) = match read_varint(buf) {
            Some(t) => t,
            None => return EitherS::B(stream::empty()),
        };
        let (opus_header, buf) = match read_varint(buf) {
            Some(t) => t,
            None => return EitherS::B(stream::empty()),
        };
        let length = (opus_header & 0x1fff) as usize;
        let last_bit = opus_header & 0x2000 != 0;
        if length > buf.len() {
            return EitherS::B(stream::empty());
        }
        let (opus_data, _) = buf.split_at(length);

        // NOTE: the mumble packet id increases by 1 per 10ms of audio contained
        // whereas rtp seq_num should increase by 1 per packet, regardless of audio,
        // but firefox seems to be just fine if we skip over rtp seq_nums.
        // NOTE: we rely on the srtp layer to prevent two-time-pads and by doing so,
        // allow for (reasonable) jitter of incoming voice packets.

        let user = match self.sessions.get_mut(&(session_id as u32)) {
            Some(s) => s,
            None => return EitherS::B(stream::empty()),
        };
        let rtp_ssrc = user.ssrc;

        let mut first_in_transmission = if user.active {
            false
        } else {
            user.start_voice_seq_num = seq_num;
            user.highest_voice_seq_num = seq_num;
            true
        };

        let offset = seq_num - user.start_voice_seq_num;
        let mut rtp_seq_num = user.rtp_seq_num_offset + offset as u32;

        let activity_stream = if last_bit {
            if seq_num <= user.highest_voice_seq_num {
                // Horribly delayed end packet from a previous stream, just drop it
                // (or single packet stream which would be inaudible anyway)
                return EitherS::B(stream::empty());
            }
            // this is the last packet of this voice transmission -> reset counters
            // doing that will effectively trash any delayed packets but that's just
            // a flaw in the mumble protocol and there's nothing we can do about it.
            EitherS::B(user.set_inactive())
        } else {
            EitherS::A(
                if seq_num == user.highest_voice_seq_num && seq_num != user.start_voice_seq_num {
                    // re-transmission, drop it
                    return EitherS::B(stream::empty());
                } else if seq_num >= user.highest_voice_seq_num
                    && seq_num < user.highest_voice_seq_num + 100
                {
                    // probably same voice transmission (also not too far in the future)
                    user.highest_voice_seq_num = seq_num;
                    EitherS::A(user.set_active(target))
                } else if seq_num < user.highest_voice_seq_num
                    && seq_num + 100 > user.highest_voice_seq_num
                {
                    // slightly delayed but probably same voice transmission
                    EitherS::A(user.set_active(target))
                } else {
                    // Either significant jitter (>2s) or we missed the end of the last
                    // transmission. Since >2s jitter will break opus horribly anyway,
                    // we assume the latter and start a new transmission
                    let stream = user.set_inactive();
                    first_in_transmission = true;
                    user.start_voice_seq_num = seq_num;
                    user.highest_voice_seq_num = seq_num;
                    rtp_seq_num = user.rtp_seq_num_offset;
                    EitherS::B(stream.chain(user.set_active(target)))
                },
            )
        };

        let rtp_time = 480 * rtp_seq_num;

        let rtp = RtpPacket {
            header: RtpFixedHeader {
                padding: false,
                marker: first_in_transmission,
                payload_type: 97,
                seq_num: rtp_seq_num as u16,
                timestamp: rtp_time as u32,
                ssrc: rtp_ssrc,
                csrc_list: Vec::new(),
                extension: None,
            },
            payload: opus_data.to_vec(),
            padding: Vec::new(),
        };
        let frame = Frame::Rtp(MuxedPacket::Rtp(rtp));
        EitherS::A(activity_stream.chain(stream::once(Ok(frame))))
    }

    fn process_packet_from_server(
        &mut self,
        mut frame: MumbleFrame,
    ) -> impl Stream<Item = Frame, Error = Error> {
        match frame.id {
            mumble::MSG_UDP_TUNNEL => EitherS::A(self.handle_voice_packet(&frame.bytes)),
            mumble::MSG_USER_STATE => {
                let mut message: Mumble::UserState =
                    protobuf::parse_from_bytes(&frame.bytes).unwrap();
                let session_id = message.get_session();
                if !self.sessions.contains_key(&session_id) {
                    let user = self.allocate_ssrc(session_id);
                    message.set_ssrc(user.ssrc);
                }
                frame.bytes = message.write_to_bytes().unwrap().as_slice().into();
                EitherS::B(stream::once(Ok(Frame::Client(frame))))
            }
            mumble::MSG_USER_REMOVE => {
                let mut message: Mumble::UserRemove =
                    protobuf::parse_from_bytes(&frame.bytes).unwrap();
                self.free_ssrc(message.get_session());
                EitherS::B(stream::once(Ok(Frame::Client(frame))))
            }
            _ => EitherS::B(stream::once(Ok(Frame::Client(frame)))),
        }
    }

    fn process_packet_from_client(
        &mut self,
        mut frame: MumbleFrame,
    ) -> impl Stream<Item = Frame, Error = Error> {
        match frame.id {
            mumble::MSG_AUTHENTICATE => {
                let mut message: Mumble::Authenticate =
                    protobuf::parse_from_bytes(&frame.bytes).unwrap();
                println!("MSG Authenticate: {:?}", message);
                if message.get_webrtc() {
                    // strip webrtc support from the connection (we will be providing it)
                    message.clear_webrtc();
                    // and make sure opus is marked as supported
                    message.set_opus(true);

                    self.ice_future = Some(Box::new(IceAgent::bind()));
                }

                frame.bytes = message.write_to_bytes().unwrap().as_slice().into();
                EitherS::A(EitherS::A(stream::once(Ok(Frame::Server(frame)))))
            }
            mumble::MSG_WEBRTC => {
                let mut message: Mumble::WebRTC = protobuf::parse_from_bytes(&frame.bytes).unwrap();
                println!("Got WebRTC: {:?}", message);
                if let Some(ref mut agent) = self.ice {
                    let f1 = agent.set_remote_pwd(message.take_ice_pwd());
                    let f2 = agent.set_remote_ufrag(message.take_ice_ufrag());
                    // FIXME trigger ICE-restart if required
                    // FIXME store and use remote dtls fingerprint
                    EitherS::B(EitherS::A(
                        f1.join(f2)
                            .map(|_| stream::empty())
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "failed to set ice creds")
                            })
                            .from_err()
                            .flatten_stream(),
                    ))
                } else {
                    EitherS::A(EitherS::B(stream::empty()))
                }
            }
            mumble::MSG_ICE_CANDIDATE => {
                let mut message: Mumble::IceCandidate =
                    protobuf::parse_from_bytes(&frame.bytes).unwrap();
                let candidate = message.take_content();
                println!("Got ice candidate: {:?}", candidate);
                if let Some(ref mut agent) = self.ice {
                    EitherS::B(EitherS::B(
                        agent
                            .add_remote_ice_candidate(candidate)
                            .map(|_| stream::empty())
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "failed to add ice candidate")
                            })
                            .from_err()
                            .flatten_stream(),
                    ))
                } else {
                    EitherS::A(EitherS::B(stream::empty()))
                }
            }
            mumble::MSG_TALKING_STATE => {
                let mut message: Mumble::TalkingState =
                    protobuf::parse_from_bytes(&frame.bytes).unwrap();
                self.target = if message.has_target() {
                    Some(message.get_target() as u8)
                } else {
                    None
                };
                EitherS::A(EitherS::B(stream::empty()))
            }
            _ => EitherS::A(EitherS::A(stream::once(Ok(Frame::Server(frame))))),
        }
    }

    fn process_rtp_packet(&mut self, buf: &[u8]) -> impl Stream<Item = Frame, Error = Error> {
        stream::iter_result(match self.rtp_reader.read_packet(&mut &buf[..]) {
            Ok(MuxedPacket::Rtp(rtp)) => {
                if let Some(target) = self.target {
                    // FIXME derive mumble seq_num from rtp timestamp to properly handle
                    // packet reordering and loss (done). But maybe keep it low?
                    let seq_num = rtp.header.timestamp / 480;

                    let header = 128_u8 | target;
                    let mut vec: Vec<u8> = Vec::new();
                    vec.push(header);
                    write_varint32(&mut vec, seq_num as u32).unwrap();
                    write_varint32(&mut vec, rtp.payload.len() as u32).unwrap();
                    vec.extend(rtp.payload);

                    Some(Ok(Frame::Server(MumbleFrame {
                        id: mumble::MSG_UDP_TUNNEL,
                        bytes: vec.into(),
                    })))
                } else {
                    None
                }
            }
            Ok(MuxedPacket::Rtcp(_rtcp)) => None,
            Err(_err) => None, // FIXME maybe not silently drop the error?
        })
    }
}

impl Future for Connection {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        'poll: loop {
            // If there's a frame pending to be sent, sent it before everything else
            if let Some(frame) = self.next_serverbound_frame.take() {
                match self.outbound_server.start_send(frame)? {
                    AsyncSink::NotReady(frame) => {
                        self.next_serverbound_frame = Some(frame);
                        return Ok(Async::NotReady);
                    }
                    AsyncSink::Ready => {}
                }
            }
            if let Some(frame) = self.next_clientbound_frame.take() {
                match self.outbound_client.start_send(frame)? {
                    AsyncSink::NotReady(frame) => {
                        self.next_clientbound_frame = Some(frame);
                        return Ok(Async::NotReady);
                    }
                    AsyncSink::Ready => {}
                }
            }
            if let Some(frame) = self.next_rtp_frame.take() {
                if let Some(ref mut dtls_srtp) = self.dtls_srtp {
                    match dtls_srtp.start_send(frame)? {
                        AsyncSink::NotReady(frame) => {
                            self.next_rtp_frame = Some(frame);
                            return Ok(Async::NotReady);
                        }
                        AsyncSink::Ready => {}
                    }
                } else {
                    // RTP not yet setup, just drop the frame
                }
            }

            // Send out all pending frames
            if self.stream_to_be_sent.is_some() {
                match self.stream_to_be_sent.as_mut().unwrap().poll()? {
                    Async::NotReady => return Ok(Async::NotReady),
                    Async::Ready(Some(frame)) => {
                        match frame {
                            Frame::Server(frame) => self.next_serverbound_frame = Some(frame),
                            Frame::Client(frame) => self.next_clientbound_frame = Some(frame),
                            Frame::Rtp(frame) => {
                                let mut buf = Vec::new();
                                self.rtp_writer.write_packet(&mut buf, &frame)?;
                                self.next_rtp_frame = Some(buf)
                            }
                        }
                        continue 'poll;
                    }
                    Async::Ready(None) => {
                        self.stream_to_be_sent = None;
                    }
                }
            }

            // All frames have been sent (or queued), flush any buffers in the output path
            self.outbound_client.poll_complete()?;
            self.outbound_server.poll_complete()?;
            if let Some(ref mut dtls_srtp) = self.dtls_srtp {
                dtls_srtp.poll_complete()?;
            }

            // Check/register voice timeouts
            // Note that this must be ran if any new sessions are added or timeouts are
            // modified as otherwise we may be blocking on IO and won't get notified of
            // timeouts. In particular, this means that it has to always be called if
            // we suspect that we may be blocking on inbound IO (outbound is less critical
            // since any action taken as a result of timeouts will have to wait for it
            // anyway), hence this being positioned above the code for incoming packets below.
            // (same applies to the other futures directly below it)
            for session in self.sessions.values_mut() {
                if let Async::Ready(Some(())) = session.timeout.poll()? {
                    let stream = session.set_inactive();
                    self.stream_to_be_sent = Some(Box::new(stream));
                    continue 'poll;
                }
            }

            // Poll ice future if required
            if self.ice_future.is_some() {
                if let Async::Ready((agent, stream)) = self.ice_future.as_mut().unwrap().poll()? {
                    self.ice_future = None;

                    println!("ICE ready.");

                    let stream = self.setup_ice(agent, stream);
                    self.stream_to_be_sent = Some(Box::new(stream));
                    continue 'poll;
                } else {
                    // wait for ice before processing futher packets to ensure
                    // that the WebRTC init message isn't sent too late
                    return Ok(Async::NotReady);
                }
            }

            // Poll dtls_srtp future if required
            if let Async::Ready(Some(mut dtls_srtp)) = self.dtls_srtp_future.poll()? {
                self.dtls_srtp_future = None;

                println!("DTLS-SRTP connection established.");

                dtls_srtp.add_incoming_unknown_ssrcs(self.next_ssrc as usize);
                dtls_srtp.add_outgoing_unknown_ssrcs(self.next_ssrc as usize);

                self.dtls_srtp = Some(dtls_srtp);
            }

            // Finally check for incoming packets
            match self.inbound_server.poll()? {
                Async::NotReady => {}
                Async::Ready(Some(frame)) => {
                    let stream = self.process_packet_from_server(frame);
                    self.stream_to_be_sent = Some(Box::new(stream));
                    continue 'poll;
                }
                Async::Ready(None) => return Ok(Async::Ready(())),
            }
            match self.inbound_client.poll()? {
                Async::NotReady => {}
                Async::Ready(Some(frame)) => {
                    let stream = self.process_packet_from_client(frame);
                    self.stream_to_be_sent = Some(Box::new(stream));
                    continue 'poll;
                }
                Async::Ready(None) => return Ok(Async::Ready(())),
            }
            if self.dtls_srtp.is_some() {
                match self.dtls_srtp.as_mut().unwrap().poll()? {
                    Async::NotReady => {}
                    Async::Ready(Some(frame)) => {
                        let stream = self.process_rtp_packet(&frame);
                        self.stream_to_be_sent = Some(Box::new(stream));
                        continue 'poll;
                    }
                    Async::Ready(None) => return Ok(Async::Ready(())),
                }
            }

            return Ok(Async::NotReady);
        }
    }
}

#[derive(Clone)]
enum Frame {
    Server(MumbleFrame),
    Client(MumbleFrame),
    Rtp(MuxedPacket<RtpPacket, RtcpCompoundPacket<RtcpPacket>>),
}
