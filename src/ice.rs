// FIXME replace with proper libnice bindings or pure-rust ICE/STUN lib
use error::Error;
use future::Either;
use futures::sync::{mpsc, oneshot};
use futures::{Future, Sink, Stream};
use nice::api_agent::Agent;
use nice::api_gobject::GMainLoop;
use nice::bindings_agent as ice_ffi;
use std::clone::Clone;
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::io;
use tokio::prelude::*;

pub struct IceAgent {
    ufrag: String,
    pwd: String,
    sdp: String,
    remote_sdp_sender: mpsc::Sender<String>,
    remote_ice_candidates: Vec<String>,
    remote_ufrag: Option<String>,
    remote_pwd: Option<String>,
}

pub struct IceStream {
    receiver: mpsc::Receiver<Vec<u8>>,
    sender: mpsc::Sender<Vec<u8>>,
}

impl IceAgent {
    pub fn bind() -> impl Future<Item = (Self, IceStream), Error = Error> {
        let (tokio_sender, thread_receiver) = mpsc::channel(10);
        let (thread_sender, tokio_receiver) = mpsc::channel(10);
        let (cred_sender, cred_receiver) = oneshot::channel();
        let (remote_sdp_sender, remote_sdp_receiver) = mpsc::channel(10);

        thread::spawn(move || {
            let thread_sender = Mutex::new(thread_sender);
            let mut recv_callback = Box::new(move |buf: &[u8]| {
                let result = thread_sender.lock().unwrap().try_send(buf.to_vec());
                if let Err(err) = result {
                    eprintln!("Failed to queue packet: {:?} {:?}", buf, err);
                }
            });

            let main_loop = GMainLoop::new();
            let context = main_loop.get_context();
            thread::spawn(move || {
                // FIXME stop at some point
                main_loop.run();
            });

            let agent = Arc::new(Agent::new(&context, ice_ffi::NICE_COMPATIBILITY_RFC5245));
            agent.set_software("mumble-web-proxy");

            let stream_id = agent.add_stream(1).unwrap();
            let (ufrag, pwd) = agent.get_local_credentials(stream_id).unwrap();

            agent.set_stream_name(stream_id, "audio");
            agent.gather_candidates(stream_id);
            agent.attach_recv(stream_id, 1, &context, &mut recv_callback);

            // ok, here's the thing: libnice.rs is a giant train wreck.
            // It doesn't require any of the closures which it takes to be Send
            // even though, considering they're called from the GMainLoop,
            // they really should be. That's going to explode sooner or later.
            // I have no clue how many other things are broken but one of them
            // is on_candidate_gathering_done which just segfaults.
            // Since I can neither be bothered to debug that mess nor to write
            // new bindings or a pure-rust ice lib (yet), we'll work around the
            // issue by periodically polling. FIXME
            // It turns out attach_recv is also broken, so I had to go in and fix
            // that but now I've already written this workaround so it's here to
            // stay (at least until there's a better libnice binding).
            // This will probably only give non-turn candidates which should
            // be enough for our use-case.
            loop {
                let maybe_sdp = agent.generate_local_stream_sdp(stream_id, false);
                if let Some(sdp) = maybe_sdp {
                    cred_sender.send((sdp, ufrag, pwd)).unwrap(); // FIXME handle shutdown
                    break;
                }
                ::std::thread::sleep(::std::time::Duration::from_millis(100));
            }

            let remote_sdp_handler = remote_sdp_receiver.for_each(|remote_sdp: String| {
                // FIXME do we need to handle invalid sdp?
                agent.parse_remote_sdp(&remote_sdp).unwrap();
                Ok(())
            });
            let packet_send_handler = thread_receiver.for_each(|packet: Vec<u8>| {
                agent.send(stream_id, 1, &packet[..]);
                Ok(())
            });
            remote_sdp_handler.join(packet_send_handler).wait().unwrap();
        });

        cred_receiver
            .map(|(sdp, ufrag, pwd): (String, String, String)| {
                (
                    Self {
                        ufrag,
                        pwd,
                        sdp,
                        remote_sdp_sender,
                        remote_ice_candidates: Vec::new(),
                        remote_ufrag: None,
                        remote_pwd: None,
                    },
                    IceStream {
                        receiver: tokio_receiver,
                        sender: tokio_sender,
                    },
                )
            })
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .from_err()
    }

    pub fn pwd(&self) -> &str {
        &self.pwd
    }

    pub fn ufrag(&self) -> &str {
        &self.ufrag
    }

    pub fn sdp(&self) -> &str {
        &self.sdp
    }

    pub fn set_remote_pwd(&mut self, pwd: String) -> impl Future<Item = (), Error = ()> {
        self.remote_pwd = Some(pwd);
        self.update_remote_sdp()
    }

    pub fn set_remote_ufrag(&mut self, ufrag: String) -> impl Future<Item = (), Error = ()> {
        self.remote_ufrag = Some(ufrag);
        self.update_remote_sdp()
    }

    pub fn add_remote_ice_candidate(
        &mut self,
        candidate: String,
    ) -> impl Future<Item = (), Error = ()> {
        self.remote_ice_candidates.push(candidate);
        self.update_remote_sdp()
    }

    pub fn update_remote_sdp(&self) -> impl Future<Item = (), Error = ()> {
        if let (Some(pwd), Some(ufrag)) = (&self.remote_pwd, &self.remote_ufrag) {
            let mut sdp = Vec::new();
            sdp.push("a=ice-options:trickle".to_owned());
            sdp.push("m=audio".to_owned());
            for candidate in &self.remote_ice_candidates {
                sdp.push("a=".to_owned() + candidate);
            }
            sdp.push("a=ice-pwd:".to_owned() + pwd);
            sdp.push("a=ice-ufrag:".to_owned() + ufrag);
            let f = self.remote_sdp_sender.clone().send(sdp.join("\n"));
            Either::A(f.map(|_| ()).map_err(|_| ()))
        } else {
            Either::B(future::ok(()))
        }
    }
}

impl Read for IceStream {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        match self.receiver.poll() {
            Ok(Async::Ready(Some(buf))) => (&buf[..]).read(dst),
            Ok(Async::Ready(None)) => Ok(0),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
            Err(err) => panic!(err), // FIXME should we really panic here? when can this happen?
        }
    }
}
impl AsyncRead for IceStream {}

impl Write for IceStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sender.start_send(buf.to_vec()) {
            Ok(AsyncSink::Ready) => Ok(buf.len()),
            Ok(AsyncSink::NotReady(_)) => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.sender.poll_complete() {
            Ok(Async::Ready(())) => Ok(()),
            Ok(Async::NotReady) => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}
impl AsyncWrite for IceStream {
    fn shutdown(&mut self) -> io::Result<Async<()>> {
        Ok(Async::Ready(())) // FIXME actually shutdown ice
    }
}

