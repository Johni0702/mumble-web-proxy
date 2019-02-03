use futures::sync::mpsc;
use websocket;

// FIXME clean this up

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    ServerTls(native_tls::Error),
    ClientConnection(websocket::result::WebSocketError),
    Misc(Box<std::error::Error>),
}

impl From<websocket::result::WebSocketError> for Error {
    fn from(e: websocket::result::WebSocketError) -> Self {
        Error::ClientConnection(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<native_tls::Error> for Error {
    fn from(e: native_tls::Error) -> Self {
        Error::ServerTls(e)
    }
}

impl From<tokio::timer::Error> for Error {
    fn from(e: tokio::timer::Error) -> Self {
        Error::Misc(Box::new(e))
    }
}

impl From<rtp::Error> for Error {
    fn from(e: rtp::Error) -> Self {
        Error::Misc(Box::new(e))
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        panic!();
    }
}

impl<T> From<mpsc::SendError<T>> for Error {
    fn from(_: mpsc::SendError<T>) -> Self {
        panic!();
    }
}
