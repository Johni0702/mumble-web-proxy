use futures::sync::mpsc;

// FIXME clean this up

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    ServerTls(native_tls::Error),
    ClientConnection(tungstenite::Error),
    Misc(Box<std::error::Error>),
}

impl Error {
    pub fn is_connection_closed(&self) -> bool {
        match self {
            Error::ClientConnection(tungstenite::Error::ConnectionClosed(_)) => true,
            _ => false,
        }
    }
}

impl From<tungstenite::Error> for Error {
    fn from(e: tungstenite::Error) -> Self {
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
