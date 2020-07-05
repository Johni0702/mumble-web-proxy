use futures::channel::mpsc;

// FIXME clean this up

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    ServerTls(native_tls::Error),
    ClientConnection(tungstenite::Error),
    Misc(Box<dyn std::error::Error + Send>),
}

impl Error {
    pub fn is_connection_closed(&self) -> bool {
        match self {
            Error::ClientConnection(tungstenite::Error::ConnectionClosed) => true,
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

impl From<tokio::time::Error> for Error {
    fn from(e: tokio::time::Error) -> Self {
        Error::Misc(Box::new(e))
    }
}

impl From<rtp::Error> for Error {
    fn from(e: rtp::Error) -> Self {
        Error::Misc(Box::new(e))
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Misc(Box::new(e))
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        panic!();
    }
}

impl From<mpsc::SendError> for Error {
    fn from(_: mpsc::SendError) -> Self {
        panic!();
    }
}
