use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;
use tokio::io;
use tokio_codec::{Decoder, Encoder};

#[derive(Clone, Debug)]
pub struct MumbleFrame {
    pub id: u16,
    pub bytes: Bytes,
}

pub struct MumbleCodec;

impl MumbleCodec {
    pub fn new() -> Self {
        Self {}
    }
}

impl Decoder for MumbleCodec {
    type Item = MumbleFrame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<MumbleFrame>, io::Error> {
        let buf_len = buf.len();
        if buf_len >= 6 {
            let mut buf = Cursor::new(buf);
            let id = buf.get_u16_be();
            let len = buf.get_u32_be() as usize;
            if buf_len >= 6 + len {
                let mut bytes = buf.into_inner().split_to(6 + len);
                bytes.advance(6);
                let bytes = bytes.freeze();
                Ok(Some(MumbleFrame { id, bytes }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder for MumbleCodec {
    type Item = MumbleFrame;
    type Error = io::Error;

    fn encode(&mut self, item: MumbleFrame, dst: &mut BytesMut) -> Result<(), io::Error> {
        let id = item.id;
        let bytes = &item.bytes;
        let len = bytes.len();
        dst.reserve(6 + len);
        dst.put_u16_be(id);
        dst.put_u32_be(len as u32);
        dst.put(bytes);
        Ok(())
    }
}

macro_rules! define_packet_mappings {
    ( $id:expr, $head:ident ) => {
        #[allow(dead_code)]
        pub const $head: u16 = $id;
    };
    ( $id:expr, $head:ident, $( $tail:ident ),* ) => {
        #[allow(dead_code)]
        pub const $head: u16 = $id;
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
