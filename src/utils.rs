use futures::Stream;
use tokio::prelude::*;

pub fn read_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let (b0, buf) = buf.split_first()?;
    let result = if (b0 & 0x80) == 0x00 {
        (u64::from(b0 & 0x7F), buf)
    } else {
        let (b1, buf) = buf.split_first()?;
        if (b0 & 0xC0) == 0x80 {
            (u64::from(b0 & 0x3F) << 8 | u64::from(*b1), buf)
        } else {
            let (b2, buf) = buf.split_first()?;
            if (b0 & 0xF0) == 0xF0 {
                match b0 & 0xFC {
                    0xF0 => {
                        let (b3, buf) = buf.split_first()?;
                        let (b4, buf) = buf.split_first()?;
                        (
                            u64::from(*b1) << 24
                                | u64::from(*b2) << 16
                                | u64::from(*b3) << 8
                                | u64::from(*b4),
                            buf,
                        )
                    }
                    0xF4 => {
                        let (b3, buf) = buf.split_first()?;
                        let (b4, buf) = buf.split_first()?;
                        let (b5, buf) = buf.split_first()?;
                        let (b6, buf) = buf.split_first()?;
                        let (b7, buf) = buf.split_first()?;
                        let (b8, buf) = buf.split_first()?;
                        (
                            u64::from(*b1) << 56
                                | u64::from(*b2) << 48
                                | u64::from(*b3) << 40
                                | u64::from(*b4) << 32
                                | u64::from(*b5) << 24
                                | u64::from(*b6) << 16
                                | u64::from(*b7) << 8
                                | u64::from(*b8),
                            buf,
                        )
                    }
                    0xF8 => {
                        let (val, buf) = read_varint(buf)?;
                        (!val, buf)
                    }
                    0xFC => (!u64::from(b0 & 0x03), buf),
                    _ => {
                        return None;
                    }
                }
            } else if (b0 & 0xF0) == 0xE0 {
                let (b3, buf) = buf.split_first()?;
                (
                    u64::from(b0 & 0x0F) << 24
                        | u64::from(*b1) << 16
                        | u64::from(*b2) << 8
                        | u64::from(*b3),
                    buf,
                )
            } else if (b0 & 0xE0) == 0xC0 {
                (
                    u64::from(b0 & 0x1F) << 16 | u64::from(*b1) << 8 | u64::from(*b2),
                    buf,
                )
            } else {
                return None;
            }
        }
    };
    Some(result)
}

pub fn write_varint32<T: Write>(buf: &mut T, value: u32) -> std::io::Result<()> {
    // FIXME: actually implement the variable part
    buf.write_all(&[
        240,
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ])
}

/// Like `futures::future::Either` but for Streams
pub enum EitherS<A, B> {
    A(A),
    B(B),
}

impl<A, B> Stream for EitherS<A, B>
where
    A: Stream,
    B: Stream<Item = A::Item, Error = A::Error>,
{
    type Item = A::Item;
    type Error = A::Error;
    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        match self {
            EitherS::A(s) => s.poll(),
            EitherS::B(s) => s.poll(),
        }
    }
}
