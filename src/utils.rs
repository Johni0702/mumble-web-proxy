use futures::pin_mut;
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Like `futures::future::Either` but for Streams
pub enum EitherS<A, B> {
    A(A),
    B(B),
}

impl<A, B> Stream for EitherS<A, B>
where
    A: Stream + Unpin,
    B: Stream<Item = A::Item> + Unpin,
{
    type Item = A::Item;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            EitherS::A(s) => {
                pin_mut!(s);
                s.poll_next(cx)
            }
            EitherS::B(s) => {
                pin_mut!(s);
                s.poll_next(cx)
            }
        }
    }
}
