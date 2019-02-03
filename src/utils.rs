use futures::Stream;
use tokio::prelude::*;

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
