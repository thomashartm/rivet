//! Runs the PostgreSQL protocol over the [`ByteStream`] of a tunnel.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use rivet_sdk::error::Result;
use rivet_sdk::extension::{BoxFuture, ByteStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Gives a [`ByteStream`] the Tokio I/O traits that `tokio-postgres` needs.
///
/// It runs at most one `read` and one `write` of the stream at a time, as the
/// [`ByteStream`] contract demands. A write is accepted at once and finishes
/// in the background: the next write, flush or shutdown waits for it and
/// reports its error.
pub(crate) struct Transport {
    stream: Arc<dyn ByteStream>,
    reading: Option<BoxFuture<'static, Result<Vec<u8>>>>,
    /// Bytes that the stream gave but the reader had no room for.
    unread: Vec<u8>,
    writing: Option<BoxFuture<'static, Result<()>>>,
}

impl Transport {
    pub(crate) fn new(stream: Box<dyn ByteStream>) -> Self {
        Self {
            stream: Arc::from(stream),
            reading: None,
            unread: Vec::new(),
            writing: None,
        }
    }

    /// Waits for the write in progress, if any.
    fn poll_written(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(write) = &mut self.writing {
            let result = ready!(write.as_mut().poll(cx));
            self.writing = None;
            result.map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A reader may wait for the answer to a write it never flushed (the
        // `SSLRequest` of the TLS start): the write must go on meanwhile.
        if this.writing.is_some()
            && let Poll::Ready(Err(error)) = this.poll_written(cx)
        {
            return Poll::Ready(Err(error));
        }
        if this.unread.is_empty() {
            let stream = &this.stream;
            let read = this.reading.get_or_insert_with(|| {
                let (stream, max) = (Arc::clone(stream), buf.remaining().max(1));
                Box::pin(async move { stream.read(max).await })
            });
            let result = ready!(read.as_mut().poll(cx));
            this.reading = None;
            // An empty result is the end of the stream: nothing is put in `buf`.
            this.unread = result.map_err(io::Error::other)?;
        }
        let count = this.unread.len().min(buf.remaining());
        buf.put_slice(&this.unread[..count]);
        this.unread.drain(..count);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_written(cx))?;
        let (stream, data) = (Arc::clone(&this.stream), buf.to_vec());
        this.writing = Some(Box::pin(async move { stream.write(data).await }));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_written(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The stream closes when it is dropped.
        self.get_mut().poll_written(cx)
    }
}
