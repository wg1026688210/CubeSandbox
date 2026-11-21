// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

//! Async support for pipe or something has file descriptor

use nix::unistd;
use std::{
    fmt, io,
    io::{Read, Result, Write},
    mem,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

fn set_nonblocking(fd: RawFd) {
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
    }
}

struct StreamFd(OwnedFd);

impl io::Read for &StreamFd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match unistd::read(self.0.as_raw_fd(), buf) {
            Ok(l) => Ok(l),
            Err(e) => Err(e.into()),
        }
    }
}

impl io::Write for &StreamFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match unistd::write(self.0.as_raw_fd(), buf) {
            Ok(l) => Ok(l),
            Err(e) => Err(e.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for StreamFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub struct PipeStream(AsyncFd<StreamFd>);

impl PipeStream {
    /// Takes ownership of `fd`, which is closed when the stream is dropped.
    pub fn new(fd: RawFd) -> Result<Self> {
        set_nonblocking(fd);
        // SAFETY: ownership of `fd` transfers to the returned stream.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self(AsyncFd::new(StreamFd(fd))?))
    }

    pub fn from_fd(fd: RawFd) -> Self {
        unsafe { Self::from_raw_fd(fd) }
    }
}

impl AsRawFd for PipeStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for PipeStream {
    fn into_raw_fd(self) -> RawFd {
        // into_inner deregisters the fd from the tokio reactor; without this
        // the fd stays registered and re-wrapping it in a PipeStream fails
        // with EEXIST.
        self.0.into_inner().0.into_raw_fd()
    }
}

impl FromRawFd for PipeStream {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self::new(fd).unwrap()
    }
}

impl fmt::Debug for PipeStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PipeStream({})", self.as_raw_fd())
    }
}

impl AsyncRead for PipeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let b;
        unsafe {
            b = &mut *(buf.unfilled_mut() as *mut [mem::MaybeUninit<u8>] as *mut [u8]);
        };

        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;

            match guard.try_io(|inner| inner.get_ref().read(b)) {
                Ok(Ok(n)) => {
                    unsafe {
                        buf.assume_init(n);
                    }
                    buf.advance(n);
                    return Ok(()).into();
                }
                Ok(Err(e)) => return Err(e).into(),
                Err(_would_block) => {
                    continue;
                }
            }
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;

            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Do nothing in shutdown is very important
        // The only right way to shutdown pipe is drop it
        // Otherwise PipeStream will conflict with its twins
        // Because they both have same fd, and both registered.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::OFlag;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_into_raw_fd_deregisters_from_reactor() {
        let (rfd, _wfd) = unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let stream = PipeStream::new(rfd).unwrap();
        let fd = stream.into_raw_fd();

        // The fd must be deregistered from the reactor: re-wrapping it in a
        // PipeStream must not fail with EEXIST.
        let stream2 = PipeStream::new(fd).unwrap();
        drop(stream2);
    }

    #[tokio::test]
    // Shutdown should never close the inner fd.
    async fn test_pipestream_shutdown() {
        let (_, wfd1) = unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let mut writer1 = PipeStream::new(wfd1).unwrap();

        // if close fd in shutdown, the fd will be reused
        // and the test will failed
        let _ = writer1.shutdown().await.unwrap();

        // let _ = unistd::close(wfd1);

        let (rfd2, wfd2) = unistd::pipe2(OFlag::O_CLOEXEC).unwrap(); // reuse fd number, rfd2 == wfd1

        let mut reader2 = PipeStream::new(rfd2).unwrap();
        let mut writer2 = PipeStream::new(wfd2).unwrap();

        // deregister writer1, then reader2 which has the same fd will be deregistered from epoll
        drop(writer1);

        let _ = writer2.write(b"1").await;

        let mut content = vec![0u8; 1];
        // Will Block here if shutdown close the fd.
        let _ = reader2.read(&mut content).await;
    }
}
