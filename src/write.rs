//! Cryptostream types which operate over [`Write`](std::io::Write) streams, providing both
//! encryption and decryption facilities.
//!
//! Use [`write::Encryptor`] to pass in plaintext and have it write the encrypted equivalent to the
//! underlying `Write` stream, or use [`write::Decryptor`] to do the opposite and have decrypted
//! plaintext written to the wrapped `Write` output each time encrypted bytes are written to the
//! instance.

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{Error, ErrorKind, Write};

const BUFFER_SIZE: usize = 4096;

struct Cryptostream<W: Write> {
    buffer: [u8; BUFFER_SIZE],
    /// This `Option` is guaranteed to always be `Some` up until the point
    /// [`to_inner()`](self::to_inner) is called, which is the only place `None` is swapped in. As
    /// that call consumes the `Cryptostream` object, we can safely assume that `writer.unwrap()`
    /// is always safe to call.
    writer: Option<W>,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
    never_used: bool,
}

impl<W: Write> Cryptostream<W> {
    pub fn new(
        mode: Mode,
        writer: W,
        cipher: Cipher,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self, ErrorStack> {
        let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
        crypter.pad(true);

        Ok(Self {
            buffer: [0u8; BUFFER_SIZE],
            writer: Some(writer),
            never_used: true,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
        })
    }

    /// Function shared by Drop and finish()
    fn inner_finish(&mut self) -> Result<(), Error> {
        if !self.finalized {
            self.finalized = true;

            // Crypter::finalize() will panic if Crypter::update() was never previously called.
            if !self.never_used {
                let mut buffer = [0u8; 16];
                let bytes_written = self
                    .crypter
                    .finalize(&mut buffer)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;

                self.writer
                    .as_mut()
                    .unwrap()
                    .write(&buffer[0..bytes_written])?;
            }
        }

        self.flush()
    }

    /// Finishes writing to the underlying cryptostream, padding the final block as needed,
    /// flushing all output. Returns the wrapped `Write` instance.
    pub fn finish(mut self) -> Result<W, Error> {
        self.inner_finish()?;

        // Return the original `W` instance. Since we implement `Drop`, we have to put something in
        // its place, as we cannot simply destructure ourselves. (This is why `inner` is an
        // `Option<W>` rather than `W`).
        let mut inner = None;
        std::mem::swap::<Option<W>>(&mut self.writer, &mut inner);
        Ok(inner.unwrap())
    }
}

impl<W: Write> Write for Cryptostream<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if self.finalized {
            return Ok(0);
        }

        // Crypter::update() requires `output.len() >= input.len() + block_size`
        let block_size = self.cipher.block_size();
        let max_read = std::cmp::min(BUFFER_SIZE - block_size, buf.len());

        if max_read > 0 {
            let bytes_encrypted = self
                .crypter
                .update(&buf[0..max_read], &mut self.buffer)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;

            // Flag the crypter as having been used and needing finalizing
            self.never_used = false;

            self.writer
                .as_mut()
                .unwrap()
                .write_all(&self.buffer[0..bytes_encrypted])?;
        }

        // Regardless of how many bytes of encrypted ciphertext we wrote to the underlying stream
        // (taking padding into consideration) we return how many bytes of *input* were processed,
        // which can never be larger than the number of bytes passed in to us originally.
        Ok(max_read)
    }

    /// Flushes the underlying stream but does not clear all internal buffers or explicitly pad the
    /// output blocks, as that would prevent us from appeding anything in the future if we are not
    /// at a block boundary.
    fn flush(&mut self) -> Result<(), Error> {
        // If `Cryptostream::finish()` is manually called, writer can be `None`
        match self.writer.as_mut() {
            Some(x) => x.flush(),
            _ => Ok(()),
        }
    }
}

impl<W: Write> Drop for Cryptostream<W> {
    /// Write all buffered output to the underlying stream, pad the final block if needed, and
    /// flush everything.
    fn drop(&mut self) {
        // We should never panic on Drop
        let _r = self.inner_finish();
    }
}

/// An encrypting stream adapter that encrypts what is written to it.
///
/// `write::Encryptor` is a stream adapter that sits atop a `Write` stream. Plaintext written to
/// the `Encryptor` is encrypted and written to the underlying stream.
pub struct Encryptor<W: Write> {
    inner: Cryptostream<W>,
}

impl<W: Write> Encryptor<W> {
    pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            inner: Cryptostream::new(Mode::Encrypt, writer, cipher, key, iv)?,
        })
    }

    /// Finishes writing to the underlying cryptostream, padding the final block as needed,
    /// flushing all output. Returns the wrapped `Write` instance.
    pub fn finish(self) -> Result<W, Error> {
        self.inner.finish()
    }
}

impl<W: Write> Write for Encryptor<W> {
    /// Writes decrypted bytes to the cryptostream, causing their encrypted contents to be written
    /// to the underlying `Write` object.
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        self.inner.write(&mut buf)
    }

    /// Flushes the underlying stream but does not clear all internal buffers or explicitly pad the
    /// output blocks as that would prevent us from appeding anything in the future if we are not a
    /// block boundary.
    fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush()
    }
}

/// A decrypting stream adapter that decrypts what is written to it
///
/// `write::Decryptor` is a stream adapter that sits atop a `Write` stream. Ciphertext written to
/// the `Decryptor` is decrypted and written to the underlying stream.
pub struct Decryptor<W: Write> {
    inner: Cryptostream<W>,
}

impl<W: Write> Decryptor<W> {
    pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            inner: Cryptostream::new(Mode::Decrypt, writer, cipher, key, iv)?,
        })
    }

    /// Finishes writing to the underlying cryptostream, padding the final block as needed,
    /// flushing all output. Returns the wrapped `Write` instance.
    pub fn finish(self) -> Result<W, Error> {
        self.inner.finish()
    }
}

impl<W: Write> Write for Decryptor<W> {
    /// Writes encrypted bytes to the cryptostream, causing their decrypted contents to be written
    /// to the underlying `Write` object.
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        self.inner.write(&mut buf)
    }

    /// Flushes the underlying stream but does not clear all internal buffers or explicitly pad the
    /// output blocks as that would prevent us from reading any further in the future if we are not
    /// a block boundary.
    fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush()
    }
}
