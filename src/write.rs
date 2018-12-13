//! Cryptostream types which operate over [`Write`] streams, providing both encryption and
//! decryption facilities.

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{Error, ErrorKind, Write};

const BUFFER_SIZE: usize = 4096;

struct Cryptostream<W: Write> {
    writer: W,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<W: Write> Write for Cryptostream<W> {
    fn write(&mut self, source_buffer: &[u8]) -> Result<usize, Error> {
        if self.finalized {
            warn!("Attempt to write {} bytes to finalized cryptostream", source_buffer.len());
            return Ok(0);
        }

        let block_size = self.cipher.block_size();
        let mut sink_buffer = [0u8; BUFFER_SIZE];

        // We can't write more than BUFFER_SIZE - block_size bytes.
        let bytes_consumed = source_buffer.len().min(BUFFER_SIZE - block_size);

        let bytes_produced = self.crypter.update(&source_buffer[..bytes_consumed],
                                                 &mut sink_buffer)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        trace!("Consumed {} bytes out of {} bytes written to cryptostream", bytes_consumed, source_buffer.len());

        self.writer.write_all(&sink_buffer[..bytes_produced])?;
        trace!("Wrote {} bytes to underlying stream", bytes_produced);

        // Regardless of how many bytes of encrypted ciphertext we wrote to the underlying stream
        // (taking padding into consideration) we return how many bytes of *input* were processed.
        return Ok(bytes_consumed);
    }

    fn flush(&mut self) -> Result<(), Error> {
        trace!("flush called");

        if !self.finalized {
            self.finalized = true;

            let mut sink_buffer = [0u8; 16];
            let bytes_produced = self.crypter.finalize(&mut sink_buffer)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            trace!("Flushed {} bytes to the underlying stream", bytes_produced);
            self.writer.write_all(&sink_buffer[..bytes_produced])?;
        } else {
            warn!("Attempt to flush finalized cryptostream");
        }

        return Ok(());
    }
}

impl<W: Write> Drop for Cryptostream<W> {
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

/// An encrypting stream adapter that encrypts what is written to it
///
/// `write::Encryptor` is a stream adapter that sits atop a `Write` stream. Plaintext written to
/// the `Encryptor` is encrypted and written to the underlying stream.
pub struct Encryptor<W: Write> {
    inner: Cryptostream<W>,
}

impl<W: Write> Cryptostream<W> {
    pub fn new(mode: Mode, writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
        crypter.pad(true);

        Ok(Self {
            writer: writer,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
        })
    }
}

impl<W: Write> Encryptor<W> {
    pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            inner: Cryptostream::new(Mode::Encrypt, writer, cipher, key, iv)?,
        })
    }
}

impl<W: Write> Write for Encryptor<W> {
    /// Writes decrypted bytes to the cryptostream, causing their encrypted contents to be written
    /// to the underlying `Write` object. Writing less than cipher-specific `blocksize` bytes
    /// causes the output to be finalized.
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        return self.inner.write(&mut buf);
    }

    /// Writes the final bytes of encrypted content to the underlying stream. This must not be
    /// called before all bytes have been written to the cryptostream.
    fn flush(&mut self) -> Result<(), Error> {
        return self.inner.flush();
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
}

impl<W: Write> Write for Decryptor<W> {
    /// Writes encrypted bytes to the cryptostream, causing their decrypted contents to be written
    /// to the underlying `Write` object.
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        return self.inner.write(&mut buf);
    }

    /// Writes the final bytes of encrypted content to the underlying stream. This must not be
    /// called before all bytes have been written to the cryptostream.
    fn flush(&mut self) -> Result<(), Error> {
        return self.inner.flush();
    }
}

