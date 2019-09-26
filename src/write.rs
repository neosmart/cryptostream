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
    writer: W,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<W: Write> Write for Cryptostream<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if self.finalized {
            return Ok(0);
        }

        let mut buffer = [0u8; BUFFER_SIZE];

        let mut bytes_encrypted = self.crypter.update(&buf, &mut buffer)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        // eprintln!("Encrypted {} bytes written to cryptostream", bytes_encrypted);

        if buf.len() < self.cipher.block_size() {
            self.finalized = true;
            let write_bytes = self.crypter.finalize(&mut buffer[bytes_encrypted..])
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            // eprintln!("Encrypted {} bytes written to cryptostream", write_bytes);
            bytes_encrypted += write_bytes;
        };

        let mut bytes_written = 0;
        while bytes_written != bytes_encrypted {
            let write_bytes = self.writer.write(&buffer[bytes_written..bytes_encrypted])?;
            // eprintln!("Wrote {} bytes to underlying stream", write_bytes);
            bytes_written += write_bytes;
        }

        // eprintln!("Total bytes encrypted: {}", bytes_written);

        // Regardless of how many bytes of encrypted ciphertext we wrote to the underlying stream
        // (taking padding into consideration) we return how many bytes of *input* were processed,
        // which can never be larger than the number of bytes passed in to us originally.
        return Ok(buf.len());
    }

    fn flush(&mut self) -> Result<(), Error> {
        // eprintln!("flush called");

        if !self.finalized {
            self.finalized = true;

            let mut buffer = [0u8; 16];
            let bytes_written = self.crypter.finalize(&mut buffer)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            // eprintln!("Flushed {} bytes to the underlying stream", bytes_written);
            self.writer.write(&buffer[0..bytes_written])?;
        }

        return Ok(());
    }
}

impl<W: Write> Drop for Cryptostream<W> {
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

/// An encrypting stream adapter that encrypts what is written to it.
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

