//! Cryptostream types which operate over [`BufRead`] streams, providing both encryption and
//! decryption facilities.

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{BufRead, Error, ErrorKind, Read};

const BUFFER_SIZE: usize = 4096;

struct Cryptostream<R: Read> {
    reader: R,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<R: Read> Cryptostream<R> {
    pub fn new(mode: Mode, reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
        crypter.pad(true);

        Ok(Self {
            reader: reader,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
        })
    }
}

impl<R: Read> Read for Cryptostream<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        if self.finalized {
            return Ok(0);
        }

        let block_size = self.cipher.block_size();
        // we could actually easily support algorithms with non-power-of-two block sizes by simply
        // using modulo division instead of ANDing with `blocksize - 1`, but in practice all
        // ciphers worth supporting will have a power-of-two block size and the bitwise AND is much
        // faster.
        debug_assert!(
            block_size.count_ones() == 1,
            "Only algorithms with power-of-two block sizes are supported!"
        );
        let mut buffer = [0u8; BUFFER_SIZE];
        let max_read = BUFFER_SIZE & !(block_size - 1);
        let mut buffer = &mut buffer[0..max_read];

        let mut bytes_read = self.reader.read(&mut buffer)?;
        // eprintln!("Read {} bytes from underlying stream", bytes_read);
        let mut eof = bytes_read == 0;
        while !eof && ((bytes_read & (block_size - 1)) != bytes_read) {
            // we have read a partial block, which is only allowed
            // if this is the end of the underlying stream.
            bytes_read += match self.reader.read(&mut buffer[bytes_read..]) {
                Ok(0) => {
                    eof = true;
                    0
                }
                Ok(n) => {
                    // eprintln!("Read {} bytes from underlying stream", n);
                    n
                }
                Err(e) => match e.kind() {
                    ErrorKind::Interrupted => continue,
                    // Technically we must be able to guarantee no bytes were read if we return
                    // with an error, but how can we do that?
                    _ => return Err(e),
                },
            };
        }

        let mut bytes_written = 0;
        if bytes_read != 0 {
            let write_bytes = self.crypter
                .update(&buffer[bytes_written..bytes_read], &mut buf)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            // eprintln!("Wrote {} bytes to encrypted stream", write_bytes);
            bytes_written += write_bytes;
        };
        if eof {
            self.finalized = true;
            let write_bytes = self.crypter.finalize(&mut buf[bytes_written..])
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            // eprintln!("Wrote {} bytes to encrypted stream", write_bytes);
            bytes_written += write_bytes;
        }

        // eprintln!("Returning {} bytes encrypted", bytes_written);
        return Ok(bytes_written);
    }
}

/// An encrypting stream adapter that encrypts what it reads
///
/// `read::Encryptor` is a stream adapter that sits atop a plaintext (non-encrypted) [`BufRead`]
/// source, exposing a second [`BufRead`] interface. Bytes read out of `bufread::Encryptor` are the
/// encrypted contents of the underlying stream.
pub struct Encryptor<R: BufRead> {
    inner: Cryptostream<R>,
}

impl<R: BufRead> Encryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            inner: Cryptostream::new(Mode::Encrypt, reader, cipher, key, iv)?,
        })
    }
}

impl<R: BufRead> Read for Encryptor<R> {
    /// Reads encrypted data out of the underlying plaintext
    ///
    /// `buf` must be at least the size of one block or else `read` will return 0 prematurely. This
    /// routine will read in multiples of block size to avoid needless buffering of data, and so it
    /// is normal for it to read less than the buffer size if the buffer is not a multiple of the
    /// block size.
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        return self.inner.read(&mut buf);
    }
}

/// A decrypting stream adapter that decrypts what it reads
///
/// `read::Decryptor` is a stream adapter that sits atop a ciphertext (encrypted) `Read` source,
/// exposing a second `Read` interface. Bytes read out of `read::Decrytor` are the decrypted
/// contents of the underlying `Read` stream.
pub struct Decryptor<R: BufRead> {
    inner: Cryptostream<R>,
}

impl<R: BufRead> Decryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            inner: Cryptostream::new(Mode::Decrypt, reader, cipher, key, iv)?,
        })
    }
}

impl<R: BufRead> Read for Decryptor<R> {
    /// Reads decrypted data out of the underlying encrypted ciphertext
    ///
    /// `buf` must be at least the size of one block or else `read` will return 0 prematurely. This
    /// routine will read in multiples of block size to avoid needless buffering of data, and so it
    /// is normal for it to read less than the buffer size if the buffer is not a multiple of the
    /// block size.
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        return self.inner.read(&mut buf);
    }
}