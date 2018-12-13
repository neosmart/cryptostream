//! Cryptostream types which operate over [`BufRead`] streams, providing both encryption and
//! decryption facilities.

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{BufRead, Error, ErrorKind, Read};

const OVERFLOW_SIZE: usize = 64;

pub struct OverflowBuf {
    buf: [u8; OVERFLOW_SIZE],
    start: usize,
    end: usize,
}

impl OverflowBuf {
    pub fn new() -> Self {
        OverflowBuf {
            buf: [0u8; OVERFLOW_SIZE],
            start: 0,
            end: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn len(&self) -> usize { self.end - self.start }

    pub fn get_buf(&mut self) -> &mut [u8] {
        self.start = 0;
        self.end = 0;
        &mut self.buf
    }

    pub fn truncate(&mut self, size: usize) {
        self.end = size;
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let bytes_to_copy = buf.len().min(self.end - self.start);
        buf[..bytes_to_copy].copy_from_slice(&self.buf[self.start .. self.start + bytes_to_copy]);
        self.start += bytes_to_copy;
        bytes_to_copy
    }
}

struct Cryptostream<R: BufRead> {
    reader: R,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
    overflow: OverflowBuf,
}

impl<R: BufRead> Cryptostream<R> {
    pub fn new(mode: Mode, reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
        crypter.pad(true);

        Ok(Self {
            reader: reader,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
            overflow: OverflowBuf::new(),
        })
    }
}

impl<R: BufRead> Read for Cryptostream<R> {
    fn read(&mut self, mut sink_buffer: &mut [u8]) -> Result<usize, Error> {
        if self.finalized {
            warn!("Attempt to read from finalized cryptostream");
            return Ok(0);
        }

        // Drain the overflow buffer first, make no attempt to add more data
        // from the underlying stream.
        if !self.overflow.is_empty() {
            trace!("Reading {} bytes out of {} bytes from overflow buffer",
                   self.overflow.len().min(sink_buffer.len()),
                   self.overflow.len());
            return Ok(self.overflow.read(&mut sink_buffer));
        }

        let block_size = self.cipher.block_size();

        let mut bytes_consumed= 0;
        let mut bytes_produced= 0;
        while !self.finalized && bytes_produced == 0 {  // This can be optimized to fill buf as much as possible
            {
                let source_buffer = self.reader.fill_buf()?;
                bytes_produced = match source_buffer.len() {
                    0 => {
                        trace!("Finalizing cryptostream");
                        self.finalized = true;
                        let bytes_produced = self.crypter.finalize(&mut sink_buffer)
                            .map_err(|e| Error::new(ErrorKind::Other, e))?;
                        trace!("Produced {} bytes into sink buffer",bytes_produced);
                        bytes_produced
                    },
                    len if sink_buffer.len() >= 2 * block_size => {
                        // OpenSSL requires the output to be at least input len + blocksize. When
                        // buf.len() would be 1 + block_size we'd be writing a single byte to
                        // crypter.update, which may cause no output. We'd then loop, processing
                        // a single byte at a time, until we have output or the underlying stream
                        // is depleted, in which case we ended up in crypter.finalize above.
                        //
                        // That would suck, so let's require at least 2 blocks of output, so we can
                        // write a single block and get at least a single block as output.
                        bytes_consumed = len.min(sink_buffer.len() - block_size);
                        trace!("Consuming {} bytes from source buffer", bytes_consumed);
                        let bytes_produced = self.crypter
                            .update(&source_buffer[..bytes_consumed], &mut sink_buffer)
                            .map_err(|e| Error::new(ErrorKind::Other, e))?;
                        trace!("Produced {} bytes into sink buffer", bytes_produced);
                        bytes_produced
                    },
                    len => {
                        // Read through the overflow buffer
                        bytes_consumed = len.min(self.overflow.capacity() - block_size);
                        trace!("Consuming {} bytes from source buffer", bytes_consumed);
                        let bytes_produced = self.crypter
                            .update(&source_buffer[..bytes_consumed], self.overflow.get_buf())
                            .map_err(|e| Error::new(ErrorKind::Other, e))?;
                        self.overflow.truncate(bytes_produced);
                        trace!("Produced {} bytes into overflow buffer", bytes_produced);

                        // Read from the overflow buffer to make progress
                        trace!("Reading {} bytes out of {} bytes from overflow buffer",
                               self.overflow.len().min(sink_buffer.len()),
                               self.overflow.len());
                        self.overflow.read(&mut sink_buffer)
                    }
                };
            }
            self.reader.consume(bytes_consumed);
        }

        Ok(bytes_produced)
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
