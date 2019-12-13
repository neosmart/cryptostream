//! Cryptostream types which operate over [`BufRead`](std::io::BufRead) streams, providing both
//! encryption and decryption facilities.
//!
//! Note that unlike the situation with `Read` and `Write`, there's no need for a `bufwrite`
//! counterpart to this flavor of `Cryptostream` as there is no issue with simply wrapping a
//! [`write::Encryptor`]/[`write::Decryptor`] instance (implementing [`Write`](std::io::Write)) in
//! a `BufWriter` the way you would any other `Write` destination. However when reading *out* of a
//! `BufRead` source (whether to encrypt or decrypt its contents) you will run into an ugly
//! situation when you read partial blocks as only a complete block in the middle of a stream can
//! be correctly encrypted or decrypted. If your block is `n` bytes and your call to
//! `source.read()` returns `n + x` bytes, you need to buffer them somewhere then hand them back to
//! the `Cryptostream` encryptor/decryptor to prepend to the results of the next read so that they
//! can be processed correctly.
//!
//! The `bufread::Cryptostream` variants in this module handle the buffering for you, and ensure
//! that reads always return (when and where possible) nice, round buffers divisible by the
//! enryption algorithm's block size.

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{BufRead, Error, ErrorKind, Read};

/// EVP_MAX_BLOCK_LENGTH in OpenSSL is 32 bytes, and we require at least 2*n-1 for the worst case
/// where we start off with just a byte shy of a block and then read an entire block.
const EVP_MAX_BLOCK_LENGTH: usize = 32;
const BUFFER_SIZE: usize = EVP_MAX_BLOCK_LENGTH * 2;

struct Buffer {
    buffer: [u8; BUFFER_SIZE],
    length: usize,
    index: usize,
}

// Explicitly use a simple stack-allocated struct rather than a heap-allocated vector.
impl Default for Buffer {
    fn default() -> Self {
        Self {
            buffer: [0u8; BUFFER_SIZE],
            length: 0,
            index: 0,
        }
    }
}

impl<'a> Buffer {
    fn len(&self) -> usize {
        self.length - self.index
    }

    fn is_empty(&self) -> bool {
        self.length == self.index
    }

    fn fill<F, E>(&mut self, mut read: F) -> Result<usize, E>
    where
        F: FnMut(&mut [u8]) -> Result<usize, E>,
    {
        let mut write_buf = &mut self.buffer[self.length..];
        let written = read(&mut write_buf)?;
        self.length += written;
        Ok(written)
    }

    fn reset(&mut self) {
        self.index = 0;
        self.length = 0;
    }
}

impl Read for Buffer {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        let len = std::cmp::min(dst.len(), self.len());
        dst[..len].copy_from_slice(&self.buffer[self.index..][..len]);
        self.index += len;
        Ok(len)
    }
}

#[test]
fn zero_len_buffer_read() {
    let mut b = Buffer::default();
    let mut temp = Vec::new();
    match b.read(&mut temp) {
        Ok(0) => {}
        _ => panic!("Zero-length read failure!"),
    }
}

struct Cryptostream<R: Read> {
    reader: R,
    read_buffer: [u8; BUFFER_SIZE],
    write_buffer: Buffer,
    never_used: bool,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<R: Read> Cryptostream<R> {
    pub fn new(
        mode: Mode,
        reader: R,
        cipher: Cipher,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Self, ErrorStack> {
        let mut crypter = Crypter::new(cipher, mode, key, Some(iv))?;
        crypter.pad(true);

        Ok(Self {
            reader: reader,
            read_buffer: [0; BUFFER_SIZE],
            write_buffer: Default::default(),
            never_used: true,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
        })
    }

    pub fn finish(self) -> R {
        self.reader
    }
}

impl<R: Read> Read for Cryptostream<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        let block_size = self.cipher.block_size();
        debug_assert!(
            block_size.count_ones() == 1,
            "Only algorithms with power-of-two block sizes are supported!"
        );

        if !self.write_buffer.is_empty() {
            // Resume from previously transformed content
            let drained = self.write_buffer.read(&mut buf)?;
            eprintln!("Drained {} bytes from overflow", drained);
            return Ok(drained);
        }
        if self.finalized {
            return Ok(0);
        }

        // Read::read() is required to return zero bytes only if the EOF is reached, so we must
        // loop over the input source until at least one block has been read and transformed.
        let mut bytes_read = 0;
        loop {
            let max_read = self.read_buffer.len() - bytes_read - block_size;
            let mut read_buffer = &mut self.read_buffer[bytes_read..][..max_read];
            match self.reader.read(&mut read_buffer) {
                Ok(0) => {
                    // We have reached the end of the wrapped/underlying stream
                    self.finalized = true;

                    // [openssl::symm::Crypter::finalize(..)] will panic if zero bytes have been
                    // written to the instance before `finalize()` is called. We have to call
                    // Crypter::finalize(..) if we ever wrote to the instance.
                    return if self.never_used {
                        Ok(0)
                    } else if !self.write_buffer.is_empty() || buf.len() < bytes_read + block_size {
                        // The destination buffer is not sufficient for a zero-copy operation
                        // without scatter-gather.
                        let write_buffer = &mut self.write_buffer;
                        let crypter = &mut self.crypter;
                        let written = write_buffer.fill(|b| crypter.finalize(b))
                            .map_err(|e| Error::new(ErrorKind::Other, e))?;

                        let copied = self.write_buffer.read(buf)?;
                        eprintln!("Finalized {} of {} bytes with overflow", copied, written);

                        Ok(copied)
                    } else {
                        // We can skip the copy and use the provided buffer directly.
                        self.crypter
                            .finalize(&mut buf)
                            .map_err(|e| Error::new(ErrorKind::Other, e))
                    }
                }
                Ok(n) => {
                    self.never_used = false;
                    bytes_read += n;

                    // OpenSSL will panic if we try to read into too small a buffer, so we may need
                    // to buffer the result locally.
                    if buf.len() < n + block_size {
                        let write_buffer = &mut self.write_buffer;
                        let crypter = &mut self.crypter;
                        write_buffer.reset();
                        let bytes_written = write_buffer.fill(|b| crypter.update(&read_buffer[..n], b))
                            .map_err(|e| Error::new(ErrorKind::Other, e))?;

                        match bytes_written {
                            0 => continue,
                            written => {
                                let copied = self.write_buffer.read(&mut buf)?;
                                eprintln!(
                                    "Transformed {} of {} bytes with overflow",
                                    copied, written
                                );
                                return Ok(copied);
                            }
                        };
                    } else {
                        // Skip the double-buffering and write directly to the source.
                        match self.crypter.update(&self.read_buffer[..n], &mut buf) {
                            Ok(0) => continue,
                            Ok(written) => return Ok(written),
                            e @ Err(_) => return e.map_err(|e| Error::new(ErrorKind::Other, e)),
                        };
                    };
                }
                // It is safe to just bubble up ErrorKind::Interrupted as our state is updated each loop.
                Err(e) => return Err(e),
            };
        }
    }
}

/// An encrypting stream adapter that encrypts what it reads
///
/// `bufread::Encryptor` is a stream adapter that sits atop a plaintext (non-encrypted) [`BufRead`]
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

    pub fn finish(self) -> R {
        self.inner.reader
    }
}

impl<R: BufRead> Read for Encryptor<R> {
    /// Reads encrypted data out of the underlying plaintext
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        self.inner.read(&mut buf)
    }
}

/// A decrypting stream adapter that decrypts what it reads
///
/// `bufread::Decryptor` is a stream adapter that sits atop a ciphertext (encrypted) `BufRead` source,
/// exposing a second `BufRead` interface. Bytes read out of `bufread::Decrytor` are the decrypted
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

    pub fn finish(self) -> R {
        self.inner.finish()
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
        self.inner.read(&mut buf)
    }
}
