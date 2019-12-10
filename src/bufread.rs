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

/// This size is only used for the creation of the internal buffers and has no bearing on the block
/// size, apart from necessarily being at least as large. 4KB should be enough for everyone, right?
const BUFFER_SIZE: usize = 4096;

struct Cryptostream<R: Read> {
    reader: R,
    buffer: [u8; BUFFER_SIZE],
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
            buffer: [0u8; BUFFER_SIZE],
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
        if self.finalized {
            return Ok(0);
        }

        let block_size = self.cipher.block_size();
        // We could actually easily support algorithms with non-power-of-two block sizes by simply
        // using modulo division instead of ANDing with `blocksize - 1`, but in practice all
        // ciphers worth supporting will have a power-of-two block size and the bitwise AND is much
        // faster.
        debug_assert!(
            block_size.count_ones() == 1,
            "Only algorithms with power-of-two block sizes are supported!"
        );

        debug_assert!(
            buf.len() >= 2 * block_size,
            "The read buffer must be at least twice the length of the cipher block size!"
        );

        // Crypter::update() requires the output buffer to be at least `input.len() + block_size`
        // in length, so we only read as much as we can pass to `update()` in one call, otherwise
        // we need to preserve buffer contents across calls and implement a circular queue with
        // unnecessary copying.
        let mut bytes_read = 0;
        let max_read = std::cmp::min(buf.len() - block_size, BUFFER_SIZE);

        // Read::read() is required to return zero bytes only if the EOF is reached, so we must
        // loop over the input source until at least one block has been read and transformed.
        loop {
            let mut buffer = &mut self.buffer[bytes_read..max_read];
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.finalized = true;

                    // [openssl::symm::Crypter::finalize(..)] will panic if zero bytes have been written to
                    // the instance before `finalize()` is called. We have to call finalize() if we ever
                    // wrote to the instance, i.e. called `Crypter::update()`, even if we didn't this
                    // round.
                    if self.never_used {
                        return Ok(0);
                    } else {
                        return self
                            .crypter
                            .finalize(&mut buf)
                            .map_err(|e| Error::new(ErrorKind::Other, e));
                    }
                }
                Ok(n) => {
                    self.never_used = false;
                    bytes_read += n;
                    match self.crypter.update(&buffer[0..n], &mut buf) {
                        Ok(0) => continue,
                        Ok(written) => return Ok(written),
                        e @ Err(_) => return e.map_err(|e| Error::new(ErrorKind::Other, e)),
                    }
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
    ///
    /// `buf` must be at least the size of one block or else `read` will return 0 prematurely. This
    /// routine will read in multiples of block size to avoid needless buffering of data, and so it
    /// is normal for it to read less than the buffer size if the buffer is not a multiple of the
    /// block size.
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
