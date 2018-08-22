//! Cryptostream types which operate over [`BufRead`] streams, providing both encryption and
//! decryption facilities.

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{BufRead, Error, Read};

const BUFFER_SIZE: usize = 4096;

/// An encrypting stream adapter that encrypts what it reads
///
/// `read::Encryptor` is a stream adapter that sits atop a plaintext (non-encrypted) [`BufRead`]
/// source, exposing a second [`BufRead`] interface. Bytes read out of `bufread::Encryptor` are the
/// encrypted contents of the underlying stream.
pub struct Encryptor<R: BufRead> {
    reader: R,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<R: BufRead> Encryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Self {
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
        crypter.pad(true);

        Self {
            reader: reader,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
        }
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
        return Cryptostream::update(&mut self.reader, &mut self.crypter, &mut buf, &mut self.finalized);
    }
}

/// A decrypting stream adapter that decrypts what it reads
///
/// `read::Decryptor` is a stream adapter that sits atop a ciphertext (encrypted) `Read` source,
/// exposing a second `Read` interface. Bytes read out of `read::Decrytor` are the decrypted
/// contents of the underlying `Read` stream.
pub struct Decryptor<R: BufRead> {
    reader: R,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<R: BufRead> Decryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Self {
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
        // crypter.pad(true);

        Self {
            reader: reader,
            cipher: cipher.clone(),
            crypter: crypter,
            finalized: false,
        }
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
        return Cryptostream::update(&mut self.reader, &mut self.crypter, &mut buf, &mut self.finalized);
    }
}

trait Cryptostream<R> {
}

impl<R: Read> Cryptostream<R> {
    fn update(reader: &mut R, crypter: &mut Crypter, mut buf: &mut [u8], finalized: &mut bool) -> Result<usize, Error> {
        if *finalized {
            return Ok(0);
        }

        // read in multiples of block size.
        // let blocks = buf.len() / cipher.block_size();
        let mut buffer = [0u8; BUFFER_SIZE];

        let result = match reader.read(&mut buffer)? {
            0 => {
                *finalized = true;
                crypter.finalize(&mut buf)
            },
            bytes_read @ _ => crypter.update(&buffer[0..bytes_read], &mut buf),
        };

        let bytes_encrypted = result.unwrap();
        return Ok(bytes_encrypted);
    }
}
