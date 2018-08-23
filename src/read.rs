//! Cryptostream types which operate over [`Read`] streams, providing both encryption and
//! decryption facilities.

use bufread;
use openssl::error::ErrorStack;
use openssl::symm::Cipher;
use std::io::{BufReader, Error, Read};

/// An encrypting stream adapter that encrypts what it reads
///
/// `read::Encryptor` is a stream adapter that sits atop a plaintext (non-encrypted) `Read` source,
/// exposing a second `Read` interface. Bytes read out of `read::Encryptor` are the encrypted
/// contents of the underlying `Read` stream.
pub struct Encryptor<R: Read> {
    reader: bufread::Encryptor<BufReader<R>>,
}

impl<R: Read> Encryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            reader: bufread::Encryptor::new(BufReader::new(reader), cipher, key, iv)?,
        })
    }
}

impl<R: Read> Read for Encryptor<R> {
    /// Reading from the cryptostream returns an encrypted view of bytes pulled from the underlying
    /// `Read` stream.
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        self.reader.read(&mut buf)
    }
}

/// A decrypting stream adapter that decrypts what it reads
///
/// `read::Decryptor` is a stream adapter that sits atop a ciphertext (encrypted) `Read` source,
/// exposing a second `Read` interface. Bytes read out of `read::Decrytor` are the decrypted
/// contents of the underlying `Read` stream.
pub struct Decryptor<R: Read> {
    reader: bufread::Decryptor<BufReader<R>>,
}

impl<R: Read> Decryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> Result<Self, ErrorStack> {
        Ok(Self {
            reader: bufread::Decryptor::new(BufReader::new(reader), cipher, key, iv)?,
        })
    }
}

impl<R: Read> Read for Decryptor<R> {
    /// Reading from the cryptostream returns returns a decrypted view of bytes pulled from the
    /// underlying `Read` stream.
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Error> {
        self.reader.read(&mut buf)
    }
}
