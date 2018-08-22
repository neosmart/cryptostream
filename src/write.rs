//! Cryptostream types which operate over [`Read`] streams, providing both encryption and
//! decryption facilities.

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{Error, Write};

const BUFFER_SIZE: usize = 4096;

/// An encrypting stream adapter that encrypts what is written to it
///
/// `write::Encryptor` is a stream adapter that sits atop a `Write` stream. Plaintext written to
/// the `Encryptor` is encrypted and written to the underlying stream.
pub struct Encryptor<W: Write> {
    writer: W,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<W: Write> Encryptor<W> {
    pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> Self {
	let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
	crypter.pad(true);

	Self {
	    writer: writer,
	    cipher: cipher.clone(),
	    crypter: crypter,
	    finalized: false,
	}
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
	return Cryptostream::update(&mut self.writer, &self.cipher, &mut self.crypter, &mut buf, &mut self.finalized);
    }

    fn flush(&mut self) -> Result<(), Error> {
	Ok(())
    }
}

/// An decrypting stream adapter that decrypts what is written to it
///
/// `write::Decryptor` is a stream adapter that sits atop a `Write` stream. Ciphertext written to
/// the `Decryptor` is decrypted and written to the underlying stream.
pub struct Decryptor<W: Write> {
    writer: W,
    cipher: Cipher,
    crypter: Crypter,
    finalized: bool,
}

impl<W: Write> Decryptor<W> {
    pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> Self {
	let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
	crypter.pad(true);

	Self {
	    writer: writer,
	    cipher: cipher.clone(),
	    crypter: crypter,
	    finalized: false,
	}
    }
}

impl<W: Write> Write for Decryptor<W> {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
	return Cryptostream::update(&mut self.writer, &self.cipher, &mut self.crypter, &mut buf, &mut self.finalized);
    }

    fn flush(&mut self) -> Result<(), Error> {
	Ok(())
    }
}

trait Cryptostream<W> {
}

impl<W: Write> Cryptostream<W> {
    fn update(writer: &mut W, cipher: &Cipher, crypter: &mut Crypter, buf: &[u8], finalized: &mut bool) -> Result<usize, Error> {
	if *finalized {
	    return Ok(0);
	}

	let mut buffer = [0u8; BUFFER_SIZE];

	let mut bytes_written = crypter.update(&buf, &mut buffer).unwrap();

	if buf.len() < cipher.block_size() {
	    *finalized = true;
	    bytes_written += crypter.finalize(&mut buffer).unwrap()
	};

	return Ok(bytes_written);
    }
}

