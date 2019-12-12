//! The `cryptostream` crate provides a number of stream adapters [that provide "transparent"
//! encryption or
//! decryption](https://neosmart.net/blog/2018/transparent-encryption-and-decryption-in-rust-with-cryptostreams/)
//! of the wrapped [`Read`](std::io::Read) or [`Write`](std::io::Write) source. Since rust doesn't
//! have a generic "stream" type that implements both reads and writes and in order to enforce
//! correct semantics (and boost security!), you need to pick the cryptostream variant that
//! correctly matches your needs.
//!
//! The most common reasons for using this library:
//!
//! * [`read::Decryptor`]: You have an encrypted
//! `Read` source and you want to transparently decrypt its contents while reading from it (e.g.
//! you have encrypted data at rest and want to decrypt it into memory).
//! * [`write::Encryptor`]:
//! You have a `Write` instance you want to write the encrypted ciphertext equivalent of some
//! plaintext you have in memory (e.g. you have plaintext data in memory you want to store it
//! encrypted).
//!
//! Considerably less common use cases:
//!
//! * [`read::Encryptor`]: You have a `Read` source containing
//! plaintext but you want to pull encrypted contents out of it (e.g. you want to encrypt data
//! stored as plaintext).
//! * [`write::Decryptor`]: You want to write cyphertext to a `Write`
//! instance and have it pass through the decrypted plaintext to the underlying stream (e.g. you
//! have cryptotext in memory and want to store it decrypted).
//!
//! Additionally, the [`bufread`] module provides the [`bufread::Encryptor`] and
//! [`bufread::Decryptor`] types for encrypting/decrypting plaintext/ciphertext on-the-fly from a
//! [`BufRead`](std::io::BufRead) source. (There is no need for a `bufwrite` variant.)

pub mod bufread;
pub mod read;
pub mod write;

#[cfg(test)]
mod tests;
