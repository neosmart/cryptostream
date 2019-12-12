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

#[cfg(not(feature = "system-openssl"))]
extern crate openssl;
#[cfg(feature = "system-openssl")]
extern crate openssl_sys as openssl;

pub mod bufread;
pub mod read;
pub mod write;

/// Because we rename the openssl crate without the `vendored` feature as openssl_sys (you cannot
/// have a dependency imported (even XOR conditionally) twice with the same name, and you cannot
/// have conditional features for dependencies based off of your own feature in Cargo.toml), we
/// re-export the `openssl::symm:Cipher` as `cryptostream::Cipher` so no `extern crate openssl` is
/// required for downstream users of this library, which won't work if the `system-openssl` option
/// were used.
pub use openssl::symm::Cipher as Cipher;

#[cfg(test)]
mod tests;
