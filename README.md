# Rust Cryptostream Crate

[![crates.io](https://img.shields.io/crates/v/cryptostream.svg)](https://crates.io/crates/cryptostream) [![docs.rs](https://docs.rs/cryptostream/badge.svg)](https://docs.rs/crate/cryptostream)

`cryptostream` provides a rust equivalent to the [.NET
Cryptostream](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptostream)
class, providing an efficient and easy solution to on-the-fly encryption or decryption of existing
`Read` or `Write` resources. Cryptography is provided via [rust-openssl](https://github.com/sfackler/rust-openssl)
and is fully configurable.

## What is a Cryptostream?

In brief, a
[Cryptostream](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptostream)
is a wrapper around a stream (in rust parlance, a `Read` or `Write` type) that transparently
encrypts or decrypts the underlying contents. After creating an instance of a `Cryptostream` with
the cipher, key, and IV specified, bytes written to or read from the Cryptostream are the same as
the `Read` or `Write` stream it is wrapping, only additionally encrypted or decrypted. It makes
handling encrypted sources or destinations a breeze, and requires virtually no changes to your
existing pipeline - it's just a `Read` or `Write`, like any other.

## Crate Design

As rust (for better or for worse) lacks a `Stream` type, `cryptostream` has been implemented in both
encryption and decryption modes twice, once as a `Read` impl and once as a `Write` impl (design cues
taken from the `flate2` crate), with a bonus `BufRead` impl thrown in for good measure. This means
that for any combination of available [ciphertext|plaintext] and desired [read|write] application,
one of the `cryptostream` impls should match your usecase. A `cryptostream` should be created
matching the type of resource you wish to consume (in case source data is a `Read` impl) or the type
of resource you wish to create (in case destination is a `Write` impl).

Implementations have been grouped by trait into namespace and have names conveying their
applications:

* `cryptostream::read::Encryptor`
* `cryptostream::read::Decryptor`
* `cryptostream::write::Encryptor`
* `cryptostream::write::Decryptor`

## `Read` vs `Write` Cryptostreams

The difference between the `Read` and `Write` variants of `cryptostream` are perhaps best
illustrated by example. In both of the following examples, we will be decrypting ciphertext, however
in one case we need to use `read::Decryptor` and in the other `write::Decryptor`.

In the first case, we have a `Read` source which contains the bytes we need to decrypt, and we wish
to obtain the equivalent plaintext in memory to later perform some operation with in its decoded
state:

```rust

// This is the cipher text, base64-encoded to avoid any whitespace munging. In this
// contrived example, we are using a binary `Vec<u8>` as the `Read` source containing
// the encrypted data; in practice it could be a binary file, a network stream, or
// anything else.
let src: Vec<u8> = decode(concat!(
    "vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdO",
    "VC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXv",
    "Q6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw==",
))
.unwrap();
let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

// The source can be anything implementing `Read`. In this case, a simple &[u8] slice.
let mut decryptor =
    read::Decryptor::new(src.as_slice(), Cipher::aes_128_cbc(), &key, &iv).unwrap();

let mut decrypted = [0u8; 1024]; // a buffer to decrypt into
let mut bytes_decrypted = 0;

loop {
    // Just read from the `Decryptor` as if it were any other `Read` impl,
    // the decryption takes place automatically.
    let read_count = decryptor.read(&mut decrypted[bytes_decrypted..]).unwrap();
    bytes_decrypted += read_count;
    if read_count == 0 {
        break;
    }
}

println!("{}", String::from_utf8_lossy(&decrypted));

```

Now what about if you want to _write out_ the decrypted contents instead of _read_ them, but still
wish to perform decryption all the same?

```rust

// Starting again with the same encrypted bytestream, encoded as base64:
let src: Vec<u8> = decode(concat!(
    "vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdO",
    "VC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXv",
    "Q6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw=="
))
.unwrap();
let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

// The destination can be any object implementing `Write`: in this case, a `Vec<u8>`.
let mut decrypted = Vec::new();

// When a `cryptostream` is dropped, all buffers are flushed and it is automatically
// finalized. We can either call `drop()` on the cryptostream or put its usage in a
// separate scope.
{
    let mut decryptor =
        write::Decryptor::new(&mut decrypted, Cipher::aes_128_cbc(), &key, &iv).unwrap();

    let mut bytes_decrypted = 0;

    while bytes_decrypted != src.len() {
        // Just write encrypted ciphertext to the `Decryptor` instance as if it were any
        // other `Write` impl. Decryption takes place automatically.
        let write_count = decryptor.write(&src[bytes_decrypted..]).unwrap();
        bytes_decrypted += write_count;
    }
}

// The underlying `Write` instance is only guaranteed to contain the complete and
// finalized contents after the cryptostream is either explicitly finalized with a
// call to `Cryptostream::finish()` or when it's dropped (either at the end of a scope
// or via an explicit call to `drop()`, whichever you prefer).
println!("{}", String::from_utf8_lossy(&decrypted));

```
