use base64::decode;
use cryptostream::{read, write};
use openssl::symm::Cipher;
use std::io::prelude::*;

fn main() {
    f1();
    f2();
}

fn f1() {
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
}

fn f2() {
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
}
