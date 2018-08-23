extern crate openssl;
extern crate rand;

use openssl::symm::{Cipher, Crypter, Mode};
use std::io::prelude::*;

use read;
use write;

pub const TEST: &[u8] = b"It was the best of times, it was the worst of times.";

#[test]
fn basic_read_encrypt() {
    let source: &[u8] = TEST;
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let mut encrypted = [0u8; 1024];
    let mut encryptor = read::Encryptor::new(source, cipher, &key, &iv).unwrap();
    let mut total_bytes_read = 0;
    loop {
        let bytes_read = encryptor
            .read(&mut encrypted)
            .expect("Encryptor read failure!");
        if bytes_read == 0 {
            break;
        }

        eprintln!("Read {} bytes out of encrypted stream", bytes_read);
        eprintln!(
            "Bytes: {:?}",
            &encrypted[total_bytes_read..total_bytes_read + bytes_read]
        );
        total_bytes_read += bytes_read;
    }

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).unwrap();
    let mut decrypted = [0u8; 1024];
    let mut bytes_decrypted = crypter
        .update(&encrypted[0..total_bytes_read], &mut decrypted)
        .unwrap();
    bytes_decrypted += crypter.finalize(&mut decrypted[bytes_decrypted..]).unwrap();

    eprintln!("Decrypted {} bytes", bytes_decrypted);
    let decrypted_msg = String::from_utf8(decrypted[0..bytes_decrypted].to_vec()).unwrap();
    eprintln!("Decrypted message: {}", decrypted_msg);
    assert_eq!(String::from_utf8(source.to_vec()).unwrap(), decrypted_msg);
}

#[test]
fn basic_write_encrypt() {
    let source: &[u8] = TEST;
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let mut encrypted = Vec::new();
    let mut bytes_written = 0;

    {
        let mut encryptor = write::Encryptor::new(&mut encrypted, cipher, &key, &iv).unwrap();

        while bytes_written < source.len() {
            let write_bytes = encryptor.write(&source[bytes_written..]).unwrap();
            eprintln!("Wrote {} bytes to cryptostream", write_bytes);
            bytes_written += write_bytes;
        }
    }

    eprintln!("Encrypted bytes: {:?}", &encrypted[0..bytes_written]);

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv)).unwrap();
    let mut decrypted = [0u8; 1024];
    let mut bytes_decrypted = crypter.
        update(&encrypted, &mut decrypted)
        .unwrap();
    bytes_decrypted += crypter.finalize(&mut decrypted[bytes_decrypted..]).unwrap();

    eprintln!("Decrypted {} bytes", bytes_decrypted);
    let decrypted_msg = String::from_utf8(decrypted[0..bytes_decrypted].to_vec()).unwrap();
    eprintln!("Decrypted message: {}", decrypted_msg);
    assert_eq!(String::from_utf8(source.to_vec()).unwrap(), decrypted_msg);
}

