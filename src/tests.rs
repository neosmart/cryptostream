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
            .read(&mut encrypted[total_bytes_read..])
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
fn basic_read_to_end_encrypt() {
    let source: &[u8] = TEST;
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let mut encrypted = vec![];
    let mut encryptor = read::Encryptor::new(source, cipher, &key, &iv).unwrap();
    let total_bytes_read = encryptor.read_to_end(&mut encrypted).unwrap();
    eprintln!("Read {} bytes out of encrypted stream", total_bytes_read);
    eprintln!("Bytes: {:?}", &encrypted);

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

#[test]
fn basic_write_all_encrypt() {
    let source: &[u8] = TEST;
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let mut encrypted = Vec::new();
    {
        let mut encryptor = write::Encryptor::new(&mut encrypted, cipher, &key, &iv).unwrap();
        encryptor.write_all(source).unwrap();
    }

    eprintln!("Encrypted bytes: {:?}", &encrypted);

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

#[test]
fn basic_read_decrypt() {
    let source = TEST;
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();

    let mut encrypted = [0u8; 1024];
    let mut bytes_written = crypter.update(TEST, &mut encrypted).unwrap();
    bytes_written += crypter.finalize(&mut encrypted[bytes_written..]).unwrap();

    let encrypted = &encrypted[0..bytes_written]; // reframe
    let mut decrypted = [0u8; 1024];
    let mut bytes_decrypted = 0;

    {
        let mut decryptor = read::Decryptor::new(encrypted, cipher, &key, &iv).unwrap();

        while bytes_decrypted < source.len() {
            let decrypt_bytes = decryptor.read(&mut decrypted[bytes_decrypted..]).unwrap();
            bytes_decrypted += decrypt_bytes;
        }
        eprintln!("Decrypted a total of {} bytes", bytes_decrypted);
    }

    let decrypted = &decrypted[0..bytes_decrypted]; // reframe
    assert_eq!(&decrypted, &TEST);
}

#[test]
fn basic_read_to_end_decrypt() {
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();

    let mut encrypted = [0u8; 1024];
    let mut bytes_written = crypter.update(TEST, &mut encrypted).unwrap();
    bytes_written += crypter.finalize(&mut encrypted[bytes_written..]).unwrap();

    let encrypted = &encrypted[0..bytes_written]; // reframe
    let mut decrypted = vec![];
    let bytes_decrypted;

    {
        let mut decryptor = read::Decryptor::new(encrypted, cipher, &key, &iv).unwrap();
        bytes_decrypted = decryptor.read_to_end(&mut decrypted).unwrap();
        eprintln!("Decrypted a total of {} bytes", bytes_decrypted);
    }

    let decrypted = &decrypted; // reframe
    assert_eq!(&decrypted[..], TEST);
}

#[test]
fn basic_write_decrypt() {
    let source = TEST;
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();
    let mut cryptor = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();

    let mut encrypted = [0u8; 1024];
    let mut bytes_written = cryptor.update(TEST, &mut encrypted).unwrap();
    bytes_written += cryptor.finalize(&mut encrypted[bytes_written..]).unwrap();

    let encrypted = &encrypted[0..bytes_written]; // reframe
    let mut decrypted = Vec::new();
    let mut bytes_decrypted = 0;

    {
        let mut decryptor = write::Decryptor::new(&mut decrypted, cipher, &key, &iv).unwrap();

        while bytes_decrypted < source.len() {
            let decrypt_bytes = decryptor.write(&encrypted[bytes_decrypted..]).unwrap();
            bytes_decrypted += decrypt_bytes;
        }
        eprintln!("Decrypted a total of {} bytes", bytes_decrypted);
    }

    assert_eq!(&decrypted, &TEST);
}

#[test]
fn basic_write_all_decrypt() {
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();
    let mut cryptor = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();

    let mut encrypted = [0u8; 1024];
    let mut bytes_written = cryptor.update(TEST, &mut encrypted).unwrap();
    bytes_written += cryptor.finalize(&mut encrypted[bytes_written..]).unwrap();

    let encrypted = &encrypted[0..bytes_written]; // reframe
    let mut decrypted = Vec::new();

    {
        let mut decryptor = write::Decryptor::new(&mut decrypted, cipher, &key, &iv).unwrap();
        decryptor.write_all(encrypted).unwrap();
        eprintln!("Decrypted a total of {} bytes", encrypted.len());
    }

    assert_eq!(&decrypted, &TEST);
}
