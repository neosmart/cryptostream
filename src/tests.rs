use openssl::symm::{Cipher, Crypter, Mode};
use std::io::prelude::*;

use crate::read;
use crate::write;

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

    assert!(
        total_bytes_read > source.len(),
        "Encrypted payload less than original input!"
    );
    assert!(
        total_bytes_read < source.len() + cipher.block_size(),
        "Encrypted payload exceeds padded original input!"
    );

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
    let mut bytes_decrypted = crypter.update(&encrypted, &mut decrypted).unwrap();
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
fn empty_read_decrypt() {
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let encrypted: &[u8] = b"";
    let mut decrypted = [0u8; 1024];

    let mut decryptor = read::Decryptor::new(encrypted, cipher, &key, &iv).unwrap();
    let decrypted_bytes = decryptor.read(&mut decrypted[0..]).unwrap();
    assert_eq!(decrypted_bytes, 0);
}

#[test]
fn empty_write_decrypt() {
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let encrypted = Vec::new();
    let encryptor = write::Decryptor::new(encrypted, cipher, &key, &iv).unwrap();
    encryptor.finish().unwrap();
}

#[test]
fn finish_empty_write_encrypt() {
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let encrypted = Vec::new();
    let encryptor = write::Encryptor::new(encrypted, cipher, &key, &iv).unwrap();
    encryptor.finish().unwrap();
}

fn init_secrets() -> (Cipher, [u8; 128/8], [u8; 128/8]) {
    let cipher = Cipher::aes_128_cbc();
    let key: [u8; 128 / 8] = rand::random();
    let iv: [u8; 128 / 8] = rand::random();

    (cipher, key, iv)
}

#[test]
fn finish_empty_read_encrypt() {
    let (cipher, key, iv) = init_secrets();

    let plaintext: &[u8] = b"";
    let encryptor = read::Encryptor::new(plaintext, cipher, &key, &iv).unwrap();
    encryptor.finish();
}

fn encrypt(plaintext: &[u8], cipher: Cipher, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cryptor = openssl::symm::Crypter::new(cipher, Mode::Encrypt, key, Some(iv))
        .expect("Failed to create OpenSSL encryptor!");
    let mut encrypted = Vec::new();
    encrypted.resize(plaintext.len() + cipher.block_size(), 0);
    let mut bytes_written = cryptor.update(plaintext, &mut encrypted)
        .expect("OpenSSL update for encryption failed!");
    bytes_written += cryptor.finalize(&mut encrypted[bytes_written..])
        .expect("OpenSSL finalization for encryption failed!");
    encrypted.truncate(bytes_written);
    encrypted
}

fn verify_transform(plaintext: &[u8], ciphertext: &[u8], cipher: Cipher, key: &[u8], iv: &[u8]) {
    let encrypted = encrypt(plaintext, cipher, &key, &iv);
    assert_eq!(ciphertext, encrypted.as_slice());
}

#[test]
fn read_encrypt_less_than_block() {
    let (cipher, key, iv) = init_secrets();

    let plaintext: &[u8] = b"one";
    let mut encryptor = read::Encryptor::new(plaintext, cipher, &key, &iv).unwrap();
    let mut encrypted = Vec::new();

    match encryptor.read_to_end(&mut encrypted) {
        Ok(16) => {},
        _ => panic!("Failed to read encrypted bytes!"),
    };
    drop(encryptor);

    // It's OK not to drop the encryptor before verifying since we necessarily read until the
    // source is exhausted.
    verify_transform(plaintext, &encrypted, cipher, &key, &iv);
}


#[test]
fn read_decrypt_less_than_block() {
    let (cipher, key, iv) = init_secrets();

    let plaintext: &[u8] = b"one";
    let encrypted = encrypt(plaintext, cipher, &key, &iv);
    let mut decryptor = read::Encryptor::new(plaintext, cipher, &key, &iv).unwrap();
    let mut decrypted = Vec::new();

    match decryptor.read_to_end(&mut decrypted) {
        Ok(16) => {},
        _ => panic!("Failed to read encrypted bytes!"),
    };

    // It's OK not to drop the decryptor before verifying since we necessarily read until the
    // source is exhausted.
    verify_transform(plaintext, &encrypted, cipher, &key, &iv);
}

#[test]
fn write_encrypt_less_than_block() {
    let (cipher, key, iv) = init_secrets();

    let plaintext: &[u8] = b"hello";
    let ciphertext = Vec::new();
    let mut encryptor = write::Encryptor::new(ciphertext, cipher, &key, &iv).unwrap();

    encryptor.write_all(plaintext)
        .expect("Failed to write all bytes to encryptor!");

    // Here we must ensure the encryptor is flushed/dropped before comparing the results.
    // Merely dropping the encryptor leaves us unable to access the results, so call
    // `.finish()` instead.
    let ciphertext = encryptor.finish()
        .expect("Failed to finish encryptor!");
    verify_transform(&plaintext, &ciphertext, cipher, &key, &iv);
}

#[test]
fn write_decrypt_less_than_block() {
    let (cipher, key, iv) = init_secrets();

    let plaintext: &[u8] = b"hello";
    let encrypted = encrypt(plaintext, cipher, &key, &iv);
    let decrypted = Vec::new();
    let mut decryptor = write::Decryptor::new(decrypted, cipher, &key, &iv).unwrap();

    decryptor.write_all(&encrypted)
        .expect("Failed to write all bytes to decryptor!");

    // Here we must ensure the encryptor is flushed/dropped before comparing the results.
    // Merely dropping the encryptor leaves us unable to access the results, so call
    // `.finish()` instead.
    let decrypted = decryptor.finish()
        .expect("Failed to finish decryptor!");
    assert_eq!(plaintext, decrypted.as_slice(), "Mismatch of original and decrypted contents!");
}
