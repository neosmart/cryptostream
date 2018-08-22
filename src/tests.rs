extern crate rand;
extern crate openssl;

use openssl::symm::Cipher;
use std::io::prelude::*;

use read;
use write;

#[test]
fn basic_read_encrypt() {
    let source: &[u8] = b"It was the best of times, it was the worst of times.";
    let key: [u8; 128/8] = rand::random();
    let iv: [u8; 128/8] = rand::random();
    let cipher = Cipher::aes_128_cbc();

    let mut encrypted = [0u8; 1024];
    let mut encryptor = read::Encryptor::new(source, cipher, &key, &iv);
    let mut total_bytes_read = 0;
    loop {
        let bytes_read = encryptor.read(&mut encrypted).expect("Encryptor read failure!");
        if bytes_read == 0 {
            break;
        }

        eprintln!("Read {} bytes out of encrypted stream", bytes_read);
        eprintln!("Bytes: {:?}", &encrypted[total_bytes_read..total_bytes_read + bytes_read]);
        total_bytes_read += bytes_read;
    }
}
