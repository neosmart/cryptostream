//! This is a test for https://github.com/neosmart/cryptostream/issues/9
//! which reported a mismatch after an encrypt/decrypt cycle with a large
//! (4096-byte) buffer size. It turned out to be a user error, caused by
//! not using `write_all()`.

#![allow(unused)]

use crate::bufread;
use crate::read::Decryptor as ReadDecryptor;
use crate::read::Encryptor as ReadEncryptor;
use crate::write::Encryptor as WriteEncryptor;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Fill;
use size::Size;
use std::cmp::Ordering;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::io::SeekFrom;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;

/// Creates a file at the indicated path `path` and fills it with `size` bytes of random data.
fn create_rand_file(path: &Path, size: usize) {
    let mut buffer = [0u8; 1024];
    let mut remainder = size as usize;
    let mut rng = rand::thread_rng();
    let mut dst = File::options()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();

    while remainder > 0 {
        buffer.try_fill(&mut rng).unwrap();
        let write_count = remainder.min(buffer.len());
        dst.write_all(&buffer[..write_count]).unwrap();
        remainder = remainder.checked_sub(write_count).unwrap();
    }
}

struct OnDrop<F>
where
    F: Fn(),
{
    callback: F,
}

impl<F> OnDrop<F>
where
    F: Fn(),
{
    pub fn new(f: F) -> Self {
        Self { callback: f }
    }
}

impl<F> Drop for OnDrop<F>
where
    F: Fn(),
{
    fn drop(&mut self) {
        (self.callback)()
    }
}

#[test]
fn large_buffer_encrypt_decrypt() {
    let cleanup = OnDrop::new(|| {
        for f in ["issue_9.src", "issue_9.enc", "issue_9.dec"] {
            let _ = std::fs::remove_file(Path::new(f));
        }
    });

    // Create a large source file
    let start = Instant::now();
    let src_path = Path::new("issue_9.src");
    let size = Size::from_mib(10);
    create_rand_file(&src_path, size.bytes() as usize);
    eprintln!("{} source file generated in {:?}", size, start.elapsed());

    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    key.try_fill(&mut rng);
    let mut iv = [0u8; 16];
    iv.try_fill(&mut rng);

    // Encrypt directly to the destination by reading from source and writing to a write::Encryptor
    let start = Instant::now();
    let mut src = File::open(&src_path).unwrap();
    let enc_path = Path::new("issue_9.enc");
    let mut enc = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&enc_path)
        .unwrap();
    let mut encryptor = WriteEncryptor::new(enc, Cipher::aes_128_cbc(), &key, &iv).unwrap();

    // Bug report alleges corruption happens with large read buffer size?
    let mut buffer = [0u8; 4096];

    loop {
        let read = src.read(&mut buffer).unwrap();
        encryptor.write_all(&buffer[..read]).unwrap();
        if read == 0 {
            break;
        }
    }

    // Finalize the encrypted stream
    encryptor.finish().unwrap();
    eprintln!("File encrypted in {:?}", start.elapsed());

    // Now decrypt the encrypted contents to a third file
    let start = Instant::now();
    let dec_path = Path::new("issue_9.dec");
    let mut dec = File::options()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&dec_path)
        .unwrap();
    let mut dec = BufWriter::new(dec);
    let mut enc = File::open(&enc_path).unwrap();
    let mut enc = BufReader::new(enc);
    // let mut decryptor = ReadDecryptor::new(enc, Cipher::aes_128_cbc(), &key, &iv).unwrap();
    let mut decryptor =
        crate::bufread::Decryptor::new(enc, Cipher::aes_128_cbc(), &key, &iv).unwrap();

    loop {
        let read = decryptor.read(&mut buffer).unwrap();
        dec.write_all(&buffer[..read]).unwrap();

        if read == 0 {
            break;
        }
    }

    dec.flush().unwrap();
    eprintln!("File decrypted in {:?}", start.elapsed());

    assert_files_are_equal(&src_path, &dec_path);
}

fn assert_files_are_equal(lhs: &Path, rhs: &Path) {
    let lhs_len = std::fs::metadata(&lhs).unwrap().len();
    let rhs_len = std::fs::metadata(&rhs).unwrap().len();
    assert_eq!(lhs_len, rhs_len, "Mismatch in file lengths!");

    let mut file1 = File::open(&lhs).unwrap();
    let mut file2 = File::open(&rhs).unwrap();

    let mut buff1 = [0u8; 4096];
    let mut buff2 = [0u8; 4096];
    let mut chunk_start = 0;
    loop {
        let read = file1.read(&mut buff1).unwrap();
        if read == 0 {
            break;
        }

        file2.read_exact(&mut buff2[..read]).unwrap();

        if buff1[..read].cmp(&buff2[..read]) != Ordering::Equal {
            for i in 0..read {
                if buff1[i] != buff2[i] {
                    panic!(
                        "Mismatch in file contents starting at {:x}",
                        chunk_start + i
                    );
                }
            }
        }

        chunk_start += read;
    }
}
