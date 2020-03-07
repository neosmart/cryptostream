//! This test is taken from the bug report in neosmart/cryptostream#7 and verifies that the issue
//! described in f64cf3a25496f880f73b5b75dbe79d04e57cb328 does not occur. The bug was caused by too
//! small a read buffer combined with a sufficiently large underlying source and a sufficiently
//! large destination buffer.

use crate::bufread;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io::{BufReader, Read};
use std::io;

struct RandomRead<R>
where
    R: Read,
{
    inner: R,
    rng: rand::rngs::ThreadRng,
}

impl<R: Read> RandomRead<R> {
    pub fn new(inner: R) -> Self {
        RandomRead {
            inner,
            rng: rand::thread_rng(),
        }
    }
}

impl<R: Read> Read for RandomRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use rand::prelude::*;

        let bufsize: usize = if buf.len() <= 5 {
            buf.len()
        } else {
            std::cmp::max(self.rng.gen::<usize>() % buf.len(), 5)
        };

        self.inner.read(&mut buf[..bufsize])
    }
}

#[test]
fn random_read() -> io::Result<()> {
    use openssl::rand::rand_bytes;

    let mut plaintext = vec![0u8; (0.4 * 1024. * 1024. + 5.) as usize];
    rand_bytes(&mut plaintext)?;
    let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

    let mut encrypted = vec![0u8; (0.4 * 1024. * 1024. + 128.) as usize];

    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;

    let resultsize = crypter.update(&plaintext, &mut encrypted)?;
    let resultsize2 = crypter.finalize(&mut encrypted[resultsize..])?;
    encrypted.truncate(resultsize + resultsize2);

    let bufreader = BufReader::new(RandomRead::new(&encrypted[..]));
    let mut decryptor = bufread::Decryptor::new(bufreader, cipher, key, iv)?;
    let mut test: Vec<u8> = Vec::new();
    decryptor.read_to_end(&mut test)?;
    drop(decryptor);

    assert_eq!(plaintext.len(), test.len());
    // Don't use assert_eq!(plaintext, test) here, as it will dump the entire contents
    // of the buffer to stdout on test failure!
    assert!(plaintext == test);

    Ok(())
}
