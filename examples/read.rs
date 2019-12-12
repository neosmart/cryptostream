use base64::decode;
use cryptostream::read;
use openssl::symm::Cipher;
use std::io::Read;

fn main() {
    let src: Vec<u8> =
        decode("vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdOVC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXvQ6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw==").unwrap();
    let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    // the source can be any object implementing `Read`. In this case, a simple &[u8] slice.
    let mut decryptor =
        read::Decryptor::new(src.as_slice(), Cipher::aes_128_cbc(), &key, &iv).unwrap();

    let mut decrypted = [0u8; 1024]; // a buffer to decrypt into
    let mut bytes_decrypted = 0;

    loop {
        // Just read from `Decryptor` as if it were any other `Read` impl. Decryption
        // is automatic.
        let read_count = decryptor.read(&mut decrypted[bytes_decrypted..]).unwrap();
        bytes_decrypted += read_count;
        if read_count == 0 {
            break;
        }
    }

    println!("{}", String::from_utf8_lossy(&decrypted));
}
