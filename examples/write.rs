use base64::decode;
use cryptostream::write;
use cryptostream::Cipher;
use std::io::Write;

fn main() {
    let src: Vec<u8> =
        decode("vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdOVC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXvQ6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw==").unwrap();
    let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    // the destination can be any object implementing `Write`. In this case, a Vec<u8>.
    let mut decrypted = Vec::new();
    {
        let mut decryptor =
            write::Decryptor::new(&mut decrypted, Cipher::aes_128_cbc(), &key, &iv).unwrap();

        let mut bytes_decrypted = 0;

        while bytes_decrypted != src.len() {
            // Just write encrypted ciphertext to the `Decryptor` instance as if it were any
            // other `Write` impl. Decryption is automatic.
            let write_count = decryptor.write(&src[bytes_decrypted..]).unwrap();
            bytes_decrypted += write_count;
        }
    }

    println!("{}", String::from_utf8_lossy(&decrypted));
}
