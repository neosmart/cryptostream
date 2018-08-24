# Rust Cryptostream Crate

`cryptostream` provides a rust equivalent to the [.NET
Cryptostream](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptostream)
class, providing an efficient and easy solution to on-the-fly encryption or decryption of existing
`Read` or `Write` resources. Cryptography is provided via [rust-openssl](https://github.com/sfackler/rust-openssl)
and is fully configurable.

## Design

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

## `Read` vs `Write` cryptostreams

The difference between the `Read` and `Write` variants of `cryptostream` are perhaps best
illustrated by example. In both of the following examples, we will be decrypting ciphertext, however
in one case we need to use `read::Decryptor` and in the other `write::Decryptor`.

In the first case, we have a `Read` source which contains the bytes we need to decrypt, and we wish
to obtain the equivalent plaintext in memory to later perform some operation with in its decoded
state:

```rust
let src: Vec<u8> =
	decode("vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdOVC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXvQ6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw==").unwrap();
let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

// the source can be any object implementing `Read`. In this case, a simple &[u8] slice.
let mut decryptor = read::Decryptor::new(src.as_slice(),
										 Cipher::aes_128_cbc(),
										 &key, &iv).unwrap();

let mut decrypted = [0u8; 1024]; // a buffer to decrypt into
let mut bytes_decrypted = 0;

loop {
	// Just read from the `Decryptor` as if it were any other `Read` impl.
	// Decryption is automatic.
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
let src: Vec<u8> =
	decode("vuU+0SXFWQLu8vl/o1WzmPCmf7x/O6ToGQ162Aq2CHxcnc/ax/Q8nTbRlNn0OSPrFuE3yDdOVC35RmwtUIlxKIkWbnxJpRF5yRJvVByQgWX1qLW8DfMjRp7gVaFNv4qr7G65M6hbSx6hGJXvQ6s1GiFwi91q0V17DI79yVrINHCXdBnUOqeLGfJ05Edu+39EQNYn4dky7VdgTP2VYZE7Vw==").unwrap();
let key: Vec<_> = decode("kjtbxCPw3XPFThb3mKmzfg==").unwrap();
let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

// the destination can be any object implementing `Write`. In this case, a Vec<u8>.
let mut decrypted = Vec::new();
{
	let mut decryptor = write::Decryptor::new(&mut decrypted,
											  Cipher::aes_128_cbc(),
											  &key, &iv).unwrap();

	let mut bytes_decrypted = 0;

	while bytes_decrypted != src.len() {
		// Just write encrypted ciphertext to the `Decryptor` instance as if it were any
		// other `Write` impl. Decryption is automatic.
		let write_count = decryptor.write(&src[bytes_decrypted..]).unwrap();
		bytes_decrypted += write_count;
	}
}

println!("{}", String::from_utf8_lossy(&decrypted));
```
