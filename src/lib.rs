#[macro_use]
extern crate log;
extern crate openssl;

pub mod bufread;
pub mod read;
pub mod write;

#[cfg(test)]
mod tests;
