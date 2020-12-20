rust-pop3
================
POP3 Client for Rust

This client has SSL support. SSL is configured using an SSLContext that is passed into the connect method of a POP3Stream. If no SSL
support is wanted just pass in None. The library rust-openssl is used to support SSL for this project.

[![Number of Crate Downloads](https://img.shields.io/crates/d/pop3.svg)](https://crates.io/crates/pop3)
[![Crate Version](https://img.shields.io/crates/v/pop3.svg)](https://crates.io/crates/pop3)
[![Crate License](https://img.shields.io/crates/l/pop3.svg)](https://crates.io/crates/pop3)
[![Travis CI Build Status](https://travis-ci.org/mattnenterprise/rust-pop3.svg)](https://travis-ci.org/mattnenterprise/rust-pop3)
[![Coverage Status](https://coveralls.io/repos/github/mattnenterprise/rust-pop3/badge.svg?branch=master)](https://coveralls.io/github/mattnenterprise/rust-pop3?branch=master)

[Documentation](https://docs.rs/pop3/)

### Usage
```rust
extern crate pop3;
extern crate openssl;

use openssl::ssl::{SslConnector, SslMethod};
use pop3::POP3Stream;
use pop3::POP3Result::{POP3Stat, POP3List, POP3Message, POP3Err};

fn main() {
	let mut gmail_socket = match POP3Stream::connect(("pop.gmail.com", 995), Some(SslConnector::builder(SslMethod::tls()).unwrap().build()),"pop.gmail.com") {
        Ok(s) => s,
        Err(e) => panic!("{}", e)
    };

    let res = gmail_socket.login("username", "password");
    match res {
        POP3Err => println!("Err logging in"),
        _ => (),
    }

    let stat = gmail_socket.stat();
    match stat {
    	POP3Stat {num_email,
				  mailbox_size} => println!("num_email: {},  mailbox_size:{}", num_email, mailbox_size),
		_ => println!("Err for stat"),
    }

    let list_all = gmail_socket.list(None);
    match list_all {
        POP3List {emails_metadata} => {
            for i in emails_metadata.iter() {
                println!("message_id: {},  message_size: {}", i.message_id, i.message_size);
            }
        },
        _ => println!("Err for list_all"),
    }

    let message_25 = gmail_socket.retr(25);
    match message_25 {
        POP3Message{raw} => {
            for i in raw.iter() {
                println!("{}", i);
            }
        },
        _ => println!("Error for message_25"),
    }

    gmail_socket.quit();
}
```

### License

MIT
