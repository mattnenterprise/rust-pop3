rust-pop3
================
POP3 Client for Rust

This client has SSL support. SSL is configured using an SSLContext that is passed into the connect method of a POP3Stream. If no SSL
support is wanted just pass in None. The library rust-openssl is used to support SSL for this project.


[![Build Status](https://travis-ci.org/mattnenterprise/rust-pop3.svg)](https://travis-ci.org/mattnenterprise/rust-pop3)

### Installation

Add pop3 via your `Cargo.toml`:
```toml
[dependencies.pop3]
git = "https://github.com/mattnenterprise/rust-pop3"
```

### Usage
```rs
extern crate pop3;
extern crate openssl;

use openssl::ssl::{SslContext, SslMethod};
use pop3::POP3Stream;
use pop3::POP3Result::{POP3Stat, POP3List, POP3Message};

fn main() {
    let mut gmail_socket = match POP3Stream::connect("pop.gmail.com", 995, Some(SslContext::new(SslMethod::Sslv23).unwrap())) {
        Ok(s) => s,
        Err(e) => panic!("{}", e)
    };

    gmail_socket.login("username", "password");

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