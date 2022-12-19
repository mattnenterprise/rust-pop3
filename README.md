# rust-pop3

**Forked https://github.com/mattnenterprise/rust-pop3**

POP3 Client for Rust

This client has SSL support. SSL is configured using an SSLContext that is passed into the connect method of a POP3Stream. If no SSL
support is wanted just pass in None. The library was updated to use native-tls to support SSL connectivity for this project.

[![Number of Crate Downloads](https://img.shields.io/crates/d/rs-pop3.svg)](https://crates.io/crates/rs-pop3)
[![Crate Version](https://img.shields.io/crates/v/rs-pop3.svg)](https://crates.io/crates/rs-pop3)
[![Crate License](https://img.shields.io/crates/l/rs-pop3.svg)](https://crates.io/crates/rs-pop3)
[![Coverage Status](https://coveralls.io/repos/github/k8scat/rust-pop3/badge.svg?branch=master)](https://coveralls.io/github/k8scat/rust-pop3?branch=master)

[Documentation](https://docs.rs/rs_pop3/)

## Usage

`Cargo.toml`

```toml
[dependencies]
native-tls = "0.2.11"
rs-pop3 = "1.0.8"
```

`main.rs`

```rust
use native_tls::{TlsConnector,TlsStream,TlsConnectorBuilder};
use rs_pop3::POP3Stream;
use rs_pop3::POP3Result::{POP3Stat, POP3List, POP3Message, POP3Err};

fn main() {
    	let mut gmail_socket = match POP3Stream::connect(("pop.gmail.com", 995), Some(TlsConnector::new().unwrap()),"pop.gmail.com") {
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

## License

[MIT](https://github.com/k8scat/rust-pop3/blob/master/LICENSE)
