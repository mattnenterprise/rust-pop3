extern crate pop3;

use pop3::POP3Result::{POP3List, POP3Message, POP3Stat};
use pop3::POP3Stream;
use rustls::ClientConfig;
use webpki_roots;

fn main() {
    let mut client_config = ClientConfig::new();
    client_config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let mut gmail_socket = match POP3Stream::connect(
        ("pop.gmail.com", 995),
        Some(client_config),
        "pop.gmail.com",
    ) {
        Ok(s) => s,
        Err(e) => panic!("{}", e),
    };

    let res = gmail_socket.login("username", "password");
    println!("{:#?}", res);

    let stat = gmail_socket.stat();

    match stat {
        POP3Stat {
            num_email,
            mailbox_size,
        } => println!("num_email: {},  mailbox_size:{}", num_email, mailbox_size),
        _ => println!("Err for stat"),
    }

    let list_all = gmail_socket.list(None);
    match list_all {
        POP3List { emails_metadata } => {
            for i in emails_metadata.iter() {
                println!(
                    "message_id: {},  message_size: {}",
                    i.message_id, i.message_size
                );
            }
        }
        _ => println!("Err for list_all"),
    }

    let message_25 = gmail_socket.retr(25);
    match message_25 {
        POP3Message { raw } => {
            for i in raw.iter() {
                println!("{}", i);
            }
        }
        _ => println!("Error for message_25"),
    }

    gmail_socket.quit();
}
