#![crate_name = "pop3"]
#![crate_type = "lib"]

#[macro_use]
extern crate lazy_static;

use regex::Regex;
use rustls::{ClientConfig, ClientSession, StreamOwned};
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::string::String;
use std::sync::Arc;
use webpki;
use POP3Command::{
    Dele, Greet, ListAll, ListOne, Noop, Pass, Quit, Retr, Rset, Stat, UidlAll, UidlOne, User,
};
use POP3StreamTypes::{Basic, Ssl};

lazy_static! {
    static ref ENDING_REGEX: Regex = Regex::new(r"^\.\r\n$").unwrap();
    static ref OK_REGEX: Regex = Regex::new(r"\+OK(.*)").unwrap();
    static ref ERR_REGEX: Regex = Regex::new(r"-ERR(.*)").unwrap();
    static ref STAT_REGEX: Regex = Regex::new(r"\+OK (\d+) (\d+)\r\n").unwrap();
    static ref MESSAGE_DATA_UIDL_ALL_REGEX: Regex =
        Regex::new(r"(\d+) ([\x21-\x7e]+)\r\n").unwrap();
    static ref MESSAGE_DATA_UIDL_ONE_REGEX: Regex =
        Regex::new(r"\+OK (\d+) ([\x21-\x7e]+)\r\n").unwrap();
    static ref MESSAGE_DATA_LIST_ALL_REGEX: Regex = Regex::new(r"(\d+) (\d+)\r\n").unwrap();
}

/// Wrapper for a regular TcpStream or a SslStream.
enum POP3StreamTypes {
    Basic(TcpStream),
    Ssl(StreamOwned<ClientSession, TcpStream>),
}

/// The stream to use for interfacing with the POP3 Server.
pub struct POP3Stream {
    stream: POP3StreamTypes,
    pub is_authenticated: bool,
}

/// List of POP3 Commands
#[derive(Clone)]
enum POP3Command {
    Greet,
    User,
    Pass,
    Stat,
    UidlAll,
    UidlOne,
    ListAll,
    ListOne,
    Retr,
    Dele,
    Noop,
    Rset,
    Quit,
}

impl POP3Stream {
    /// Creates a new POP3Stream.
    pub fn connect<A: ToSocketAddrs>(
        addr: A,
        ssl_context: Option<ClientConfig>,
        domain: &str,
    ) -> Result<POP3Stream> {
        let tcp_stream = TcpStream::connect(addr)?;

        let mut socket = match ssl_context {
            Some(context) => {
                let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();
                let sess = rustls::ClientSession::new(&Arc::new(context), dns_name);
                POP3Stream {
                    stream: Ssl(rustls::StreamOwned::new(sess, tcp_stream)),
                    is_authenticated: false,
                }
            }
            None => POP3Stream {
                stream: Basic(tcp_stream),
                is_authenticated: false,
            },
        };
        match socket.read_response(Greet) {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Failed to read greet response",
                ))
            }
        }
        Ok(socket)
    }

    fn write_str(&mut self, s: &str) -> Result<()> {
        match self.stream {
            Ssl(ref mut stream) => stream.write_fmt(format_args!("{}", s)),
            Basic(ref mut stream) => stream.write_fmt(format_args!("{}", s)),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.stream {
            Ssl(ref mut stream) => stream.read(buf),
            Basic(ref mut stream) => stream.read(buf),
        }
    }

    /// Login to the POP3 server.
    pub fn login(&mut self, username: &str, password: &str) -> POP3Result {
        let user_command = format!("USER {}\r\n", username);
        let pass_command = format!("PASS {}\r\n", password);
        //Send user command
        match self.write_str(&user_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }
        match self.read_response(User) {
            Ok(_) => {
                match self.write_str(&pass_command) {
                    Ok(_) => self.is_authenticated = true,
                    Err(_) => panic!("Error writing"),
                }
                match self.read_response(Pass) {
                    Ok(res) => match res.result {
                        Some(s) => s,
                        None => POP3Result::POP3Err,
                    },
                    Err(_) => panic!("Failure to use PASS"),
                }
            }
            Err(_) => panic!("Failure to use USER"),
        }
    }

    /// Gives the current number of messages in the mailbox and the total size in bytes of the mailbox.
    pub fn stat(&mut self) -> POP3Result {
        if !self.is_authenticated {
            panic!("login");
        }

        let stat_command = "STAT\r\n";
        match self.write_str(&stat_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }
        match self.read_response(Stat) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    pub fn uidl(&mut self, message_number: Option<i32>) -> POP3Result {
        if !self.is_authenticated {
            panic!("login");
        }

        let uidl_command = match message_number {
            Some(i) => format!("UIDL {}\r\n", i),
            None => format!("UIDL\r\n"),
        };
        let command_type = match message_number {
            Some(_) => UidlOne,
            None => UidlAll,
        };

        match self.write_str(&uidl_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(command_type) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    /// List displays a summary of messages where each message number is shown and the size of the message in bytes.
    pub fn list(&mut self, message_number: Option<i32>) -> POP3Result {
        if !self.is_authenticated {
            panic!("login");
        }

        let list_command = match message_number {
            Some(i) => format!("LIST {}\r\n", i),
            None => format!("LIST\r\n"),
        };
        let command_type = match message_number {
            Some(_) => ListOne,
            None => ListAll,
        };

        match self.write_str(&list_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(command_type) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    /// retrieves the message of the message id given.
    pub fn retr(&mut self, message_id: i32) -> POP3Result {
        if !self.is_authenticated {
            panic!("login");
        }

        let retr_command = format!("RETR {}\r\n", message_id);

        match self.write_str(&retr_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(Retr) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    /// Delete the message with the given message id.
    pub fn dele(&mut self, message_id: i32) -> POP3Result {
        if !self.is_authenticated {
            panic!("login");
        }

        let dele_command = format!("DELE {}\r\n", message_id);

        match self.write_str(&dele_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(Dele) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    /// This resets the session to its original state.
    pub fn rset(&mut self) -> POP3Result {
        if !self.is_authenticated {
            panic!("Not Logged In");
        }

        let retr_command = format!("RETR\r\n");

        match self.write_str(&retr_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(Rset) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    /// Quits the current session.
    pub fn quit(&mut self) -> POP3Result {
        let quit_command = "QUIT\r\n";

        match self.write_str(&quit_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(Quit) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => POP3Result::POP3Err,
        }
    }

    /// Doesn't do anything. This is usually just used to keep the connection open.
    pub fn noop(&mut self) -> POP3Result {
        if !self.is_authenticated {
            panic!("Not Logged In");
        }

        let noop_command = "noop\r\n";

        match self.write_str(noop_command) {
            Ok(_) => {}
            Err(_) => panic!("Error writing"),
        }

        match self.read_response(Noop) {
            Ok(res) => match res.result {
                Some(s) => s,
                None => POP3Result::POP3Err,
            },
            Err(_) => panic!("Error noop"),
        }
    }

    fn read_response(&mut self, command: POP3Command) -> Result<Box<POP3Response>> {
        let mut response = Box::new(POP3Response::new());
        //Carriage return
        let cr = 0x0d;
        //Line Feed
        let lf = 0x0a;
        let mut line_buffer: Vec<u8> = Vec::new();

        while !response.complete {
            while line_buffer.len() < 2
                || (line_buffer[line_buffer.len() - 1] != lf
                    && line_buffer[line_buffer.len() - 2] != cr)
            {
                let byte_buffer: &mut [u8] = &mut [0];
                match self.read(byte_buffer) {
                    Ok(_) => {}
                    Err(e) => println!("Error Reading!: {}", e),
                }
                line_buffer.push(byte_buffer[0]);
            }

            match String::from_utf8(line_buffer.clone()) {
                Ok(res) => {
                    response.add_line(res, command.clone());
                    line_buffer = Vec::new();
                }
                Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to read the response")),
            }
        }
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct POP3EmailMetadata {
    pub message_id: i32,
    pub message_size: i32,
}

#[derive(Clone, Debug)]
pub struct POP3EmailUidldata {
    pub message_id: i32,
    pub message_uid: String,
}

#[derive(Debug)]
pub enum POP3Result {
    POP3Ok,
    POP3Err,
    POP3Stat {
        num_email: i32,
        mailbox_size: i32,
    },
    POP3Uidl {
        emails_metadata: Vec<POP3EmailUidldata>,
    },
    POP3List {
        emails_metadata: Vec<POP3EmailMetadata>,
    },
    POP3Message {
        raw: Vec<String>,
    },
}

#[derive(Default)]
struct POP3Response {
    complete: bool,
    lines: Vec<String>,
    result: Option<POP3Result>,
}

impl POP3Response {
    fn new() -> POP3Response {
        POP3Response {
            complete: false,
            lines: Vec::new(),
            result: None,
        }
    }

    fn add_line(&mut self, line: String, command: POP3Command) {
        //We are retreiving status line
        if self.lines.len() == 0 {
            if OK_REGEX.is_match(&line) {
                self.lines.push(line);
                match command {
                    Greet | User | Pass | Quit | Dele | Rset => {
                        self.result = Some(POP3Result::POP3Ok);
                        self.complete = true;
                    }
                    Stat => {
                        self.complete = true;
                        self.parse_stat()
                    }
                    UidlAll => {}
                    UidlOne => {
                        self.complete = true;
                        self.parse_uidl_one();
                    }
                    ListAll => {}
                    ListOne => {
                        self.complete = true;
                        self.parse_list_one();
                    }
                    Retr => {}
                    _ => self.complete = true,
                }
            } else if ERR_REGEX.is_match(&line) {
                self.lines.push(line);
                self.result = Some(POP3Result::POP3Err);
                self.complete = true;
            }
        } else {
            if ENDING_REGEX.is_match(&line) {
                self.lines.push(line);
                match command {
                    UidlAll => {
                        self.complete = true;
                        self.parse_uidl_all();
                    }
                    ListAll => {
                        self.complete = true;
                        self.parse_list_all();
                    }
                    Retr => {
                        self.complete = true;
                        self.parse_message();
                    }
                    _ => self.complete = true,
                }
            } else {
                self.lines.push(line);
            }
        }
    }

    fn parse_stat(&mut self) {
        let caps = STAT_REGEX.captures(&self.lines[0]).unwrap();
        let num_emails = FromStr::from_str(caps.get(1).unwrap().as_str());
        let total_email_size = FromStr::from_str(caps.get(2).unwrap().as_str());
        self.result = Some(POP3Result::POP3Stat {
            num_email: num_emails.unwrap(),
            mailbox_size: total_email_size.unwrap(),
        })
    }

    fn parse_uidl_all(&mut self) {
        let mut metadata = Vec::new();

        for i in 1..self.lines.len() - 1 {
            let caps = MESSAGE_DATA_UIDL_ALL_REGEX
                .captures(&self.lines[i])
                .unwrap();
            let message_id = FromStr::from_str(caps.get(1).unwrap().as_str());
            let message_uid = caps.get(2).unwrap().as_str();

            metadata.push(POP3EmailUidldata {
                message_id: message_id.unwrap(),
                message_uid: message_uid.to_owned(),
            });
        }

        self.result = Some(POP3Result::POP3Uidl {
            emails_metadata: metadata,
        });
    }

    fn parse_uidl_one(&mut self) {
        let caps = MESSAGE_DATA_UIDL_ONE_REGEX
            .captures(&self.lines[0])
            .unwrap();
        let message_id = FromStr::from_str(caps.get(1).unwrap().as_str());
        let message_uid = caps.get(2).unwrap().as_str();

        self.result = Some(POP3Result::POP3Uidl {
            emails_metadata: vec![POP3EmailUidldata {
                message_id: message_id.unwrap(),
                message_uid: message_uid.to_owned(),
            }],
        });
    }

    fn parse_list_all(&mut self) {
        let mut metadata = Vec::new();

        for i in 1..self.lines.len() - 1 {
            let caps = MESSAGE_DATA_LIST_ALL_REGEX
                .captures(&self.lines[i])
                .unwrap();
            let message_id = FromStr::from_str(caps.get(1).unwrap().as_str());
            let message_size = FromStr::from_str(caps.get(2).unwrap().as_str());
            metadata.push(POP3EmailMetadata {
                message_id: message_id.unwrap(),
                message_size: message_size.unwrap(),
            });
        }
        self.result = Some(POP3Result::POP3List {
            emails_metadata: metadata,
        });
    }

    fn parse_list_one(&mut self) {
        let caps = STAT_REGEX.captures(&self.lines[0]).unwrap();
        let message_id = FromStr::from_str(caps.get(1).unwrap().as_str());
        let message_size = FromStr::from_str(caps.get(2).unwrap().as_str());
        self.result = Some(POP3Result::POP3List {
            emails_metadata: vec![POP3EmailMetadata {
                message_id: message_id.unwrap(),
                message_size: message_size.unwrap(),
            }],
        });
    }

    fn parse_message(&mut self) {
        let mut raw = Vec::new();
        for i in 1..self.lines.len() - 1 {
            raw.push(self.lines[i].clone());
        }
        self.result = Some(POP3Result::POP3Message { raw });
    }
}
