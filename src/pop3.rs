#![crate_name = "pop3"]
#![crate_type = "lib"]

extern crate openssl;
extern crate regex;

use POP3StreamTypes::{Basic, Ssl};
use POP3Command::{Greet, User, Pass, Stat, ListAll, ListOne, Retr, Dele, Noop, Rset, Quit};
use std::string::String;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::TcpStream;
use openssl::ssl::{SslContext, SslStream};
use std::str::FromStr;
use regex::Regex;

/// Wrapper for a regular TcpStream or a SslStream.
enum POP3StreamTypes {
	Basic(TcpStream),
	Ssl(SslStream<TcpStream>)
}

/// The stream to use for interfacing with the POP3 Server.
pub struct POP3Stream {
	stream: POP3StreamTypes,
	pub host: &'static str,
	pub port: u16,
	pub is_authenticated: bool
}

/// List of POP3 Commands
#[derive(Clone)]
enum POP3Command {
	Greet,
	User,
	Pass,
	Stat,
	ListAll,
	ListOne,
	Retr,
	Dele,
	Noop,
	Rset,
	Quit
}

impl POP3Stream {

	/// Creates a new POP3Stream.
	pub fn connect(host: &'static str, port: u16, ssl_context: Option<SslContext>) -> Result<POP3Stream> {
		let connect_string = format!("{}:{}", host, port);
		let tcp_stream = try!(TcpStream::connect(connect_string.as_slice()));
		let mut socket = match ssl_context {
			Some(context) => POP3Stream {stream: Ssl(SslStream::new(&context, tcp_stream).unwrap()), host: host, port: port, is_authenticated: false},
			None => POP3Stream {stream: Basic(tcp_stream), host: host, port: port, is_authenticated: false},
		};
		match socket.read_response(Greet) {
			Ok(_) => (),
			Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to read greet response", None))
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
		match self.write_str(user_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}
		match self.read_response(User) {
			Ok(_) => {
				match self.write_str(pass_command.as_slice()) {
					Ok(_) => self.is_authenticated = true,
					Err(_) => panic!("Error writing"),
				}
				match self.read_response(Pass) {
					Ok(_) => {
						POP3Result::POP3Ok
					},
					Err(_) => panic!("Failure to use PASS")
				}
			},
			Err(_) => panic!("Failure to use USER")
		}
	}

	/// Gives the current number of messages in the mailbox and the total size in bytes of the mailbox.
	pub fn stat(&mut self) -> POP3Result {
		if !self.is_authenticated {
			panic!("login");
		}

		let stat_command = "STAT\r\n";
		match self.write_str(stat_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}
		match self.read_response(Stat) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => POP3Result::POP3Err
		}
	}

	/// List displays a summary of messages where each message number is shown and the size of the message in bytes. 
	pub fn list(&mut self, message_number: Option<int>) -> POP3Result {
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

		match self.write_str(list_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}

		match self.read_response(command_type) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => POP3Result::POP3Err
		}
	}

	/// retrieves the message of the message id given.
	pub fn retr(&mut self, message_id: int) -> POP3Result {
		if !self.is_authenticated {
			panic!("login");
		}

		let retr_command = format!("RETR {}\r\n", message_id);

		match self.write_str(retr_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}

		match self.read_response(Retr) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => POP3Result::POP3Err
		}
	}

	/// Delete the message with the given message id.
	pub fn dele(&mut self, message_id: int) -> POP3Result {
		if !self.is_authenticated {
			panic!("login");
		}

		let dele_command = format!("DELE {}\r\n", message_id);
		
		match self.write_str(dele_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}

		match self.read_response(Dele) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => POP3Result::POP3Err
		}
	}

	/// This resets the session to its original state.
	pub fn rset(&mut self) -> POP3Result {
		if !self.is_authenticated {
			panic!("Not Logged In");
		}

		let retr_command = format!("RETR\r\n");

		match self.write_str(retr_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}

		match self.read_response(Rset) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => POP3Result::POP3Err
		}
	}

	/// Quits the current session.
	pub fn quit(&mut self) -> POP3Result {
		let quit_command = "QUIT\r\n";

		match self.write_str(quit_command.as_slice()) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}

		match self.read_response(Quit) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => POP3Result::POP3Err
		}
	}

	/// Doesn't do anything. This is usually just used to keep the connection open.
	pub fn noop(&mut self) -> POP3Result {
		if !self.is_authenticated {
			panic!("Not Logged In");
		}

		let noop_command = "noop\r\n";

		match self.write_str(noop_command) {
			Ok(_) => {},
			Err(_) => panic!("Error writing"),
		}

		match self.read_response(Noop) {
			Ok(res) => {
				match res.result {
					Some(s) => s,
					None => POP3Result::POP3Err
				}
			},
			Err(_) => panic!("Error noop")
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
			while line_buffer.len() < 2 || (line_buffer[line_buffer.len()-1] != lf && line_buffer[line_buffer.len()-2] != cr) {
				let byte_buffer: &mut [u8] = &mut [0];
				match self.read(byte_buffer) {
					Ok(_) => {},
					Err(_) => println!("Error Reading!"),
				}
				line_buffer.push(byte_buffer[0]);
			}

			match String::from_utf8(line_buffer.clone()) {
        		Ok(res) => {
          			response.add_line(res, command.clone());
            		line_buffer = Vec::new();
        		},
        		Err(e) => return Err(Error::new(ErrorKind::Other, "Failed to read the response", None))
      		}
		}
		Ok(response)
	}
}

pub struct POP3EmailMetadata {
	pub message_id: int,
	pub message_size: int
}

pub enum POP3Result {
	POP3Ok,
	POP3Err,
	POP3Stat {
		num_email: int,
		mailbox_size: int
	},
	POP3List {
		emails_metadata: Vec<POP3EmailMetadata>
	},
	POP3Message {
		raw: Vec<String>
	}
}

struct POP3Response {
	complete: bool,
	lines: Vec<String>,
	result: Option<POP3Result>
}

impl POP3Response {
	fn new() -> POP3Response {
		POP3Response {
			complete: false,
			lines: Vec::new(),
			result: None
		}
	}

	fn add_line(&mut self, line: String, command: POP3Command) {
		let l = line.clone();
		let ending_regex = match Regex::new(r"^\.\r\n$") {
			Ok(re) => re,
			Err(_) => panic!("Invalid Regex!!"),
		};
		
		//We are retreiving status line
		if self.lines.len() == 0 {
			let ok_regex = match Regex::new(r"\+OK(.*)") {
				Ok(re) => re,
				Err(_) => panic!("Invalid Regex!!"),
			};

			let err_regex = match Regex::new(r"-ERR(.*)") {
				Ok(re) => re,
				Err(_) => panic!("Invalid Regex!!"),
			};

			if ok_regex.is_match(l.as_slice()) {
				self.lines.push(l);
				match command {
					Greet|User|Pass|Quit|Dele|Rset => {
						self.result = Some(POP3Result::POP3Ok);
						self.complete = true;
					},
					Stat => {
						self.complete = true;
						self.parse_stat()
					},
					ListAll => {

					},
					ListOne => {
						self.complete = true;
						self.parse_list_one();
					},
					Retr => {

					},
					_ => self.complete = true,
				}
			} else if err_regex.is_match(l.as_slice()) {
				self.lines.push(l);
				self.result = Some(POP3Result::POP3Err);
				self.complete = true;
			}
		} else {
			if ending_regex.is_match(l.as_slice()) {
				self.lines.push(l);
				match command {
					ListAll => {
						self.complete = true;
						self.parse_list_all();
					},
					Retr => {
						self.complete = true;
						self.parse_message();
					},
					_ => self.complete = true,
				}
			} else {
				self.lines.push(l);
			}
		}
	}

	fn parse_stat(&mut self) {
		let stat_regex = match Regex::new(r"\+OK (\d+) (\d+)\r\n") {
			Ok(re) => re,
			Err(_) => panic!("Invalid Regex!!"),
		};
		let caps = stat_regex.captures(self.lines[0].as_slice()).unwrap();
		let num_emails = FromStr::from_str(caps.at(1).unwrap());
		let total_email_size = FromStr::from_str(caps.at(2).unwrap());
		self.result = Some(POP3Result::POP3Stat {
			num_email: num_emails.unwrap(),
			mailbox_size: total_email_size.unwrap()
		})
	}

	fn parse_list_all(&mut self) {
		let message_data_regex = match Regex::new(r"(\d+) (\d+)\r\n") {
			Ok(re) => re,
			Err(_) => panic!("Invalid Regex!!"),
		};
		let mut metadata = Vec::new();

		for i in range(1, self.lines.len()-1) {
			let caps = message_data_regex.captures(self.lines[i].as_slice()).unwrap();
			let message_id = FromStr::from_str(caps.at(1).unwrap());
			let message_size = FromStr::from_str(caps.at(2).unwrap());
			metadata.push(POP3EmailMetadata{ message_id: message_id.unwrap(), message_size: message_size.unwrap()});
		}
		self.result = Some(POP3Result::POP3List {
			emails_metadata: metadata
		});
	}

	fn parse_list_one(&mut self) {
		let stat_regex = match Regex::new(r"\+OK (\d+) (\d+)\r\n") {
			Ok(re) => re,
			Err(_) => panic!("Invalid Regex!!"),
		};
		let caps = stat_regex.captures(self.lines[0].as_slice()).unwrap();
		let message_id = FromStr::from_str(caps.at(1).unwrap());
		let message_size = FromStr::from_str(caps.at(2).unwrap());
		self.result = Some(POP3Result::POP3List {
			emails_metadata: vec![POP3EmailMetadata{ message_id: message_id.unwrap(), message_size: message_size.unwrap()}]
		});
	}

	fn parse_message(&mut self) {
		let mut raw = Vec::new();
		for i in range(1, self.lines.len()-1) {
			raw.push(String::from_str(self.lines[i].as_slice()));
		}
		self.result = Some(POP3Result::POP3Message{
			raw: raw
		});
	}
}