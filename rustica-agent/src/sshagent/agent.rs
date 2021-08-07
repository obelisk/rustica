use std::thread;
use std::sync::Arc;
use std::sync::Mutex;

use std::os::unix::net::{UnixListener, UnixStream};

use super::protocol::Request;

use super::handler::SshAgentHandler;

use super::error::HandleResult;
pub struct Agent;

impl Agent {
	fn handle_client<T: SshAgentHandler>(handler: Arc<Mutex<T>>, mut stream: UnixStream) -> HandleResult<()> {
		debug!("handling new connection");
		loop {
			let req = Request::read(&mut stream)?;
			trace!("request: {:?}", req);
			let response = handler.lock().unwrap().handle_request(req)?;
			trace!("handler: {:?}", response);
			response.write(&mut stream)?;
		}
	}

	pub fn run<T:SshAgentHandler + 'static>(handler: T, listener: UnixListener) {
		let arc_handler = Arc::new(Mutex::new(handler));
		// accept the connections and spawn a new thread for each one 
		for stream in listener.incoming() {
			match stream {
				Ok(stream) => {
					let ref_handler = arc_handler.clone();
					thread::spawn( ||{
						match Agent::handle_client(ref_handler, stream){
							Ok(_) => {},
							Err(e) => debug!("handler: {:?}", e),
						}
					});
				}
				Err(_) => {
					// connection failed
					break;
				}
			}
		}
	}
}