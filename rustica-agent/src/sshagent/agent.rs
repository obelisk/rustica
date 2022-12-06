use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::select;
use tokio::sync::mpsc::Receiver;

use super::protocol::Request;

use super::handler::SshAgentHandler;

use super::error::HandleResult;
pub struct Agent;

impl Agent {
    async fn handle_client<T: SshAgentHandler>(
        handler: &mut T,
        mut stream: UnixStream,
    ) -> HandleResult<()> {
        loop {
            let req = Request::read(&mut stream).await?;
            trace!("request: {:?}", req);
            let response = handler.handle_request(req).await?;
            trace!("handler: {:?}", response);
            response.write(&mut stream).await?;
        }
    }

    pub async fn run<T: SshAgentHandler + 'static>(handler: T, socket_path: String) {
        return Self::run_with_termination_channel(handler, socket_path, None).await;
    }

    pub async fn run_with_termination_channel<T: SshAgentHandler + 'static>(
        mut handler: T,
        socket_path: String,
        term_channel: Option<Receiver<()>>,
    ) {
        let listener = UnixListener::bind(socket_path).unwrap();

        if let Some(mut term_channel) = term_channel {
            loop {
                select! {
                    _ = term_channel.recv() => {
                        println!("Received termination request. Exiting...");
                        return
                    },
                    v = listener.accept() => {
                        match v {
                            Ok(stream) => {
                                debug!("Got connection from: {:?}", stream.1);
                                match Agent::handle_client(&mut handler, stream.0).await {
                                    Ok(_) => {}
                                    Err(e) => debug!("handler: {:?}", e),
                                }
                            }
                            Err(e) => {
                                // connection failed
                                println!("Encountered an error: {e}. Exiting...");
                                return;
                            }
                        }
                    },
                }
            }
        } else {
            loop {
                select! {
                    v = listener.accept() => {
                        match v {
                            Ok(stream) => {
                                match Agent::handle_client(&mut handler, stream.0).await {
                                    Ok(_) => {}
                                    Err(e) => debug!("handler: {:?}", e),
                                }
                            }
                            Err(e) => {
                                // connection failed
                                println!("Encountered an error: {e}. Exiting...");
                                return;
                            }
                        }
                    },
                }
            }
        }
    }
}
