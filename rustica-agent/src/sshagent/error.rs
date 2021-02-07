use std::{io};

pub type ParsingError<T> = Result<T, Error>;
pub type WrittingError<T> = Result<T, Error>;
pub type HandleResult<T> = Result<T, Error>;


#[derive(Debug)]
pub struct Error {
    pub details: String,
}

impl Error {
    fn new<T: AsRef<str>>(details: T) -> Error {
        Error {
            details: String::from(details.as_ref()),
        }
    }
}


impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(format!("IOError: {}", err))
    }
}


impl<'a> From<&'a str> for Error {
	fn from(err: &'a str) -> Error {
	    Error::new(err)
    }
}