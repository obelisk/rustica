use super::error::{Error, ErrorKind, Result};

use byteorder::{BigEndian, ByteOrder};

/// A `Reader` is used for reading from a byte sequence
/// representing an encoded OpenSSH public key or certificate.
#[derive(Debug)]
pub struct Reader<'a> {
    inner: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new `Reader` instance from the given byte sequence.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// ```
    pub fn new<T: ?Sized + AsRef<[u8]>>(inner: &T) -> Reader {
        Reader {
            inner: inner.as_ref(),
            offset: 0,
        }
    }

    /// Sets the `Reader` current offset to a given position.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// reader.set_offset(0);
    /// let num_42_again = reader.read_u32().unwrap();
    /// assert_eq!(num_42_again, 42);
    /// ```
    pub fn set_offset(&mut self, offset: usize) -> Result<()> {
        self.offset = offset;

        Ok(())
    }

    /// Gets the `Reader` current offset.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// assert_eq!(reader.get_offset(), 4);
    /// ```
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Reads a byte buffer from the wrapped byte sequence and
    /// returns it as a `Vec<u8>`.
    /// The buffer is represented by it's length as `u32` value
    /// followed by the actual bytes to read.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let bytes = reader.read_bytes().unwrap();
    /// assert_eq!(bytes, [97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103]);
    /// ```
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];

        if slice.len() < 4 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        let size = BigEndian::read_u32(&slice[..4]) as usize;

        if slice.len() < size + 4 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        self.offset += size + 4;
        let result = slice[4..size + 4].to_vec();

        Ok(result)
    }

    /// Reads `len` bytes from the wrapped buffer as raw data
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let bytes = reader.read_raw_bytes(4).unwrap();
    /// assert_eq!(bytes, [0, 0, 0, 13]);
    /// ```
    pub fn read_raw_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        if len + self.offset > self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];

        self.offset += len;
        let result = slice[..len].to_vec();

        Ok(result)
    }

    /// Reads an `mpint` value from the wrapped byte sequence.
    ///
    /// Drops the leading byte if it's value is zero according to the RFC 4251, section 5.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 3, 1, 0, 1];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let mpint = reader.read_mpint().unwrap();
    /// assert_eq!(mpint, [1, 0, 1]);
    /// ```
    pub fn read_mpint(&mut self) -> Result<Vec<u8>> {
        let bytes = self.read_bytes()?;

        if bytes[0] == 0 {
            return Ok(bytes[1..].to_vec());
        }

        Ok(bytes)
    }

    /// Reads a `string` value from the wrapped byte sequence and
    /// returns it as a `String`. The value that we read should be a valid UTF-8.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let result = reader.read_string().unwrap();
    /// assert_eq!(result, "a test string");
    /// ```
    pub fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        let result = String::from_utf8(bytes)?;

        Ok(result)
    }

    /// Reads an `u32` value from the wrapped byte sequence and returns it.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 42];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let num = reader.read_u32().unwrap();
    /// assert_eq!(num, 42);
    /// ```
    pub fn read_u32(&mut self) -> Result<u32> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 4 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        self.offset += 4;
        let value = BigEndian::read_u32(&slice[..4]);

        Ok(value)
    }

    /// Reads an `u64` value from the wrapped byte sequence and returns it.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 0, 0, 0, 0, 42];
    /// let mut reader = sshkeys::Reader::new(&data);
    /// let num = reader.read_u64().unwrap();
    /// assert_eq!(num, 42);
    /// ```
    pub fn read_u64(&mut self) -> Result<u64> {
        if self.offset >= self.inner.len() {
            return Err(Error::with_kind(ErrorKind::UnexpectedEof));
        }

        let slice = &self.inner[self.offset..];
        if slice.len() < 8 {
            return Err(Error::with_kind(ErrorKind::InvalidFormat));
        }

        self.offset += 8;
        let value = BigEndian::read_u64(&slice[..8]);

        Ok(value)
    }
}
