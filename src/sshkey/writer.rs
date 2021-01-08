use byteorder::{BigEndian, ByteOrder};

/// A `Writer` is used for encoding a key in OpenSSH compatible format.
#[derive(Debug)]
pub struct Writer {
    inner: Vec<u8>,
}

impl Writer {
    /// Creates a new `Writer` instance.
    ///
    /// # Example
    /// ```rust
    /// let writer = sshkeys::Writer::new();
    /// ```
    pub fn new() -> Writer {
        Writer { inner: Vec::new() }
    }

    /// Writes a byte sequence to the underlying vector.
    /// The value is represented as a the byte sequence length,
    /// followed by the actual byte sequence.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let mut writer = sshkeys::Writer::new();
    /// writer.write_bytes(&[0, 0, 0, 42]);
    /// let bytes = writer.into_bytes();
    /// assert_eq!(bytes, vec![0, 0, 0, 4, 0, 0, 0, 42]);
    /// ```
    pub fn write_bytes(&mut self, val: &[u8]) {
        let size = val.len() as u32;
        let mut buf = vec![0; 4];
        BigEndian::write_u32(&mut buf, size);
        self.inner.append(&mut buf);
        self.inner.extend_from_slice(&val);
    }

    /// Writes a `string` value to the underlying byte sequence.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let mut writer = sshkeys::Writer::new();
    /// writer.write_string("a test string");
    /// let bytes = writer.into_bytes();
    /// assert_eq!(bytes, [0, 0, 0, 13, 97, 32, 116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103]);
    /// ```
    pub fn write_string(&mut self, val: &str) {
        self.write_bytes(val.as_bytes());
    }

    /// Writes an `mpint` value to the underlying byte sequence.
    /// If the MSB bit of the first byte is set then the number is
    /// negative, otherwise it is positive.
    /// Positive numbers must be preceeded by a leading zero byte according to RFC 4251, section 5.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let mut writer = sshkeys::Writer::new();
    /// writer.write_mpint(&[1, 0, 1]);
    /// let bytes = writer.into_bytes();
    /// assert_eq!(bytes, [0, 0, 0, 3, 1, 0, 1]);
    /// ```
    pub fn write_mpint(&mut self, val: &[u8]) {
        let mut bytes = val.to_vec();

        // If most significant bit is set then prepend a zero byte to
        // avoid interpretation as a negative number.
        if val.get(0).unwrap_or(&0) & 0x80 != 0 {
            bytes.insert(0, 0);
        }

        self.write_bytes(&bytes);
    }

    /// Converts the `Writer` into a byte sequence.
    /// This consumes the underlying byte sequence used by the `Writer`.
    ///
    /// # Example
    /// ```rust
    /// let mut writer = sshkeys::Writer::new();
    /// writer.write_string("some data");
    /// let bytes = writer.into_bytes();
    /// assert_eq!(bytes, [0, 0, 0, 9, 115, 111, 109, 101, 32, 100, 97, 116, 97]);
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }
}
