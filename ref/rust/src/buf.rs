//! Growable byte buffer with little-endian 9P wire primitives.

use crate::types::Qid;
use std::io;

/// A buffer for marshalling/unmarshalling 9P2000.N messages.
pub struct Buf {
    data: Vec<u8>,
    pos: usize,
}

impl Buf {
    /// Create a new write buffer.
    pub fn new(cap: usize) -> Self {
        Self { data: Vec::with_capacity(cap), pos: 0 }
    }

    /// Wrap existing data for reading.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the written data.
    pub fn as_bytes(&self) -> &[u8] { &self.data }

    /// Returns the number of bytes written.
    pub fn len(&self) -> usize { self.data.len() }

    /// Resets the buffer.
    pub fn reset(&mut self) { self.data.clear(); self.pos = 0; }

    fn remaining(&self) -> usize { self.data.len() - self.pos }

    // --- Write ---

    pub fn put_u8(&mut self, v: u8) { self.data.push(v); }

    pub fn put_u16(&mut self, v: u16) { self.data.extend_from_slice(&v.to_le_bytes()); }

    pub fn put_u32(&mut self, v: u32) { self.data.extend_from_slice(&v.to_le_bytes()); }

    pub fn put_u64(&mut self, v: u64) { self.data.extend_from_slice(&v.to_le_bytes()); }

    pub fn put_str(&mut self, s: &str) {
        self.put_u16(s.len() as u16);
        self.data.extend_from_slice(s.as_bytes());
    }

    pub fn put_data(&mut self, d: &[u8]) {
        self.put_u32(d.len() as u32);
        self.data.extend_from_slice(d);
    }

    pub fn put_bytes(&mut self, d: &[u8]) { self.data.extend_from_slice(d); }

    pub fn put_qid(&mut self, q: &Qid) {
        self.put_u8(q.qtype);
        self.put_u32(q.version);
        self.put_u64(q.path);
    }

    /// Patch a u32 at a specific offset (for size field).
    pub fn patch_u32(&mut self, off: usize, v: u32) {
        self.data[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // --- Read ---

    pub fn get_u8(&mut self) -> io::Result<u8> {
        if self.remaining() < 1 { return Err(eof()); }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn get_u16(&mut self) -> io::Result<u16> {
        if self.remaining() < 2 { return Err(eof()); }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn get_u32(&mut self) -> io::Result<u32> {
        if self.remaining() < 4 { return Err(eof()); }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn get_u64(&mut self) -> io::Result<u64> {
        if self.remaining() < 8 { return Err(eof()); }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn get_str(&mut self) -> io::Result<String> {
        let slen = self.get_u16()? as usize;
        if self.remaining() < slen { return Err(eof()); }
        let s = String::from_utf8_lossy(&self.data[self.pos..self.pos + slen]).into_owned();
        self.pos += slen;
        Ok(s)
    }

    pub fn get_data(&mut self) -> io::Result<Vec<u8>> {
        let n = self.get_u32()? as usize;
        if self.remaining() < n { return Err(eof()); }
        let d = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(d)
    }

    pub fn get_fixed(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if self.remaining() < n { return Err(eof()); }
        let d = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(d)
    }

    pub fn get_qid(&mut self) -> io::Result<Qid> {
        Ok(Qid {
            qtype: self.get_u8()?,
            version: self.get_u32()?,
            path: self.get_u64()?,
        })
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "p9n: short buffer")
}
