//! Reading the tar streams that come from the guest: its output disk and the
//! upper.tar copied from it.
//!
//! The tar crate splits pax records at newlines, but xattr values (such as
//! trusted.overlay.origin, which holds the lower filesystem's UUID) can hold
//! any byte. This reader parses ustar headers and pax records itself, every
//! record by its length. It accepts what GNU tar writes with --format=posix
//! (which --xattrs implies) and what run::read_output writes, and rejects what
//! it would otherwise misread: GNU sparse members, GNU long names and global
//! pax headers. Malformed input is an error, never a panic.

use std::io::{self, Read};

use tar::EntryType;

/// The (key, value) records of a pax extended header, in order.
pub type Records = Vec<(Vec<u8>, Vec<u8>)>;

const BLOCK: usize = 512;
/// More than any pax header GNU tar writes for one member: a path of PATH_MAX
/// bytes and xattrs of XATTR_LIST_MAX (64 KiB).
const MAX_PAX_SIZE: u64 = 1 << 20;
const USTAR_MAGIC: &[u8] = b"ustar\0";

/// A member's header, with the pax records before it applied.
#[derive(Debug)]
pub struct Member {
    pub name: Vec<u8>,
    pub kind: EntryType,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    /// The length of the member's data in the stream.
    pub size: u64,
    pub link_name: Vec<u8>,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub device: (u32, u32),
    pub records: Records,
}

impl Member {
    /// Whether the data is file content (tarfile's REGULAR_TYPES without GNU sparse).
    pub fn is_regular(&self) -> bool {
        matches!(self.kind, EntryType::Regular | EntryType::Continuous)
    }
}

pub struct Reader<R: Read> {
    input: R,
    /// What is left of the current member's data, and the padding after it.
    remaining: u64,
    padding: u64,
    ended: bool,
}

/// The data of the member that `Reader::next_member` returned last.
pub struct Data<'a, R: Read>(&'a mut Reader<R>);

impl<R: Read> Read for Data<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let reader = &mut *self.0;
        if reader.remaining == 0 {
            return Ok(0);
        }
        let limit = buffer.len().min(usize::try_from(reader.remaining).unwrap_or(usize::MAX));
        let length = reader.input.read(&mut buffer[..limit])?;
        if length == 0 && limit > 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the tar stream ends inside a member"));
        }
        reader.remaining -= length as u64;
        Ok(length)
    }
}

impl<R: Read> Reader<R> {
    pub fn new(input: R) -> Reader<R> {
        Reader { input, remaining: 0, padding: 0, ended: false }
    }

    /// The next member and its data, or None at the end of the archive (a
    /// zero block, or the end of the stream between members).
    pub fn next_member(&mut self) -> Result<Option<(Member, Data<'_, R>)>, String> {
        let mut records = None;
        loop {
            self.skip_rest()?;
            if self.ended {
                return Ok(None);
            }
            let Some(block) = self.header_block()? else {
                self.ended = true;
                return match records {
                    Some(_) => Err("the archive ends after a pax extended header".to_string()),
                    None => Ok(None),
                };
            };
            let header = Header::parse(&block)?;
            self.start_data(header.size);
            match header.typeflag {
                b'x' if records.is_some() => return Err("two pax extended headers in a row".to_string()),
                b'x' if header.size > MAX_PAX_SIZE => {
                    return Err(format!("a pax extended header of {} bytes is too large", header.size));
                }
                b'x' => {
                    let mut payload = Vec::new();
                    Data(self).read_to_end(&mut payload).map_err(|error| error.to_string())?;
                    records = Some(pax_records(&payload)?);
                }
                b'g' => return Err("global pax headers are not supported".to_string()),
                b'S' => return Err("GNU sparse members are not supported".to_string()),
                b'L' | b'K' => return Err("GNU long names are not supported".to_string()),
                _ => {
                    let member = header.member(records.unwrap_or_default())?;
                    self.start_data(member.size);
                    return Ok(Some((member, Data(self))));
                }
            }
        }
    }

    /// Expect `size` bytes of data, padded to a whole block.
    fn start_data(&mut self, size: u64) {
        self.remaining = size;
        self.padding = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
    }

    /// Skip what is left of the current member.
    fn skip_rest(&mut self) -> Result<(), String> {
        for length in [self.remaining, self.padding] {
            let skipped = io::copy(&mut (&mut self.input).take(length), &mut io::sink()).map_err(|error| error.to_string())?;
            if skipped < length {
                return Err("the tar stream ends inside a member".to_string());
            }
        }
        (self.remaining, self.padding) = (0, 0);
        Ok(())
    }

    /// The next header block, or None for a zero block or the end of the stream.
    fn header_block(&mut self) -> Result<Option<[u8; BLOCK]>, String> {
        let mut block = [0; BLOCK];
        let mut filled = 0;
        while filled < BLOCK {
            match self.input.read(&mut block[filled..]) {
                Ok(0) => break,
                Ok(length) => filled += length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        match filled {
            0 => Ok(None),
            BLOCK if block.iter().all(|&byte| byte == 0) => Ok(None),
            BLOCK => Ok(Some(block)),
            _ => Err("the tar stream ends inside a header".to_string()),
        }
    }
}

/// The fields of a ustar (or GNU or v7) header block.
struct Header {
    typeflag: u8,
    name: Vec<u8>,
    mode: u64,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: u64,
    link_name: Vec<u8>,
    uname: Vec<u8>,
    gname: Vec<u8>,
    device: (u64, u64),
}

impl Header {
    fn parse(block: &[u8; BLOCK]) -> Result<Header, String> {
        let expected = number(&block[148..156], "checksum")?;
        // The checksum field counts as spaces; some writers sum signed bytes.
        let field = |index: usize| (148..156).contains(&index);
        let unsigned: u64 = block.iter().enumerate().map(|(index, &byte)| if field(index) { 32 } else { u64::from(byte) }).sum();
        let signed: i64 =
            block.iter().enumerate().map(|(index, &byte)| if field(index) { 32 } else { i64::from(byte as i8) }).sum();
        if expected != unsigned && i64::try_from(expected) != Ok(signed) {
            return Err("a tar header has a wrong checksum".to_string());
        }
        let mut name = text(&block[0..100]);
        let prefix = text(&block[345..500]);
        if &block[257..263] == USTAR_MAGIC && !prefix.is_empty() {
            name = [prefix.as_slice(), b"/", &name].concat();
        }
        Ok(Header {
            typeflag: block[156],
            name,
            mode: number(&block[100..108], "mode")?,
            uid: number(&block[108..116], "uid")?,
            gid: number(&block[116..124], "gid")?,
            size: number(&block[124..136], "size")?,
            mtime: number(&block[136..148], "mtime")?,
            link_name: text(&block[157..257]),
            uname: text(&block[265..297]),
            gname: text(&block[297..329]),
            device: (number(&block[329..337], "devmajor")?, number(&block[337..345], "devminor")?),
        })
    }

    /// The member this header describes, with the pax records before it applied.
    fn member(self, records: Records) -> Result<Member, String> {
        // The 7 octal digits of a ustar field: what run::read_output can write back.
        let small = |value: u64, what: &str| {
            u32::try_from(value).ok().filter(|&value| value <= 0o7777777).ok_or_else(|| format!("{what} {value} is too large"))
        };
        let mut member = Member {
            name: self.name,
            kind: EntryType::new(self.typeflag),
            mode: small(self.mode, "mode")?,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
            size: self.size,
            link_name: self.link_name,
            uname: self.uname,
            gname: self.gname,
            device: (small(self.device.0, "devmajor")?, small(self.device.1, "devminor")?),
            records: Vec::new(),
        };
        for (key, value) in &records {
            match key.as_slice() {
                b"path" => member.name = value.clone(),
                b"linkpath" => member.link_name = value.clone(),
                b"size" => member.size = decimal(value, "size")?,
                b"uid" => member.uid = decimal(value, "uid")?,
                b"gid" => member.gid = decimal(value, "gid")?,
                b"uname" => member.uname = value.clone(),
                b"gname" => member.gname = value.clone(),
                key if key.starts_with(b"GNU.sparse.") => return Err("GNU sparse members are not supported".to_string()),
                _ => {}
            }
        }
        member.records = records;
        Ok(member)
    }
}

/// The bytes of a header text field before its first NUL.
fn text(field: &[u8]) -> Vec<u8> {
    field[..field.iter().position(|&byte| byte == 0).unwrap_or(field.len())].to_vec()
}

/// A numeric header field: octal digits (padded with spaces or NULs), or
/// GNU's base-256, a 0x80 byte followed by a big-endian value.
fn number(field: &[u8], what: &str) -> Result<u64, String> {
    let invalid = || format!("invalid {what} field {field:?}");
    if field.first().is_some_and(|&byte| byte & 0x80 != 0) {
        // 0xff starts a negative value, which no field here may hold.
        if field[0] != 0x80 {
            return Err(invalid());
        }
        return field[1..]
            .iter()
            .try_fold(0u64, |value, &byte| value.checked_mul(256).map(|value| value | u64::from(byte)))
            .ok_or_else(invalid);
    }
    let digits = text(field);
    let digits = digits.trim_ascii();
    digits.iter().try_fold(0u64, |value, &byte| match byte {
        b'0'..=b'7' => value.checked_mul(8).map(|value| value | u64::from(byte - b'0')).ok_or_else(invalid),
        _ => Err(invalid()),
    })
}

/// A decimal pax record value.
fn decimal(value: &[u8], what: &str) -> Result<u64, String> {
    let parsed = std::str::from_utf8(value).ok().filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()));
    parsed.and_then(|text| text.parse().ok()).ok_or_else(|| format!("invalid pax {what} {:?}", String::from_utf8_lossy(value)))
}

/// The records of a pax extended header: "<length> <key>=<value>\n", where
/// the decimal length counts the whole record, so a value may hold any byte.
pub fn pax_records(mut payload: &[u8]) -> Result<Records, String> {
    let mut records = Vec::new();
    while !payload.is_empty() {
        let malformed = || format!("malformed pax record {:?}", String::from_utf8_lossy(&payload[..payload.len().min(40)]));
        let space = payload.iter().position(|&byte| byte == b' ').ok_or_else(malformed)?;
        let length = decimal(&payload[..space], "record length").ok().and_then(|length| usize::try_from(length).ok());
        let record = match length.and_then(|length| payload.get(..length)) {
            Some(record @ [.., b'\n']) if record.len() > space + 1 => record,
            _ => return Err(malformed()),
        };
        let field = &record[space + 1..record.len() - 1];
        let equals = field.iter().position(|&byte| byte == b'=').ok_or_else(malformed)?;
        records.push((field[..equals].to_vec(), field[equals + 1..].to_vec()));
        payload = &payload[record.len()..];
    }
    Ok(records)
}

/// Building tar streams by hand for tests.
#[cfg(test)]
pub(crate) mod testing {
    use tar::{EntryType, Header};

    /// A ustar header with mode 0644, owner 0 and the given size field.
    pub fn header(kind: u8, name: &[u8], size: u64) -> Header {
        let mut header = Header::new_ustar();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_entry_type(EntryType::new(kind));
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(size);
        header
    }

    /// A member as it appears in a stream: its header, then `data` padded to a block.
    pub fn member(mut header: Header, data: &[u8]) -> Vec<u8> {
        header.set_cksum();
        let mut bytes = header.as_bytes().to_vec();
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes
    }

    /// A pax extended header whose payload is `records`, written out by hand.
    pub fn pax(records: &[u8]) -> Vec<u8> {
        member(header(b'x', b"././@PaxHeader", records.len() as u64), records)
    }

    /// The members, followed by the two zero blocks that end an archive.
    pub fn stream(members: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = members.concat();
        bytes.extend([0; 1024]);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    /// Every member of a stream with its data.
    fn read_all(bytes: &[u8]) -> Result<Vec<(Member, Vec<u8>)>, String> {
        let mut reader = Reader::new(bytes);
        let mut members = Vec::new();
        while let Some((member, mut data)) = reader.next_member()? {
            let mut content = Vec::new();
            data.read_to_end(&mut content).map_err(|error| error.to_string())?;
            members.push((member, content));
        }
        Ok(members)
    }

    fn names_and_data(bytes: &[u8]) -> Vec<(String, u64, Vec<u8>)> {
        let members = read_all(bytes).unwrap();
        members.into_iter().map(|(member, data)| (String::from_utf8(member.name).unwrap(), member.size, data)).collect()
    }

    #[test]
    fn pax_records_are_delimited_by_their_length() {
        // A value may hold newlines, NULs, "=" and bytes that are not UTF-8.
        let payload = b"25 SCHILY.xattr.a=\n=\n\x00\xff\n\n11 path=/x\n";
        assert_eq!(
            pax_records(payload).unwrap(),
            [(b"SCHILY.xattr.a".to_vec(), b"\n=\n\x00\xff\n".to_vec()), (b"path".to_vec(), b"/x".to_vec())]
        );
        let long = [&b"104 k="[..], &[b'v'; 97], b"\n"].concat();
        assert_eq!(pax_records(&long).unwrap(), [(b"k".to_vec(), vec![b'v'; 97])]);
        assert_eq!(pax_records(b"").unwrap(), []);
    }

    #[test]
    fn malformed_record_lengths_are_rejected() {
        for payload in [
            &b"10 path=/x\n"[..],
            b"12 path=/x\n",
            b"11 path=/x",
            b"+12 path=/x\n",
            b"x path=/x\n",
            b"11path=/x\n",
            b"0 a=b\n",
            b"18446744073709551616 a=b\n",
            b"10 path/x\n",
            b"3 \n",
            b"2 \n",
        ] {
            assert!(pax_records(payload).is_err(), "{:?}", String::from_utf8_lossy(payload));
        }
    }

    #[test]
    fn a_member_carries_the_pax_records_before_it() {
        let long = [&b"upper/"[..], &[b'n'; 150]].concat();
        let origin = b"SCHILY.xattr.trusted.overlay.origin";
        let records = [&b"166 path="[..], &long, b"\n46 ", origin, b"=\x00\xfb\n\x00\xff\n\n"].concat();
        let mut symlink = header(b'2', b"upper/l", 0);
        symlink.as_old_mut().linkname[..6].copy_from_slice(b"target");
        let bytes = stream(&[pax(&records), member(header(b'0', b"upper/short", 3), b"abc"), member(symlink, b"")]);
        let members = read_all(&bytes).unwrap();
        let (file, data) = &members[0];
        assert_eq!(file.name, long);
        assert_eq!(file.kind, EntryType::Regular);
        assert_eq!(data, b"abc");
        assert_eq!(file.records, [(b"path".to_vec(), long.clone()), (origin.to_vec(), b"\x00\xfb\n\x00\xff\n".to_vec())]);
        let (link, _) = &members[1];
        assert_eq!((link.name.as_slice(), link.link_name.as_slice()), (&b"upper/l"[..], &b"target"[..]));
        assert_eq!(link.kind, EntryType::Symlink);
        assert!(link.records.is_empty());
    }

    #[test]
    fn the_pax_size_record_overrides_the_header() {
        let bytes = stream(&[pax(b"10 size=5\n"), member(header(b'0', b"a", 0), b"hello"), member(header(b'0', b"b", 3), b"abc")]);
        assert_eq!(names_and_data(&bytes), [("a".into(), 5, b"hello".to_vec()), ("b".into(), 3, b"abc".to_vec())]);
        // A member of 9 GiB: its size comes from the record, and its missing data is an error.
        let bytes = stream(&[pax(b"19 size=9663676416\n"), member(header(b'0', b"big", 0), b"")]);
        let mut reader = Reader::new(bytes.as_slice());
        assert_eq!(reader.next_member().unwrap().unwrap().0.size, 9_663_676_416);
        assert!(reader.next_member().is_err());
    }

    #[test]
    fn numeric_fields_are_octal_or_base_256() {
        assert_eq!(number(b"0000644\0", "mode"), Ok(0o644));
        assert_eq!(number(b"   644 \0", "mode"), Ok(0o644));
        assert_eq!(number(b"\0\0\0\0\0\0\0\0", "mode"), Ok(0));
        assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x40, 0, 0, 0], "size"), Ok(9_663_676_416));
        for invalid in [&b"0000648\0"[..], b"0x1f\0\0\0\0", &[0xff; 8], &[0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]] {
            assert!(number(invalid, "field").is_err(), "{invalid:?}");
        }
        let mut header = header(b'0', b"a", 0);
        header.as_old_mut().size = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(names_and_data(&stream(&[member(header, b"hello")])), [("a".into(), 5, b"hello".to_vec())]);
    }

    #[test]
    fn a_ustar_prefix_is_joined_to_the_name() {
        let mut header = header(b'5', b"bin", 0);
        header.as_ustar_mut().unwrap().prefix[..9].copy_from_slice(b"upper/usr");
        assert_eq!(names_and_data(&stream(&[member(header, b"")])), [("upper/usr/bin".into(), 0, Vec::new())]);
    }

    #[test]
    fn what_would_be_misread_is_rejected() {
        let file = || member(header(b'0', b"f", 0), b"");
        for members in [
            vec![member(header(b'g', b"pax_global_header", 11), b"11 path=/x\n"), file()],
            vec![member(header(b'S', b"f", 0), b"")],
            vec![member(header(b'L', b"././@LongLink", 2), b"f\0"), file()],
            vec![member(header(b'K', b"././@LongLink", 2), b"t\0"), file()],
            vec![pax(b"22 GNU.sparse.major=1\n"), file()],
            vec![pax(b"12 size=abc\n"), file()],
            vec![pax(b"11 path=/x\n"), pax(b"11 path=/y\n"), file()],
            vec![pax(b"11 path=/x\n")],
        ] {
            assert!(read_all(&stream(&members)).is_err());
        }
    }

    #[test]
    fn oversized_headers_and_fields_are_rejected() {
        // One valid record of MAX_PAX_SIZE + 1 bytes: "1048577 k=" + value + "\n".
        let records = [&b"1048577 k="[..], &vec![b'v'; 1_048_566], b"\n"].concat();
        assert_eq!(records.len() as u64, MAX_PAX_SIZE + 1);
        let file = || member(header(b'0', b"f", 0), b"");
        assert!(read_all(&stream(&[pax(&records), file()])).is_err());
        let records = [&b"1048576 k="[..], &vec![b'v'; 1_048_565], b"\n"].concat();
        assert_eq!(read_all(&stream(&[pax(&records), file()])).unwrap()[0].0.records[0].1.len(), 1_048_565);
        // A device number that run::read_output could not write back.
        let mut device = header(b'3', b"upper/dev/x", 0);
        device.as_ustar_mut().unwrap().dev_major = *b"10000000";
        assert!(read_all(&stream(&[member(device, b"")])).is_err());
        let mut device = header(b'3', b"upper/dev/x", 0);
        device.as_ustar_mut().unwrap().dev_major = *b"7777777\0";
        assert_eq!(read_all(&stream(&[member(device, b"")])).unwrap()[0].0.device, (0o7777777, 0));
    }

    #[test]
    fn a_wrong_checksum_is_rejected() {
        let mut bytes = stream(&[member(header(b'0', b"f", 0), b"")]);
        bytes[0] = b'g';
        assert!(read_all(&bytes).is_err());
    }

    #[test]
    fn the_archive_ends_at_a_zero_block_or_between_members() {
        let first = member(header(b'0', b"a", 3), b"abc");
        let second = member(header(b'0', b"b", 3), b"abc");
        assert_eq!(names_and_data(&stream(&[first.clone(), vec![0; 512], second.clone()])).len(), 1);
        assert_eq!(names_and_data(&[first.clone(), second].concat()).len(), 2);
        // Inside a header or inside data, the end of the stream is an error.
        assert!(read_all(&first[..100]).is_err());
        assert!(read_all(&first[..514]).is_err());
    }

    #[test]
    fn malformed_input_is_an_error_and_never_a_panic() {
        let records = [&b"46 SCHILY.xattr.trusted.overlay.origin=\x00\xfb\n\x00\xff\n\n"[..], b"10 size=3\n"].concat();
        let bytes = stream(&[pax(&records), member(header(b'0', b"upper/f", 0), b"abc"), member(header(b'5', b"upper/d", 0), b"")]);
        for length in 0..bytes.len() {
            let _ = read_all(&bytes[..length]);
        }
        // The headers are at 0, 1024 and 2048; a changed header gets a matching
        // checksum, so that its fields are parsed.
        let header_at = |position: usize| [0, 1024, 2048].into_iter().find(|start| (*start..start + 512).contains(&position));
        for position in 0..bytes.len() {
            for value in [0x00, b'\n', b' ', b'9', 0x80, 0xff] {
                let mut mutated = bytes.clone();
                mutated[position] = value;
                if let Some(start) = header_at(position).filter(|start| !(start + 148..start + 156).contains(&position)) {
                    let mut header = tar::Header::from_byte_slice(&mutated[start..start + 512]).clone();
                    header.set_cksum();
                    mutated[start..start + 512].copy_from_slice(header.as_bytes());
                }
                let _ = read_all(&mutated);
            }
        }
    }
}
