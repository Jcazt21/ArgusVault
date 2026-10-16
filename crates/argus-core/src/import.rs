//! Import from other password managers (PRD §3.9): KeePass/KeePassXC CSV and Bitwarden
//! unencrypted JSON.
//!
//! Both formats are parsed by small hand-written, strict parsers (the project avoids pulling in a
//! general-purpose parser for untrusted input). Secrets are held in [`Zeroizing`] strings while
//! parsing; the source file is read into a zeroizing buffer. Imported entries are always
//! [`EntryKind::Web`].
//!
//! The source file itself holds every password in plain text: the caller must tell the user to
//! delete it.

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::fs_util;
use crate::model::{Entry, MAX_ENTRIES, MAX_FIELD_LEN};
use crate::totp::TotpConfig;

/// Largest export file accepted.
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;
/// Deepest JSON nesting accepted (an export needs about 5).
const MAX_JSON_DEPTH: usize = 32;

/// Supported source formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `KeePass` / `KeePassXC` CSV export.
    KeePassCsv,
    /// Bitwarden unencrypted JSON export.
    BitwardenJson,
}

impl Format {
    /// Guess the format from the file extension.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "csv" => Some(Self::KeePassCsv),
            "json" => Some(Self::BitwardenJson),
            _ => None,
        }
    }
}

/// Outcome of an import: ready-to-insert entries and how many source records were left out.
#[derive(Debug)]
pub struct Imported {
    pub entries: Vec<Entry>,
    /// Records that were not logins, were unusable, or exceeded a limit.
    pub skipped: usize,
}

/// Read and parse an export file.
///
/// # Errors
/// I/O errors, [`Error::LimitExceeded`] for oversized files, [`Error::InvalidFormat`] /
/// [`Error::InvalidInput`] for content that is not a supported export.
pub fn import_file(path: &Path, format: Format) -> Result<Imported> {
    let data = fs_util::read_limited(path, MAX_IMPORT_BYTES)?;
    import_bytes(&data, format)
}

/// Parse an export already in memory.
///
/// # Errors
/// See [`import_file`].
pub fn import_bytes(data: &[u8], format: Format) -> Result<Imported> {
    let text = std::str::from_utf8(data).map_err(|_| Error::InvalidFormat)?;
    match format {
        Format::KeePassCsv => from_csv(text),
        Format::BitwardenJson => from_bitwarden(text),
    }
}

// ------------------------------------------------------------------ shared

fn fresh_entry(title: &str) -> Result<Entry> {
    let title = title.trim();
    Entry::new(if title.is_empty() { "(untitled)" } else { title })
}

/// Try to attach a TOTP secret; an unparsable one is dropped rather than failing the import.
fn attach_totp(entry: &mut Entry, raw: &str) {
    let raw = raw.trim();
    if !raw.is_empty() {
        entry.totp = TotpConfig::parse(raw).ok();
    }
}

fn fits(entry: &Entry) -> bool {
    entry.validate().is_ok()
}

// --------------------------------------------------------------------- CSV

/// RFC 4180 parser: quoted fields, `""` escapes, CRLF or LF, optional UTF-8 BOM.
fn parse_csv(text: &str) -> Result<Vec<Vec<Zeroizing<String>>>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows: Vec<Vec<Zeroizing<String>>> = Vec::new();
    let mut row: Vec<Zeroizing<String>> = Vec::new();
    let mut field = Zeroizing::new(String::new());
    let mut in_quotes = false;
    let mut quoted = false;
    let mut chars = text.chars().peekable();

    let end_row = |row: &mut Vec<Zeroizing<String>>, rows: &mut Vec<Vec<Zeroizing<String>>>| {
        // A blank line is not a record.
        if row.len() == 1 && row.first().is_some_and(|f| f.is_empty()) {
            row.clear();
        } else {
            rows.push(std::mem::take(row));
        }
    };

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            if field.len() > MAX_FIELD_LEN {
                return Err(Error::LimitExceeded);
            }
            continue;
        }
        match c {
            '"' if field.is_empty() && !quoted => {
                in_quotes = true;
                quoted = true;
            }
            '"' => return Err(Error::InvalidFormat),
            ',' => {
                row.push(std::mem::take(&mut field));
                quoted = false;
            }
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                quoted = false;
                end_row(&mut row, &mut rows);
            }
            _ => {
                if quoted {
                    // Text after a closing quote.
                    return Err(Error::InvalidFormat);
                }
                field.push(c);
                if field.len() > MAX_FIELD_LEN {
                    return Err(Error::LimitExceeded);
                }
            }
        }
    }
    if in_quotes {
        return Err(Error::InvalidFormat);
    }
    if !field.is_empty() || !row.is_empty() || quoted {
        row.push(field);
        end_row(&mut row, &mut rows);
    }
    Ok(rows)
}

/// Index of the first header equal (case-insensitively) to one of `names`.
fn column(header: &[Zeroizing<String>], names: &[&str]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().to_lowercase();
        names.iter().any(|n| h == *n)
    })
}

fn from_csv(text: &str) -> Result<Imported> {
    let rows = parse_csv(text)?;
    let mut rows = rows.into_iter();
    let header = rows.next().ok_or(Error::InvalidFormat)?;
    let title = column(&header, &["title", "account", "name"]);
    let user = column(&header, &["username", "login name", "user name", "user", "login"]);
    let pass = column(&header, &["password"]);
    let url = column(&header, &["url", "web site", "website", "login uri"]);
    let notes = column(&header, &["notes", "comments", "note"]);
    let totp = column(&header, &["totp", "login totp"]);
    if title.is_none() || pass.is_none() {
        return Err(Error::InvalidInput("not a KeePass CSV export (no title/password columns)"));
    }

    let mut out = Imported { entries: Vec::new(), skipped: 0 };
    for record in rows {
        if out.entries.len() >= MAX_ENTRIES {
            out.skipped += 1;
            continue;
        }
        let get = |i: Option<usize>| i.and_then(|i| record.get(i)).map_or("", |f| f.as_str());
        let mut e = fresh_entry(get(title))?;
        get(user).clone_into(&mut e.username);
        get(pass).clone_into(&mut e.password);
        get(url).trim().clone_into(&mut e.url);
        get(notes).clone_into(&mut e.notes);
        attach_totp(&mut e, get(totp));
        if fits(&e) {
            out.entries.push(e);
        } else {
            out.skipped += 1;
        }
    }
    Ok(out)
}

// -------------------------------------------------------------------- JSON

enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(Zeroizing<String>),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<()> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(Error::InvalidFormat)
        }
    }

    fn literal(&mut self, word: &str) -> Result<()> {
        let end = self.pos + word.len();
        if self.bytes.get(self.pos..end) == Some(word.as_bytes()) {
            self.pos = end;
            Ok(())
        } else {
            Err(Error::InvalidFormat)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        if depth > MAX_JSON_DEPTH {
            return Err(Error::InvalidFormat);
        }
        self.skip_ws();
        match self.peek().ok_or(Error::InvalidFormat)? {
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                loop {
                    self.skip_ws();
                    let key = self.string()?;
                    self.skip_ws();
                    self.expect(b':')?;
                    let v = self.value(depth + 1)?;
                    fields.push((key.as_str().to_owned(), v));
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Json::Obj(fields));
                        }
                        _ => return Err(Error::InvalidFormat),
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err(Error::InvalidFormat),
                    }
                }
            }
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.literal("true").map(|()| Json::Bool(true)),
            b'f' => self.literal("false").map(|()| Json::Bool(false)),
            b'n' => self.literal("null").map(|()| Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::InvalidFormat),
        }
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
            self.pos += 1;
        }
        let s = std::str::from_utf8(self.bytes.get(start..self.pos).ok_or(Error::InvalidFormat)?)
            .map_err(|_| Error::InvalidFormat)?;
        s.parse::<f64>().map(Json::Num).map_err(|_| Error::InvalidFormat)
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self.bytes.get(self.pos..self.pos + 4).ok_or(Error::InvalidFormat)?;
        let mut v = 0u32;
        for &d in digits {
            v = v * 16 + char::from(d).to_digit(16).ok_or(Error::InvalidFormat)?;
        }
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<Zeroizing<String>> {
        self.expect(b'"')?;
        let mut out = Zeroizing::new(String::new());
        loop {
            // Copy a run of plain bytes at once; the input is already valid UTF-8.
            let start = self.pos;
            while self.peek().is_some_and(|b| b != b'"' && b != b'\\' && b >= 0x20) {
                self.pos += 1;
            }
            let run = self.bytes.get(start..self.pos).ok_or(Error::InvalidFormat)?;
            out.push_str(std::str::from_utf8(run).map_err(|_| Error::InvalidFormat)?);
            if out.len() > MAX_FIELD_LEN {
                return Err(Error::LimitExceeded);
            }
            match self.peek().ok_or(Error::InvalidFormat)? {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or(Error::InvalidFormat)?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                self.literal("\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(Error::InvalidFormat);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(code).ok_or(Error::InvalidFormat)?);
                        }
                        _ => return Err(Error::InvalidFormat),
                    }
                }
                // A raw control character inside a string.
                _ => return Err(Error::InvalidFormat),
            }
        }
    }
}

fn parse_json(text: &str) -> Result<Json> {
    let mut p = JsonParser { bytes: text.as_bytes(), pos: 0 };
    let v = p.value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(Error::InvalidFormat);
    }
    Ok(v)
}

fn from_bitwarden(text: &str) -> Result<Imported> {
    // Some tools save JSON with a UTF-8 byte-order mark.
    let root = parse_json(text.strip_prefix('\u{feff}').unwrap_or(text))?;
    if matches!(root.get("encrypted"), Some(Json::Bool(true))) {
        return Err(Error::InvalidInput("encrypted Bitwarden exports are not supported"));
    }
    let Some(Json::Arr(items)) = root.get("items") else {
        return Err(Error::InvalidInput("not a Bitwarden JSON export (no items list)"));
    };

    let mut out = Imported { entries: Vec::new(), skipped: 0 };
    for item in items {
        // Only logins (type 1); notes, cards and identities are out of scope.
        let is_login =
            matches!(item.get("type"), Some(Json::Num(n)) if (*n - 1.0).abs() < f64::EPSILON);
        let login = item.get("login");
        if !is_login || login.is_none() || out.entries.len() >= MAX_ENTRIES {
            out.skipped += 1;
            continue;
        }
        let field = |parent: Option<&Json>, key: &str| {
            parent.and_then(|p| p.get(key)).and_then(Json::str).unwrap_or("").to_owned()
        };
        let mut e = fresh_entry(item.get("name").and_then(Json::str).unwrap_or(""))?;
        e.username = field(login, "username");
        e.password = field(login, "password");
        field(Some(item), "notes").clone_into(&mut e.notes);
        if let Some(Json::Arr(uris)) = login.and_then(|l| l.get("uris")) {
            if let Some(uri) = uris.iter().find_map(|u| u.get("uri").and_then(Json::str)) {
                uri.trim().clone_into(&mut e.url);
            }
        }
        attach_totp(&mut e, &field(login, "totp"));
        if fits(&e) {
            out.entries.push(e);
        } else {
            out.skipped += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const KEEPASSXC: &str = "\u{feff}\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\r\n\
        \"Root\",\"GitHub\",\"alice\",\"p,\"\"quoted\"\" pass\",\"https://github.com\",\"line1\nline2\",\"JBSWY3DPEHPK3PXP\"\r\n\
        \"Root\",\"\",\"bob\",\"pw2\",\"\",\"\",\"\"\r\n\
        \r\n";

    #[test]
    fn keepass_csv_with_quotes_newlines_and_bom() {
        let r = import_bytes(KEEPASSXC.as_bytes(), Format::KeePassCsv).unwrap();
        assert_eq!(r.skipped, 0);
        assert_eq!(r.entries.len(), 2);
        let gh = &r.entries[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.username, "alice");
        assert_eq!(gh.password, "p,\"quoted\" pass");
        assert_eq!(gh.url, "https://github.com");
        assert_eq!(gh.notes, "line1\nline2");
        assert!(gh.totp.is_some());
        assert_eq!(r.entries[1].title, "(untitled)");
    }

    #[test]
    fn keepass_classic_headers() {
        let csv = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Mail\",\"me\",\"pw\",\"https://m.example\",\"c\"\n";
        let r = import_bytes(csv.as_bytes(), Format::KeePassCsv).unwrap();
        assert_eq!(r.entries[0].title, "Mail");
        assert_eq!(r.entries[0].url, "https://m.example");
    }

    #[test]
    fn csv_without_the_expected_columns_is_rejected() {
        assert!(import_bytes(b"a,b,c\n1,2,3\n", Format::KeePassCsv).is_err());
        assert!(import_bytes(b"", Format::KeePassCsv).is_err());
    }

    #[test]
    fn malformed_csv_is_rejected() {
        assert!(import_bytes(b"Title,Password\n\"open,pw\n", Format::KeePassCsv).is_err());
        assert!(import_bytes(b"Title,Password\n\"a\"b,pw\n", Format::KeePassCsv).is_err());
        assert!(import_bytes(b"Title,Password\na\"b,pw\n", Format::KeePassCsv).is_err());
    }

    const BITWARDEN: &str = r#"{
        "encrypted": false,
        "folders": [{"id": "f", "name": "Work"}],
        "items": [
            {"type": 1, "name": "Site é🔑", "notes": "n\nnote",
             "login": {"username": "u", "password": "p\"w", "totp": "JBSWY3DPEHPK3PXP",
                       "uris": [{"match": null, "uri": "https://x.example"}]}},
            {"type": 2, "name": "A secure note", "notes": "secret", "secureNote": {"type": 0}},
            {"type": 3, "name": "A card", "card": {"number": "4111"}},
            {"type": 1, "name": "No uri", "login": {"username": "v", "password": "q"}}
        ]
    }"#;

    #[test]
    fn bitwarden_logins_are_imported_and_others_skipped() {
        let r = import_bytes(BITWARDEN.as_bytes(), Format::BitwardenJson).unwrap();
        assert_eq!(r.skipped, 2);
        assert_eq!(r.entries.len(), 2);
        let e = &r.entries[0];
        assert_eq!(e.title, "Site é🔑");
        assert_eq!(e.username, "u");
        assert_eq!(e.password, "p\"w");
        assert_eq!(e.url, "https://x.example");
        assert_eq!(e.notes, "n\nnote");
        assert!(e.totp.is_some());
        assert_eq!(r.entries[1].url, "");
    }

    #[test]
    fn bitwarden_json_with_a_byte_order_mark() {
        let with_bom = format!("\u{feff}{BITWARDEN}");
        let r = import_bytes(with_bom.as_bytes(), Format::BitwardenJson).unwrap();
        assert_eq!(r.entries.len(), 2);
    }

    #[test]
    fn bitwarden_encrypted_or_wrong_shape_is_rejected() {
        assert!(
            import_bytes(br#"{"encrypted": true, "data": "xyz"}"#, Format::BitwardenJson).is_err()
        );
        assert!(import_bytes(br#"{"foo": 1}"#, Format::BitwardenJson).is_err());
        assert!(import_bytes(b"[1,2]", Format::BitwardenJson).is_err());
        assert!(import_bytes(b"{\"items\": [", Format::BitwardenJson).is_err());
    }

    #[test]
    fn json_edge_cases() {
        assert!(parse_json(r#"{"a": "\ud800"}"#).is_err(), "lone surrogate");
        assert!(parse_json("{\"a\": \"x\ny\"}").is_err(), "raw control character");
        assert!(parse_json(r#"{"a": 1} x"#).is_err(), "trailing data");
        assert!(parse_json(r#"{"a": 01x}"#).is_err());
        let deep = "[".repeat(1000);
        assert!(parse_json(&deep).is_err(), "depth limit");
        assert!(parse_json(r#"{"a": [1, 2.5e3, -4, true, false, null, "s"]}"#).is_ok());
    }

    #[test]
    fn format_is_guessed_from_the_extension() {
        assert_eq!(Format::from_path(Path::new("x.CSV")), Some(Format::KeePassCsv));
        assert_eq!(Format::from_path(Path::new("x.json")), Some(Format::BitwardenJson));
        assert_eq!(Format::from_path(Path::new("x.txt")), None);
        assert_eq!(Format::from_path(Path::new("x")), None);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = import_bytes(&data, Format::KeePassCsv);
            let _ = import_bytes(&data, Format::BitwardenJson);
        }

        #[test]
        fn csv_fields_roundtrip(fields in proptest::collection::vec("[^\\r]{0,20}", 2..6)) {
            let quoted: Vec<String> =
                fields.iter().map(|f| format!("\"{}\"", f.replace('"', "\"\""))).collect();
            let rows = parse_csv(&format!("{}\n", quoted.join(","))).unwrap();
            // A line holding a single empty field is a blank line, not a record.
            prop_assume!(!(fields.len() == 1 && fields[0].is_empty()));
            prop_assert_eq!(rows.len(), 1);
            let got: Vec<&str> = rows[0].iter().map(|f| f.as_str()).collect();
            let want: Vec<&str> = fields.iter().map(String::as_str).collect();
            prop_assert_eq!(got, want);
        }
    }
}
