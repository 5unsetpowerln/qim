//! Make text the guest wrote safe to show on the host's terminal.

/// Removes what could control a terminal from a byte stream: escape sequences
/// (CSI, OSC and the other ESC sequences), every control character except
/// newline and tab, and the C1 controls U+0080..U+009F encoded in UTF-8. A
/// carriage return becomes a newline (a CR LF pair one newline), so that
/// progress meters, which redraw a line, show as separate lines instead of
/// overwriting what was shown. The state carries over between calls, so a
/// sequence may be split across them.
#[derive(Debug, Default)]
pub struct TerminalFilter {
    state: State,
    after_cr: bool,
}

#[derive(Debug, Default, PartialEq)]
enum State {
    #[default]
    Text,
    /// After ESC.
    Escape,
    /// In a control sequence (ESC [), up to its final byte.
    Csi,
    /// In an operating system command (ESC ]), up to BEL or ESC \.
    Osc,
    /// After ESC inside an operating system command.
    OscEscape,
    /// After 0xC2, which starts the UTF-8 encoding of U+0080..U+00BF.
    LeadC2,
}

impl TerminalFilter {
    /// Append the filtered `input` to `output`.
    pub fn push(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for &byte in input {
            self.byte(byte, output);
        }
    }

    fn byte(&mut self, byte: u8, output: &mut Vec<u8>) {
        match self.state {
            State::Text => self.text(byte, output),
            State::Escape => {
                self.state = match byte {
                    b'[' => State::Csi,
                    b']' => State::Osc,
                    // A two-byte sequence (or an unknown one): drop its second byte.
                    _ => State::Text,
                }
            }
            State::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    self.state = State::Text;
                }
            }
            State::Osc => match byte {
                0x07 => self.state = State::Text,
                0x1b => self.state = State::OscEscape,
                _ => {}
            },
            State::OscEscape => self.state = State::Text,
            State::LeadC2 => {
                self.state = State::Text;
                if !(0x80..=0x9f).contains(&byte) {
                    output.push(0xc2);
                    self.text(byte, output);
                }
            }
        }
    }

    fn text(&mut self, byte: u8, output: &mut Vec<u8>) {
        let after_cr = std::mem::take(&mut self.after_cr);
        match byte {
            0x1b => self.state = State::Escape,
            0xc2 => self.state = State::LeadC2,
            b'\r' => {
                output.push(b'\n');
                self.after_cr = true;
            }
            b'\n' if after_cr => {}
            b'\n' | b'\t' => output.push(byte),
            0x00..=0x1f | 0x7f => {}
            _ => output.push(byte),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filtered(chunks: &[&[u8]]) -> Vec<u8> {
        let mut filter = TerminalFilter::default();
        let mut output = Vec::new();
        for chunk in chunks {
            filter.push(chunk, &mut output);
        }
        output
    }

    #[test]
    fn plain_text_newlines_and_tabs_pass() {
        assert_eq!(filtered(&[b"build\tok\n"]), b"build\tok\n");
    }

    #[test]
    fn control_sequences_are_removed_whole() {
        assert_eq!(filtered(&[b"\x1b[1;31mred\x1b[0m\n"]), b"red\n");
        assert_eq!(filtered(&[b"\x1b]0;title\x07after\n"]), b"after\n");
        assert_eq!(filtered(&[b"\x1b]8;;http://x\x1b\\link\n"]), b"link\n");
        assert_eq!(filtered(&[b"a\x1bcb\n"]), b"ab\n");
    }

    #[test]
    fn other_control_characters_are_removed() {
        assert_eq!(filtered(&[b"a\x00b\x07c\x08d\x7fe\n"]), b"abcde\n");
    }

    #[test]
    fn c1_controls_are_removed_but_other_utf8_stays() {
        // U+009B is the one-character form of ESC [.
        assert_eq!(filtered(&["x\u{9b}y\n".as_bytes()]), b"xy\n");
        assert_eq!(filtered(&["\u{a2} caf\u{e9}\n".as_bytes()]), "\u{a2} caf\u{e9}\n".as_bytes());
    }

    #[test]
    fn carriage_returns_become_newlines() {
        assert_eq!(filtered(&[b"10%\r50%\r100%\r\n"]), b"10%\n50%\n100%\n");
    }

    #[test]
    fn sequences_may_be_split_between_chunks() {
        assert_eq!(filtered(&[b"\x1b[3", b"1mok\n"]), b"ok\n");
        assert_eq!(filtered(&[b"\xc2", b"\xa2\n"]), "\u{a2}\n".as_bytes());
        assert_eq!(filtered(&[b"\xc2", b"\x9bz\n"]), b"z\n");
        assert_eq!(filtered(&[b"done\r", b"\nnext\n"]), b"done\nnext\n");
    }
}
