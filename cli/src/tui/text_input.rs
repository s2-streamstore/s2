/// UTF-8-safe text input with cursor tracking at valid char boundaries.
#[derive(Debug, Clone, Default)]
pub struct TextInput {
    buf: String,
    cursor: usize,
}

impl TextInput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_value(value: impl Into<String>) -> Self {
        let buf: String = value.into();
        let cursor = buf.len();
        Self { buf, cursor }
    }

    pub fn value(&self) -> &str {
        &self.buf
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn split_at_cursor(&self) -> (&str, &str) {
        let pos = self.cursor.min(self.buf.len());
        (&self.buf[..pos], &self.buf[pos..])
    }

    /// Windowed split for display in a fixed-width area (scrolls around cursor).
    pub fn split_at_cursor_windowed(&self, max_width: usize) -> (String, String) {
        if self.buf.len() <= max_width {
            let (b, a) = self.split_at_cursor();
            return (b.to_owned(), a.to_owned());
        }
        let cursor = self.cursor.min(self.buf.len());
        let half = max_width / 2;
        let mut start = cursor.saturating_sub(half);
        while start > 0 && !self.buf.is_char_boundary(start) {
            start -= 1;
        }
        let mut end = (start + max_width).min(self.buf.len());
        while end < self.buf.len() && !self.buf.is_char_boundary(end) {
            end += 1;
        }
        if end == self.buf.len() {
            start = end.saturating_sub(max_width);
            while start > 0 && !self.buf.is_char_boundary(start) {
                start -= 1;
            }
        }
        let window = &self.buf[start..end];
        let cursor_in_window = cursor - start;
        (
            window[..cursor_in_window].to_owned(),
            window[cursor_in_window..].to_owned(),
        )
    }

    pub fn insert(&mut self, c: char) {
        cursor_insert(&mut self.buf, &mut self.cursor, c);
    }

    pub fn backspace(&mut self) {
        cursor_backspace(&mut self.buf, &mut self.cursor);
    }

    pub fn delete(&mut self) {
        cursor_delete(&mut self.buf, &mut self.cursor);
    }

    pub fn move_left(&mut self) {
        cursor_move_left(&self.buf, &mut self.cursor);
    }

    pub fn move_right(&mut self) {
        cursor_move_right(&self.buf, &mut self.cursor);
    }

    pub fn move_home(&mut self) {
        cursor_move_home(&mut self.cursor);
    }

    pub fn move_end(&mut self) {
        cursor_move_end(&self.buf, &mut self.cursor);
    }
}

// Free functions for the shared-cursor pattern in InputMode forms,
// where one `cursor: usize` is reused across whichever field is active.

pub fn cursor_insert(buf: &mut String, cursor: &mut usize, c: char) {
    let pos = (*cursor).min(buf.len());
    buf.insert(pos, c);
    *cursor = pos + c.len_utf8();
}

pub fn cursor_backspace(buf: &mut String, cursor: &mut usize) {
    if *cursor == 0 {
        return;
    }
    let prev = prev_char_boundary(buf, *cursor);
    buf.drain(prev..*cursor);
    *cursor = prev;
}

pub fn cursor_delete(buf: &mut String, cursor: &mut usize) {
    if *cursor >= buf.len() {
        return;
    }
    let next = next_char_boundary(buf, *cursor);
    buf.drain(*cursor..next);
}

pub fn cursor_move_left(buf: &str, cursor: &mut usize) {
    if *cursor > 0 {
        *cursor = prev_char_boundary(buf, *cursor);
    }
}

pub fn cursor_move_right(buf: &str, cursor: &mut usize) {
    if *cursor < buf.len() {
        *cursor = next_char_boundary(buf, *cursor);
    }
}

pub fn cursor_move_home(cursor: &mut usize) {
    *cursor = 0;
}

pub fn cursor_move_end(buf: &str, cursor: &mut usize) {
    *cursor = buf.len();
}

/// Defensively splits at cursor, snapping to a char boundary if needed.
pub fn cursor_split_at(buf: &str, cursor: usize) -> (&str, &str) {
    let mut pos = cursor.min(buf.len());
    while pos > 0 && !buf.is_char_boundary(pos) {
        pos -= 1;
    }
    (&buf[..pos], &buf[pos..])
}

fn prev_char_boundary(s: &str, pos: usize) -> usize {
    let mut i = pos.saturating_sub(1);
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn next_char_boundary(s: &str, pos: usize) -> usize {
    let mut i = pos + 1;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_roundtrip() {
        let mut input = TextInput::new();
        for c in "hello".chars() {
            input.insert(c);
        }
        assert_eq!(input.value(), "hello");
        assert_eq!(input.cursor(), 5);

        input.move_left();
        input.move_left();
        input.backspace();
        assert_eq!(input.value(), "helo");
        assert_eq!(input.cursor(), 2);

        input.move_home();
        input.delete();
        assert_eq!(input.value(), "elo");

        input.move_end();
        assert_eq!(input.cursor(), 3);
    }

    #[test]
    fn multibyte_navigation_and_editing() {
        let mut input = TextInput::new();
        for c in "café".chars() {
            input.insert(c);
        }
        assert_eq!(input.value(), "café");
        assert_eq!(input.cursor(), 5); // é is 2 bytes

        input.move_left();
        assert_eq!(input.cursor(), 3);
        assert_eq!(input.split_at_cursor(), ("caf", "é"));

        input.backspace();
        assert_eq!(input.value(), "caé");

        input.move_right();
        assert_eq!(input.cursor(), 4);

        input.delete();
        assert_eq!(input.value(), "caé");
    }

    #[test]
    fn cjk_and_emoji() {
        let mut input = TextInput::new();
        input.insert('漢');
        input.insert('🎉');
        input.insert('字');
        assert_eq!(input.value(), "漢🎉字");
        assert_eq!(input.cursor(), 10); // 3 + 4 + 3

        input.move_left(); // before '字'
        assert_eq!(input.cursor(), 7);
        input.backspace(); // removes '🎉' (4 bytes)
        assert_eq!(input.value(), "漢字");
        assert_eq!(input.cursor(), 3);
    }

    #[test]
    fn insert_in_middle_of_multibyte() {
        let mut input = TextInput::with_value("aöb");
        input.move_home();
        input.move_right(); // past 'a', cursor = 1
        input.move_right(); // past 'ö', cursor = 3
        input.insert('x');
        assert_eq!(input.value(), "aöxb");
        assert_eq!(input.cursor(), 4);
    }

    #[test]
    fn boundary_nops() {
        let mut input = TextInput::with_value("x");
        input.move_home();
        input.move_left(); // already at 0
        assert_eq!(input.cursor(), 0);
        input.backspace(); // nothing to delete
        assert_eq!(input.value(), "x");

        input.move_end();
        input.move_right(); // already at end
        assert_eq!(input.cursor(), 1);
        input.delete(); // nothing to delete
        assert_eq!(input.value(), "x");

        let empty = TextInput::new();
        assert!(empty.is_empty());
        assert_eq!(empty.split_at_cursor(), ("", ""));
    }

    // Free function tests — these exercise the shared-cursor code path
    // used by InputMode forms, not the TextInput struct.

    #[test]
    fn cursor_fns_multibyte() {
        let mut buf = String::from("aéb");
        let mut cur = 0;

        cursor_move_right(&buf, &mut cur);
        assert_eq!(cur, 1); // past 'a'
        cursor_move_right(&buf, &mut cur);
        assert_eq!(cur, 3); // past 'é'

        cursor_insert(&mut buf, &mut cur, 'x');
        assert_eq!(buf, "aéxb");
        assert_eq!(cur, 4);

        cursor_backspace(&mut buf, &mut cur);
        assert_eq!(buf, "aéb");
        assert_eq!(cur, 3);

        cursor_move_left(&buf, &mut cur);
        assert_eq!(cur, 1); // back before 'é'
        cursor_delete(&mut buf, &mut cur);
        assert_eq!(buf, "ab");
        assert_eq!(cur, 1);

        cursor_move_end(&buf, &mut cur);
        assert_eq!(cur, 2);
        cursor_move_home(&mut cur);
        assert_eq!(cur, 0);
    }

    #[test]
    fn cursor_split_at_clamps() {
        let buf = "héllo";
        assert_eq!(cursor_split_at(buf, 0), ("", "héllo"));
        assert_eq!(cursor_split_at(buf, 3), ("hé", "llo"));
        assert_eq!(cursor_split_at(buf, 100), ("héllo", ""));
    }

    #[test]
    fn windowed_split() {
        let long = "a".repeat(50);

        // Cursor at end: window shows the last 10 chars
        let input = TextInput::with_value(&long);
        let (before, after) = input.split_at_cursor_windowed(10);
        assert_eq!(before, "a".repeat(10));
        assert!(after.is_empty());

        // Cursor in middle: both sides of the split are non-empty
        let mut input = TextInput::with_value(&long);
        input.move_home();
        for _ in 0..25 {
            input.move_right();
        }
        let (before, after) = input.split_at_cursor_windowed(10);
        assert!(!before.is_empty());
        assert!(!after.is_empty());
        assert_eq!(before.len() + after.len(), 10);

        // Short string: no windowing, returns full content
        let short = TextInput::with_value("hi");
        assert_eq!(
            short.split_at_cursor_windowed(40),
            ("hi".to_owned(), String::new())
        );

        // Multibyte: window boundaries snap to char boundaries
        let s: String = "é".repeat(30); // 60 bytes, 30 two-byte chars
        let mut input = TextInput::with_value(&s);
        input.move_home();
        for _ in 0..15 {
            input.move_right();
        }
        let (before, after) = input.split_at_cursor_windowed(20);
        let window = format!("{before}{after}");
        assert!(window.len() >= 20);
        assert!(window.chars().all(|c| c == 'é'));
    }

    // Fuzz: random operations on random Unicode should never panic or
    // leave the cursor at an invalid char boundary.
    #[test]
    fn fuzz_random_operations() {
        use proptest::{
            prelude::*,
            test_runner::{Config, TestRunner},
        };

        let config = Config::with_cases(500);
        let mut runner = TestRunner::new(config);
        runner
            .run(
                &proptest::collection::vec(
                    prop_oneof![
                        any::<char>().prop_map(Op::Insert),
                        Just(Op::Backspace),
                        Just(Op::Delete),
                        Just(Op::Left),
                        Just(Op::Right),
                        Just(Op::Home),
                        Just(Op::End),
                    ],
                    1..100,
                ),
                |ops| {
                    let mut input = TextInput::new();
                    for op in ops {
                        match op {
                            Op::Insert(c) => input.insert(c),
                            Op::Backspace => input.backspace(),
                            Op::Delete => input.delete(),
                            Op::Left => input.move_left(),
                            Op::Right => input.move_right(),
                            Op::Home => input.move_home(),
                            Op::End => input.move_end(),
                        }
                        // Invariant: cursor is always at a valid char boundary
                        assert!(
                            input.buf.is_char_boundary(input.cursor),
                            "cursor {} not a char boundary in {:?}",
                            input.cursor,
                            input.buf
                        );
                        // Invariant: split_at_cursor doesn't panic
                        let _ = input.split_at_cursor();
                    }
                    Ok(())
                },
            )
            .unwrap();
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert(char),
        Backspace,
        Delete,
        Left,
        Right,
        Home,
        End,
    }
}
