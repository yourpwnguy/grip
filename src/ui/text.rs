//! Text measurement and fitting for report lines.
//!
//! Split out of `panel` because these are pure string functions with no
//! knowledge of sections, colors, or columns. The pcap table uses them
//! directly too.

/// Split `s` into lines of at most `max` display columns.
///
/// Wraps on whitespace where possible and hard-splits words longer than a
/// whole line (fingerprints and cipher names contain no spaces). Every
/// character survives except runs of whitespace collapse at wrap points.
#[must_use]
pub fn wrap(s: &str, max: usize) -> Vec<String> {
    if max == 0 {
        return vec![s.to_string()];
    }
    if s.chars().count() <= max {
        return vec![s.to_string()];
    }

    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_len = 0usize;

    for word in s.split_whitespace() {
        let mut rest = word;

        if cur_len > 0 {
            let wl = rest.chars().count();
            if cur_len + 1 + wl <= max {
                cur.push(' ');
                cur.push_str(rest);
                cur_len += 1 + wl;
                continue;
            }
            if wl > max {
                // A word longer than a whole line fills the current line
                // with its head, then hard-splits below.
                let room = max.saturating_sub(cur_len + 1);
                if room > 0 {
                    let (head, tail) = split_at_char(rest, room);
                    cur.push(' ');
                    cur.push_str(head);
                    rest = tail;
                }
            }
            out.push(std::mem::take(&mut cur));
        }

        // `cur` is empty; `rest` may still be longer than one line.
        if rest.chars().count() <= max {
            cur.push_str(rest);
            cur_len = rest.chars().count();
            continue;
        }
        let mut chars = rest.chars();
        loop {
            let chunk: String = chars.by_ref().take(max).collect();
            if chars.as_str().is_empty() {
                cur_len = chunk.chars().count();
                cur = chunk;
                break;
            }
            out.push(chunk);
        }
    }

    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Split at char index `at` (or at the end if shorter).
fn split_at_char(s: &str, at: usize) -> (&str, &str) {
    match s.char_indices().nth(at) {
        Some((i, _)) => s.split_at(i),
        None => (s, ""),
    }
}

/// Truncate to `max` display columns, marking elision with `…`.
///
/// Only the pcap table uses this: its columns must stay aligned, and table
/// cells are already short. Everything else wraps via [`wrap`].
#[must_use]
pub fn truncate(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}
