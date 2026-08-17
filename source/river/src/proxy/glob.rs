//! Glob matching for header names
//!
//! Requirement 6 of the milestone asks for header removal "on a glob or regex
//! matching basis". Regular expressions were already there; this is the other
//! half.
//!
//! A dependency would be the obvious answer, but the globs that appear in a
//! header rule are the simple kind - `x-internal-*`, `*-debug` - and matching
//! them is a well understood algorithm. Pulling in a crate for it would also
//! bring path-oriented semantics, where `*` does not cross a `/`, which is
//! wrong for header names.
//!
//! `*` matches any run of characters, including none. `?` matches exactly one.
//! Matching is case-insensitive, because header names are.

/// A compiled glob pattern
#[derive(Debug, Clone)]
pub struct Glob {
    /// Kept for equality and for error messages
    pattern: String,

    /// Lowercased once, so matching does not have to
    lowered: Vec<char>,
}

impl PartialEq for Glob {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for Glob {}

impl Glob {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            lowered: pattern.to_lowercase().chars().collect(),
        }
    }

    /// Does `text` match this pattern?
    ///
    /// A two-pointer walk with a backtrack point at the most recent `*`. This
    /// runs in time proportional to the length of the input rather than
    /// exponentially, which the naive recursive version does not - and a
    /// header name is attacker-supplied, so that difference matters.
    pub fn is_match(&self, text: &str) -> bool {
        let text: Vec<char> = text.to_lowercase().chars().collect();
        let pattern = &self.lowered;

        let (mut t, mut p) = (0usize, 0usize);
        // Where to resume if the current attempt fails: the `*` we last passed,
        // and how much of the text it had consumed.
        let mut star: Option<(usize, usize)> = None;

        while t < text.len() {
            match pattern.get(p) {
                Some('*') => {
                    // Try matching nothing first, and remember we can give the
                    // `*` another character if that fails.
                    star = Some((p, t));
                    p += 1;
                }
                Some('?') => {
                    t += 1;
                    p += 1;
                }
                Some(&c) if c == text[t] => {
                    t += 1;
                    p += 1;
                }
                _ => match star {
                    Some((star_p, star_t)) => {
                        // Let the `*` swallow one more character and retry.
                        p = star_p + 1;
                        t = star_t + 1;
                        star = Some((star_p, star_t + 1));
                    }
                    None => return false,
                },
            }
        }

        // Any pattern left over has to be `*`s, which can match nothing.
        pattern[p..].iter().all(|&c| c == '*')
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        let g = Glob::new("x-secret");
        assert!(g.is_match("x-secret"));
        assert!(!g.is_match("x-secrets"));
        assert!(!g.is_match("y-secret"));
    }

    #[test]
    fn header_names_match_case_insensitively() {
        let g = Glob::new("X-Internal-*");
        assert!(g.is_match("x-internal-trace"));
        assert!(g.is_match("X-INTERNAL-TRACE"));
    }

    #[test]
    fn a_star_matches_any_run_including_nothing() {
        let g = Glob::new("x-*-id");
        assert!(g.is_match("x--id"));
        assert!(g.is_match("x-request-id"));
        assert!(g.is_match("x-a-b-c-id"));
        assert!(!g.is_match("x-request-idx"));
    }

    #[test]
    fn a_question_mark_matches_exactly_one() {
        let g = Glob::new("x-?");
        assert!(g.is_match("x-a"));
        assert!(!g.is_match("x-"));
        assert!(!g.is_match("x-ab"));
    }

    #[test]
    fn a_bare_star_matches_everything() {
        let g = Glob::new("*");
        assert!(g.is_match(""));
        assert!(g.is_match("anything"));
    }

    #[test]
    fn trailing_stars_may_match_nothing() {
        assert!(Glob::new("abc*").is_match("abc"));
        assert!(Glob::new("abc***").is_match("abc"));
    }

    /// The case that makes the backtracking version blow up. It should return
    /// promptly rather than taking exponential time in the number of stars.
    #[test]
    fn many_stars_against_a_long_name_stays_fast() {
        let g = Glob::new("*a*a*a*a*a*a*a*a*b");
        let text = "a".repeat(2048);
        assert!(!g.is_match(&text));
    }
}
