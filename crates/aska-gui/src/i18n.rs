//! Strings, externalised from the first commit (C-06). English is the shipped default;
//! Swedish is the first additional language. The catalogue is embedded in the binary — the
//! client reads no files — and the choice of language lives in the session (or the encrypted
//! profile, M5b), never in a plain file, and is never sent anywhere.
//!
//! Format of `locale/*.txt`: `key = text`, `#` comments, `{name}` placeholders.

use std::cell::RefCell;
use std::collections::HashMap;

const EN: &str = include_str!("../locale/en.txt");
const SV: &str = include_str!("../locale/sv.txt");

/// Languages the client ships. The first is the fallback for missing keys.
pub const LANGUAGES: &[(&str, &str, &str)] = &[("en", "English", EN), ("sv", "Svenska", SV)];

thread_local! {
    static CURRENT: RefCell<&'static str> = const { RefCell::new("en") };
    static CATS: RefCell<HashMap<&'static str, HashMap<&'static str, &'static str>>> =
        RefCell::new(HashMap::new());
}

fn parse(src: &'static str) -> HashMap<&'static str, &'static str> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim(), v.trim()))
        })
        .collect()
}

fn lookup(lang: &str, key: &str) -> Option<&'static str> {
    let (code, src) = LANGUAGES
        .iter()
        .find(|(code, _, _)| *code == lang)
        .map(|(c, _, s)| (*c, *s))
        .unwrap_or(("en", EN));
    CATS.with(|cats| {
        let mut cats = cats.borrow_mut();
        let cat = cats.entry(code).or_insert_with(|| parse(src));
        cat.get(key).copied()
    })
}

/// Pick the language from the environment (`LC_ALL`, `LC_MESSAGES`, `LANG`), falling back
/// to English when the system's language has no translation.
pub fn init_from_env() {
    let env = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.is_empty())
        .unwrap_or_default();
    let code = env.split(['_', '.', '@']).next().unwrap_or("en");
    set_language(code);
}

/// Switch language for this session. Unknown codes select English.
pub fn set_language(code: &str) {
    let known = LANGUAGES
        .iter()
        .map(|(c, _, _)| *c)
        .find(|c| *c == code)
        .unwrap_or("en");
    CURRENT.with(|c| *c.borrow_mut() = known);
}

pub fn language() -> &'static str {
    CURRENT.with(|c| *c.borrow())
}

/// Look a key up in the current language, then English; the key itself as a last resort so
/// a missing string is visible rather than silent.
pub fn tr(key: &str) -> String {
    lookup(language(), key)
        .or_else(|| lookup("en", key))
        .map(str::to_string)
        .unwrap_or_else(|| key.to_string())
}

/// `tr` with `{name}` placeholders filled in.
pub fn trf(key: &str, args: &[(&str, &str)]) -> String {
    let mut s = tr(key);
    for (k, v) in args {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_has_every_english_key_and_nothing_else() {
        let en = parse(EN);
        assert!(en.len() > 80);
        for (code, _, src) in LANGUAGES {
            let cat = parse(src);
            let missing: Vec<_> = en.keys().filter(|k| !cat.contains_key(*k)).collect();
            let extra: Vec<_> = cat.keys().filter(|k| !en.contains_key(*k)).collect();
            assert!(missing.is_empty(), "{code}: missing {missing:?}");
            assert!(extra.is_empty(), "{code}: extra {extra:?}");
            for (k, v) in &cat {
                assert!(!v.is_empty(), "{code}: empty {k}");
                // Placeholders must match the English ones.
                let ph = |s: &str| {
                    s.split('{')
                        .skip(1)
                        .filter_map(|p| p.split('}').next())
                        .map(str::to_string)
                        .collect::<std::collections::BTreeSet<_>>()
                };
                assert_eq!(ph(v), ph(en[k]), "{code}: placeholders differ in {k}");
            }
        }
    }

    #[test]
    fn lookup_fallback_and_formatting() {
        set_language("sv");
        assert_eq!(tr("home.send"), "Skicka ett meddelande");
        assert_eq!(
            trf(
                "send.counter",
                &[("used", "12"), ("max", "2506"), ("block", "4 KiB")]
            ),
            "12 av 2506 byte · 4 KiB-block"
        );
        set_language("xx");
        assert_eq!(language(), "en");
        assert_eq!(tr("no.such.key"), "no.such.key");
        set_language("en");
    }
}
