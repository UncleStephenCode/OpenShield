use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use thiserror::Error;

const MAX_LOCALE_INPUT_BYTES: usize = 64;
const MAX_RESOURCE_BYTES: usize = 128 * 1024;
const MAX_MESSAGES: usize = 272;
const MAX_MESSAGE_CHARS: usize = 8_192;
const MAX_FORMATTED_MESSAGE_BYTES: usize = 64 * 1024;

macro_rules! define_locales {
    ($( $variant:ident => ($code:literal, $resource:expr) ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum Locale {
            $( $variant ),+
        }

        impl Locale {
            #[cfg(test)]
            pub const SUPPORTED: &'static [Self] = &[
                $( Self::$variant ),+
            ];

            pub const fn code(self) -> &'static str {
                match self {
                    $( Self::$variant => $code ),+
                }
            }

            const fn resource(self) -> &'static str {
                match self {
                    $( Self::$variant => $resource ),+
                }
            }

            fn from_language(language: &str) -> Option<Self> {
                match language {
                    $( $code => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

define_locales! {
    En => ("en", include_str!("../locales/en.json")),
    Ru => ("ru", include_str!("../locales/ru.json")),
    Zh => ("zh", include_str!("../locales/zh.json")),
    Es => ("es", include_str!("../locales/es.json")),
    Hi => ("hi", include_str!("../locales/hi.json")),
    Ar => ("ar", include_str!("../locales/ar.json")),
    Pt => ("pt", include_str!("../locales/pt.json")),
    Fr => ("fr", include_str!("../locales/fr.json")),
    De => ("de", include_str!("../locales/de.json")),
    Ja => ("ja", include_str!("../locales/ja.json")),
    Ko => ("ko", include_str!("../locales/ko.json")),
    Id => ("id", include_str!("../locales/id.json")),
    Tr => ("tr", include_str!("../locales/tr.json")),
    It => ("it", include_str!("../locales/it.json")),
    Pl => ("pl", include_str!("../locales/pl.json")),
    Uk => ("uk", include_str!("../locales/uk.json")),
    Nl => ("nl", include_str!("../locales/nl.json")),
    Vi => ("vi", include_str!("../locales/vi.json")),
    Th => ("th", include_str!("../locales/th.json")),
    Fa => ("fa", include_str!("../locales/fa.json")),
    Be => ("be", include_str!("../locales/be.json")),
    Az => ("az", include_str!("../locales/az.json")),
    Kk => ("kk", include_str!("../locales/kk.json")),
    Uz => ("uz", include_str!("../locales/uz.json")),
    Tt => ("tt", include_str!("../locales/tt.json")),
    Ba => ("ba", include_str!("../locales/ba.json")),
    Cv => ("cv", include_str!("../locales/cv.json")),
    Ce => ("ce", include_str!("../locales/ce.json")),
    Sah => ("sah", include_str!("../locales/sah.json")),
    Tyv => ("tyv", include_str!("../locales/tyv.json")),
    Krc => ("krc", include_str!("../locales/krc.json")),
}

impl fmt::Display for Locale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl FromStr for Locale {
    type Err = LocaleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_locale(value)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LocaleError {
    #[error("invalid locale identifier")]
    Invalid,
    #[error("unsupported locale: {0}")]
    Unsupported(String),
    #[error("invalid embedded {locale} translation resource: {reason}")]
    InvalidResource {
        locale: &'static str,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub struct I18n {
    messages: Arc<BTreeMap<String, String>>,
}

impl I18n {
    pub fn load(locale: Locale) -> Result<Self, LocaleError> {
        let english = parse_resource(Locale::En)?;
        let messages = if locale == Locale::En {
            english
        } else {
            let translated = parse_resource(locale)?;
            validate_parity(locale, &english, &translated)?;
            translated
        };
        Ok(Self {
            messages: Arc::new(messages),
        })
    }

    pub fn detect() -> Result<Self, LocaleError> {
        Self::load(detect_locale_from(|name| env::var(name).ok()))
    }

    pub fn tr<'a>(&'a self, key: &'a str) -> &'a str {
        self.messages.get(key).map_or(key, String::as_str)
    }

    pub fn format(&self, key: &str, arguments: &[(&str, &str)]) -> String {
        interpolate(self.tr(key), arguments)
    }

    #[cfg(test)]
    pub fn test_english() -> Self {
        Self::load(Locale::En).unwrap_or_else(|_| Self {
            messages: Arc::new(BTreeMap::new()),
        })
    }
}

pub fn detect_locale_from(mut get: impl FnMut(&str) -> Option<String>) -> Locale {
    for variable in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
        let Some(value) = get(variable) else {
            continue;
        };
        for candidate in value.split(':') {
            match parse_locale(candidate) {
                Ok(locale) => return locale,
                Err(
                    LocaleError::Invalid
                    | LocaleError::Unsupported(_)
                    | LocaleError::InvalidResource { .. },
                ) => {}
            }
        }
    }
    Locale::En
}

fn parse_locale(value: &str) -> Result<Locale, LocaleError> {
    if value.is_empty()
        || value.len() > MAX_LOCALE_INPUT_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
        })
    {
        return Err(LocaleError::Invalid);
    }

    let (without_modifier, modifier) = value
        .split_once('@')
        .map_or((value, None), |(base, suffix)| (base, Some(suffix)));
    if modifier.is_some_and(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) || without_modifier.contains('@')
    {
        return Err(LocaleError::Invalid);
    }
    let (without_encoding, encoding) = without_modifier
        .split_once('.')
        .map_or((without_modifier, None), |(base, suffix)| {
            (base, Some(suffix))
        });
    if encoding.is_some_and(|suffix| {
        suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) || without_encoding.contains('.')
        || without_encoding.is_empty()
    {
        return Err(LocaleError::Invalid);
    }
    if without_encoding.eq_ignore_ascii_case("c") || without_encoding.eq_ignore_ascii_case("posix")
    {
        return Ok(Locale::En);
    }
    let mut components = without_encoding.split(['_', '-']);
    let language_component = components.next().ok_or(LocaleError::Invalid)?;
    if !(2..=3).contains(&language_component.len())
        || !language_component
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic())
        || components.any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(LocaleError::Invalid);
    }
    let language = language_component.to_ascii_lowercase();
    Locale::from_language(&language).ok_or(LocaleError::Unsupported(language))
}

fn parse_resource(locale: Locale) -> Result<BTreeMap<String, String>, LocaleError> {
    let resource = locale.resource();
    if resource.len() > MAX_RESOURCE_BYTES {
        return Err(resource_error(locale, "resource is too large"));
    }
    let messages = serde_json::from_str::<BTreeMap<String, String>>(resource)
        .map_err(|error| resource_error(locale, &error.to_string()))?;
    if messages.is_empty() || messages.len() > MAX_MESSAGES {
        return Err(resource_error(locale, "invalid message count"));
    }
    for (key, value) in &messages {
        if key.is_empty()
            || !key.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
            })
        {
            return Err(resource_error(locale, "invalid message key"));
        }
        if value.is_empty() || value.chars().count() > MAX_MESSAGE_CHARS {
            return Err(resource_error(locale, "invalid message length"));
        }
        if value.chars().any(|character| {
            (character.is_control() && character != '\n')
                || is_disallowed_resource_format_character(character)
        }) {
            return Err(resource_error(
                locale,
                "control or bidi-format character in message",
            ));
        }
        if contains_mixed_latin_cyrillic_token(value) {
            return Err(resource_error(
                locale,
                "mixed Latin/Cyrillic token in message",
            ));
        }
        placeholders(value).map_err(|reason| resource_error(locale, reason))?;
    }
    Ok(messages)
}

fn validate_parity(
    locale: Locale,
    english: &BTreeMap<String, String>,
    translated: &BTreeMap<String, String>,
) -> Result<(), LocaleError> {
    if english.keys().ne(translated.keys()) {
        return Err(resource_error(locale, "message keys differ from English"));
    }
    for (key, english_value) in english {
        let Some(translated_value) = translated.get(key) else {
            return Err(resource_error(locale, "message missing"));
        };
        let english_placeholders =
            placeholders(english_value).map_err(|reason| resource_error(Locale::En, reason))?;
        let translated_placeholders =
            placeholders(translated_value).map_err(|reason| resource_error(locale, reason))?;
        if english_placeholders != translated_placeholders {
            return Err(resource_error(
                locale,
                "message placeholders differ from English",
            ));
        }
        if translated_value == english_value {
            return Err(resource_error(locale, "untranslated English message"));
        }
        if translated_value.matches('\n').count() != english_value.matches('\n').count() {
            return Err(resource_error(
                locale,
                "message newline layout differs from English",
            ));
        }
    }
    Ok(())
}

fn placeholders(value: &str) -> Result<BTreeSet<&str>, &'static str> {
    let mut result = BTreeSet::new();
    let mut remainder = value;
    while let Some(start) = remainder.find('{') {
        let after_start = &remainder[start + 1..];
        let Some(end) = after_start.find('}') else {
            return Err("unclosed placeholder");
        };
        let name = &after_start[..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err("invalid placeholder");
        }
        result.insert(name);
        remainder = &after_start[end + 1..];
    }
    if remainder.contains('}') {
        return Err("unmatched closing brace");
    }
    Ok(result)
}

fn interpolate(template: &str, arguments: &[(&str, &str)]) -> String {
    let mut output = String::with_capacity(template.len().min(MAX_FORMATTED_MESSAGE_BYTES));
    let mut remainder = template;
    while let Some(start) = remainder.find('{') {
        if !push_bounded(&mut output, &remainder[..start], false) {
            return output;
        }
        let after_start = &remainder[start + 1..];
        let Some(end) = after_start.find('}') else {
            let _complete = push_bounded(&mut output, &remainder[start..], false);
            return output;
        };
        let name = &after_start[..end];
        if let Some((_, value)) = arguments.iter().find(|(candidate, _)| *candidate == name) {
            if !push_bounded(&mut output, value, true) {
                return output;
            }
        } else if !push_bounded(&mut output, "{", false)
            || !push_bounded(&mut output, name, false)
            || !push_bounded(&mut output, "}", false)
        {
            return output;
        }
        remainder = &after_start[end + 1..];
    }
    let _complete = push_bounded(&mut output, remainder, false);
    output
}

fn push_bounded(output: &mut String, value: &str, sanitize_dynamic: bool) -> bool {
    for character in value.chars() {
        let character = if sanitize_dynamic && is_unsafe_dynamic_character(character) {
            '\u{fffd}'
        } else {
            character
        };
        if output.len().saturating_add(character.len_utf8()) > MAX_FORMATTED_MESSAGE_BYTES {
            return false;
        }
        output.push(character);
    }
    true
}

fn is_disallowed_resource_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200b}'
            | '\u{200e}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
    )
}

fn contains_mixed_latin_cyrillic_token(value: &str) -> bool {
    let mut has_latin = false;
    let mut has_cyrillic = false;
    for character in value.chars() {
        if character.is_alphabetic() {
            has_latin |= is_latin_letter(character);
            has_cyrillic |= is_cyrillic_letter(character);
            if has_latin && has_cyrillic {
                return true;
            }
        } else {
            has_latin = false;
            has_cyrillic = false;
        }
    }
    false
}

fn is_latin_letter(character: char) -> bool {
    character.is_ascii_alphabetic()
        || matches!(
            character,
            '\u{00c0}'..='\u{02af}'
                | '\u{1d00}'..='\u{1dbf}'
                | '\u{1e00}'..='\u{1eff}'
                | '\u{a720}'..='\u{a7ff}'
                | '\u{ab30}'..='\u{ab6f}'
                | '\u{ff21}'..='\u{ff3a}'
                | '\u{ff41}'..='\u{ff5a}'
        )
}

fn is_cyrillic_letter(character: char) -> bool {
    matches!(
        character,
        '\u{0400}'..='\u{052f}'
            | '\u{1c80}'..='\u{1c8f}'
            | '\u{2de0}'..='\u{2dff}'
            | '\u{a640}'..='\u{a69f}'
    )
}

pub(crate) fn is_unsafe_dynamic_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

fn resource_error(locale: Locale, reason: &str) -> LocaleError {
    LocaleError::InvalidResource {
        locale: locale.code(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact equality of a few short labels is normal for related languages and
    // for protocol/product names.  Larger prose blocks are not.  The two
    // independent limits catch both copied sentences and bulk-copied short UI
    // labels without treating placeholders or common technical words as prose.
    const MAX_SHARED_NONTRIVIAL_MESSAGES: usize = 24;
    const MAX_SHARED_SUBSTANTIVE_MESSAGES: usize = 4;

    fn lexical_words(value: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut in_placeholder = false;
        for character in value.chars() {
            match character {
                '{' => {
                    if !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                    in_placeholder = true;
                }
                '}' if in_placeholder => in_placeholder = false,
                _ if in_placeholder => {}
                _ if character.is_alphabetic() => {
                    word.extend(character.to_lowercase());
                }
                _ if !word.is_empty() => words.push(std::mem::take(&mut word)),
                _ => {}
            }
        }
        if !word.is_empty() {
            words.push(word);
        }
        words
            .into_iter()
            .filter(|word| {
                !matches!(
                    word.as_str(),
                    "openshield"
                        | "tui"
                        | "tcp"
                        | "udp"
                        | "icmp"
                        | "ipc"
                        | "cidr"
                        | "uid"
                        | "gid"
                        | "pid"
                        | "inode"
                        | "cgroup"
                        | "root"
                        | "net"
                        | "admin"
                        | "ipv"
                        | "nftables"
                        | "iptables"
                        | "systemd"
                )
            })
            .collect()
    }

    fn shared_value_weight(value: &str) -> (bool, bool) {
        let words = lexical_words(value);
        let letters = words.iter().map(|word| word.chars().count()).sum::<usize>();
        (letters >= 8, words.len() >= 4 && letters >= 20)
    }

    #[test]
    fn all_resources_are_complete_without_bulk_fallbacks() -> Result<(), LocaleError> {
        assert_eq!(Locale::SUPPORTED.len(), 31);
        let english = parse_resource(Locale::En)?;
        for &locale in Locale::SUPPORTED {
            let loaded = I18n::load(locale);
            assert!(loaded.is_ok(), "{locale}: {loaded:?}");
            if locale != Locale::En {
                let translated = parse_resource(locale)?;
                assert!(
                    translated.keys().eq(english.keys()),
                    "{locale}: translation resource does not have exact key parity"
                );
                for (key, value) in &translated {
                    assert_ne!(
                        Some(value),
                        english.get(key),
                        "{locale}: English fallback remains for {key}"
                    );
                    assert_eq!(
                        value.matches('\n').count(),
                        english[key].matches('\n').count(),
                        "{locale}: newline layout differs for {key}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn emergency_quarantine_has_a_distinct_translation_in_every_locale() -> Result<(), LocaleError>
    {
        for &locale in Locale::SUPPORTED {
            let i18n = I18n::load(locale)?;
            let emergency = i18n.tr("compatibility.reason_emergency_block_all");
            assert_ne!(emergency, i18n.tr("compatibility.reason_block_all"));
            assert!(
                emergency.chars().count() >= 16,
                "{}: {emergency}",
                locale.code()
            );
        }
        Ok(())
    }

    #[test]
    fn no_locale_pair_contains_bulk_copied_messages() -> Result<(), LocaleError> {
        let resources = Locale::SUPPORTED
            .iter()
            .map(|&locale| parse_resource(locale).map(|messages| (locale, messages)))
            .collect::<Result<Vec<_>, _>>()?;

        for (left_index, (left_locale, left)) in resources.iter().enumerate() {
            for (right_locale, right) in resources.iter().skip(left_index + 1) {
                let shared = left
                    .iter()
                    .filter_map(|(key, value)| {
                        (right.get(key) == Some(value)).then_some((key, shared_value_weight(value)))
                    })
                    .collect::<Vec<_>>();
                let nontrivial = shared.iter().filter(|(_, (value, _))| *value).count();
                let substantive = shared.iter().filter(|(_, (_, value))| *value).count();
                let examples = shared
                    .iter()
                    .filter(|(_, (nontrivial, substantive))| *nontrivial || *substantive)
                    .take(5)
                    .map(|(key, _)| key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");

                assert!(
                    nontrivial <= MAX_SHARED_NONTRIVIAL_MESSAGES,
                    "{left_locale} and {right_locale} share {nontrivial} nontrivial messages; probable bulk copy (examples: {examples})"
                );
                assert!(
                    substantive <= MAX_SHARED_SUBSTANTIVE_MESSAGES,
                    "{left_locale} and {right_locale} share {substantive} substantive messages; probable bulk copy (examples: {examples})"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn resource_text_rejects_bidi_controls_and_mixed_script_tokens() {
        assert!(is_disallowed_resource_format_character('\u{202e}'));
        assert!(!is_disallowed_resource_format_character('\u{200c}'));
        assert!(contains_mixed_latin_cyrillic_token("суратlandырыу"));
        assert!(!contains_mixed_latin_cyrillic_token("IPC-сокет"));
        assert!(!contains_mixed_latin_cyrillic_token("ҫулӑх"));
    }

    #[test]
    fn locale_normalization_accepts_common_posix_forms() {
        assert_eq!(parse_locale("ru_RU.UTF-8"), Ok(Locale::Ru));
        assert_eq!(parse_locale("pt-BR"), Ok(Locale::Pt));
        assert_eq!(parse_locale("be_BY.UTF-8"), Ok(Locale::Be));
        assert_eq!(parse_locale("az_AZ.UTF-8"), Ok(Locale::Az));
        assert_eq!(parse_locale("kk_KZ.UTF-8"), Ok(Locale::Kk));
        assert_eq!(parse_locale("uz_UZ.UTF-8"), Ok(Locale::Uz));
        assert_eq!(parse_locale("tt_RU@iqtelif"), Ok(Locale::Tt));
        assert_eq!(parse_locale("C.UTF-8"), Ok(Locale::En));
    }

    #[test]
    fn every_supported_locale_code_round_trips_through_the_safe_parser() {
        for &locale in Locale::SUPPORTED {
            assert_eq!(parse_locale(locale.code()), Ok(locale));
        }
    }

    #[test]
    fn incomplete_bulk_fallback_resources_are_not_exposed() {
        for code in [
            "dar", "av", "lez", "kum", "udm", "myv", "kv", "krl", "mrj", "mhr", "mdf", "alt", "os",
            "inh", "bua", "xal", "ady", "kjh",
        ] {
            assert_eq!(
                parse_locale(code),
                Err(LocaleError::Unsupported(code.to_owned())),
                "{code} must remain unsupported until its translation is complete"
            );
        }
    }

    #[test]
    fn unknown_auto_detected_locale_falls_back_to_english() {
        let locale = detect_locale_from(|name| (name == "LANG").then(|| "xx_XX.UTF-8".to_owned()));
        assert_eq!(locale, Locale::En);
    }

    #[test]
    fn language_priority_list_uses_first_supported_locale() {
        let locale =
            detect_locale_from(|name| (name == "LANGUAGE").then(|| "xx:uk_UA:en".to_owned()));
        assert_eq!(locale, Locale::Uk);
    }

    #[test]
    fn locale_environment_precedence_is_deterministic() {
        let locale = detect_locale_from(|name| match name {
            "LC_ALL" => Some("de_DE.UTF-8".to_owned()),
            "LC_MESSAGES" => Some("fr_FR.UTF-8".to_owned()),
            "LANGUAGE" => Some("es".to_owned()),
            "LANG" => Some("ru_RU.UTF-8".to_owned()),
            _ => None,
        });
        assert_eq!(locale, Locale::De);
    }

    #[test]
    fn malicious_locale_inputs_are_rejected_without_filesystem_access() {
        for value in [
            "../../etc/passwd",
            "..\\..\\windows",
            "/tmp/ru",
            "ru\0en",
            "ru;sh",
            "ru en",
            "..",
            ".UTF-8",
            "en..UTF-8",
            "en@",
            "русский",
        ] {
            assert_eq!(parse_locale(value), Err(LocaleError::Invalid), "{value:?}");
        }
    }

    #[test]
    fn explicit_unknown_locale_is_reported() {
        assert_eq!(
            parse_locale("zz-ZZ"),
            Err(LocaleError::Unsupported("zz".to_owned()))
        );
    }

    #[test]
    fn interpolation_does_not_reinterpret_braces_or_terminal_controls() {
        let translated = interpolate("before {value} after", &[("value", "{other}\n\u{1b}[31m")]);
        assert_eq!(translated, "before {other}\u{fffd}\u{fffd}[31m after");
    }

    #[test]
    fn interpolation_output_is_bounded() {
        let oversized = "x".repeat(MAX_FORMATTED_MESSAGE_BYTES * 2);
        let translated = interpolate("{value}", &[("value", oversized.as_str())]);
        assert_eq!(translated.len(), MAX_FORMATTED_MESSAGE_BYTES);
    }
}
