//! The [`Secret`] wrapper that keeps credentials out of logs, errors and files
//! (ARCHITECTURE.md §6.4, §7.4), and the [`SecretUri`] that references a
//! stored secret (ADR-0008).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;

/// A secret string, for example a password or a token.
///
/// - The memory is set to zero when the value is dropped.
/// - `Debug` prints a fixed marker, never the value.
/// - The type has no `Display`, no `Serialize` and no `Clone`, so the value
///   cannot reach a log, a file or a second place in memory by accident.
///
/// ```
/// use rivet_sdk::secret::Secret;
///
/// let secret = Secret::from(String::from("s3cr3t"));
/// assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
/// assert_eq!(secret.expose(), "s3cr3t");
/// ```
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Returns the secret value. This is the only way to read it.
    ///
    /// Do not copy the result into a value that lives longer than the `Secret`.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    /// Takes ownership of the string. The string is not copied.
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

const SCHEME_END: &str = "://";

/// A reference to a stored secret, for example `keychain://…`, `aws-sm://…`
/// or `gcp-sm://…` (ARCHITECTURE.md §6.3, ADR-0008).
///
/// The scheme names the secret backend. Extensions add backends, so any
/// well-formed scheme is accepted: a lowercase letter, then lowercase
/// letters, digits, `+`, `-` or `.`. A scheme without a backend fails when
/// the secret is resolved, not when the URI is parsed.
///
/// It is a reference, not a secret value, so it can be printed, cloned and
/// written to a configuration file. It serializes as its string form.
/// Parsing does no I/O and does not check that the secret exists.
///
/// ```
/// use rivet_sdk::secret::SecretUri;
///
/// let uri: SecretUri = "aws-sm://prod/db/password".parse()?;
/// assert_eq!(uri.scheme(), "aws-sm");
/// assert_eq!(uri.path(), "prod/db/password");
/// assert!("vault://prod/db".parse::<SecretUri>().is_ok());
/// assert!("prod-db".parse::<SecretUri>().is_err());
/// # Ok::<(), rivet_sdk::error::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretUri {
    uri: String,
    scheme_len: usize,
}

impl SecretUri {
    /// Returns the scheme without `://`, for example `keychain`.
    pub fn scheme(&self) -> &str {
        &self.uri[..self.scheme_len]
    }

    /// Returns the part after `://`. It is never empty.
    pub fn path(&self) -> &str {
        &self.uri[self.scheme_len + SCHEME_END.len()..]
    }

    /// Returns the full URI.
    pub fn as_str(&self) -> &str {
        &self.uri
    }
}

impl TryFrom<String> for SecretUri {
    type Error = Error;

    /// Fails with a `user` error if the scheme is not well-formed or if the
    /// path is empty.
    fn try_from(uri: String) -> Result<Self, Error> {
        // The messages do not repeat the input: a user can put a secret value
        // in the place of the URI by mistake, and errors reach logs.
        let (scheme, path) = uri
            .split_once(SCHEME_END)
            .filter(|(scheme, _)| is_scheme(scheme))
            .ok_or_else(|| {
                Error::user(
                    "a secret URI must start with a lowercase scheme and ://, \
                     for example keychain://",
                )
            })?;
        if path.trim().is_empty() {
            return Err(Error::user(format!(
                "the secret URI {scheme}{SCHEME_END} has no path"
            )));
        }
        let scheme_len = scheme.len();
        Ok(Self { uri, scheme_len })
    }
}

/// The RFC 3986 scheme grammar, lowercase only so that a scheme has one
/// spelling when a backend is looked up.
fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
}

impl FromStr for SecretUri {
    type Err = Error;

    fn from_str(uri: &str) -> Result<Self, Error> {
        Self::try_from(uri.to_owned())
    }
}

impl From<SecretUri> for String {
    fn from(uri: SecretUri) -> Self {
        uri.uri
    }
}

impl fmt::Display for SecretUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCategory;

    #[test]
    fn secret_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Secret>();
    }

    #[test]
    fn secret_debug_never_contains_the_value() {
        let secret = Secret::from(String::from("hunter2-value"));
        for rendered in [format!("{secret:?}"), format!("{secret:#?}")] {
            assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
            assert!(rendered.contains("REDACTED"));
        }
    }

    #[test]
    fn secret_expose_returns_the_value() {
        let secret = Secret::from(String::from("hunter2-value"));
        assert_eq!(secret.expose(), "hunter2-value");
    }

    #[test]
    fn secret_uri_accepts_built_in_and_extension_schemes() {
        for (text, scheme, path) in [
            ("keychain://rivet/prod-db", "keychain", "rivet/prod-db"),
            ("aws-sm://prod/db/password", "aws-sm", "prod/db/password"),
            (
                "gcp-sm://projects/p/secrets/db",
                "gcp-sm",
                "projects/p/secrets/db",
            ),
            ("vault://prod/db", "vault", "prod/db"),
            ("x1+a-b.c://entry", "x1+a-b.c", "entry"),
        ] {
            let uri: SecretUri = text.parse().expect(text);
            assert_eq!(uri.scheme(), scheme);
            assert_eq!(uri.path(), path);
            assert_eq!(uri.as_str(), text);
            assert_eq!(uri.to_string(), text);
        }
    }

    #[test]
    fn secret_uri_rejects_malformed_schemes_and_empty_paths() {
        for text in [
            "",
            "prod-db",
            "://rivet/prod-db",
            "1pass://rivet/prod-db",
            "-sm://rivet/prod-db",
            "my vault://rivet/prod-db",
            "p@ss://word",
            "KEYCHAIN://rivet/prod-db",
            "keychain:rivet/prod-db",
            "keychain://",
            "aws-sm://",
            "gcp-sm://",
            "keychain:// ",
        ] {
            let error = text.parse::<SecretUri>().expect_err(text);
            assert_eq!(error.category(), ErrorCategory::User, "{text}");
        }
    }

    #[test]
    fn secret_uri_error_does_not_repeat_the_input() {
        let error = "hunter2-value".parse::<SecretUri>().unwrap_err();
        assert!(!error.to_string().contains("hunter2"));
    }

    #[test]
    fn secret_uri_serializes_as_its_string_form() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Holder {
            password: SecretUri,
        }
        let holder = Holder {
            password: "aws-sm://prod/db/password".parse().unwrap(),
        };
        let text = toml::to_string(&holder).unwrap();
        assert_eq!(text, "password = \"aws-sm://prod/db/password\"\n");
        assert_eq!(toml::from_str::<Holder>(&text).unwrap(), holder);
        assert!(toml::from_str::<Holder>("password = \"hunter2\"").is_err());
    }
}
