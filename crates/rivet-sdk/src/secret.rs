//! The [`Secret`] wrapper that keeps credentials out of logs, errors and files
//! (ARCHITECTURE.md §6.4, §7.4).

use std::fmt;

use zeroize::Zeroizing;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
