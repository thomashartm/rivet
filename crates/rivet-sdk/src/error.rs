//! Error types shared across the extension contract (ARCHITECTURE.md §5.6).

use std::fmt;

/// Result type of the SDK. The error type defaults to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The kind of failure. A caller uses it to decide how to react.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCategory {
    /// The input was wrong. The user can correct it.
    User,
    /// Authentication or authorisation failed.
    Auth,
    /// The endpoint could not be reached, or the connection was lost.
    Connectivity,
    /// The database reported an error.
    Database,
    /// A guard blocked the operation.
    Policy,
    /// The operation was cancelled.
    Cancelled,
    /// The operation failed, but the same operation can succeed if it is tried again.
    Retryable,
    /// A defect in the host or in an extension.
    Internal,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::Auth => "auth",
            Self::Connectivity => "connectivity",
            Self::Database => "database",
            Self::Policy => "policy",
            Self::Cancelled => "cancelled",
            Self::Retryable => "retryable",
            Self::Internal => "internal",
        })
    }
}

/// The one error type of the SDK: a category, a message and an optional source.
///
/// The message and the source MUST NOT contain secrets (§5.6).
/// `Display` prints `<category>: <message>`.
///
/// ```
/// use rivet_sdk::error::{Error, ErrorCategory};
///
/// let error = Error::connectivity("handshake failed")
///     .with_source(std::io::Error::other("socket closed"));
/// assert_eq!(error.category(), ErrorCategory::Connectivity);
/// assert_eq!(error.to_string(), "connectivity: handshake failed");
/// ```
#[derive(Debug)]
pub struct Error {
    category: ErrorCategory,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            source: None,
        }
    }

    /// Creates an error of the category [`ErrorCategory::User`].
    pub fn user(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::User, message)
    }

    /// Creates an error of the category [`ErrorCategory::Auth`].
    pub fn auth(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Auth, message)
    }

    /// Creates an error of the category [`ErrorCategory::Connectivity`].
    pub fn connectivity(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Connectivity, message)
    }

    /// Creates an error of the category [`ErrorCategory::Database`].
    pub fn database(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Database, message)
    }

    /// Creates an error of the category [`ErrorCategory::Policy`].
    pub fn policy(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Policy, message)
    }

    /// Creates an error of the category [`ErrorCategory::Cancelled`].
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Cancelled, message)
    }

    /// Creates an error of the category [`ErrorCategory::Retryable`].
    pub fn retryable(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Retryable, message)
    }

    /// Creates an error of the category [`ErrorCategory::Internal`].
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Internal, message)
    }

    /// Sets the error that caused this error. It replaces an earlier source.
    #[must_use]
    pub fn with_source(
        mut self,
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Returns the category of this error.
    pub fn category(&self) -> ErrorCategory {
        self.category
    }

    /// Returns the message for a human reader, without the category.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.category, self.message)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn each_constructor_sets_its_category() {
        let cases = [
            (Error::user("m"), ErrorCategory::User),
            (Error::auth("m"), ErrorCategory::Auth),
            (Error::connectivity("m"), ErrorCategory::Connectivity),
            (Error::database("m"), ErrorCategory::Database),
            (Error::policy("m"), ErrorCategory::Policy),
            (Error::cancelled("m"), ErrorCategory::Cancelled),
            (Error::retryable("m"), ErrorCategory::Retryable),
            (Error::internal("m"), ErrorCategory::Internal),
        ];
        for (error, category) in cases {
            assert_eq!(error.category(), category);
            assert_eq!(error.message(), "m");
        }
    }

    #[test]
    fn category_display_is_the_lowercase_name() {
        let names = [
            (ErrorCategory::User, "user"),
            (ErrorCategory::Auth, "auth"),
            (ErrorCategory::Connectivity, "connectivity"),
            (ErrorCategory::Database, "database"),
            (ErrorCategory::Policy, "policy"),
            (ErrorCategory::Cancelled, "cancelled"),
            (ErrorCategory::Retryable, "retryable"),
            (ErrorCategory::Internal, "internal"),
        ];
        for (category, name) in names {
            assert_eq!(category.to_string(), name);
        }
    }

    #[test]
    fn error_display_is_category_then_message() {
        let error = Error::connectivity(String::from("host unreachable"));
        assert_eq!(error.to_string(), "connectivity: host unreachable");
    }

    #[test]
    fn error_without_source_has_no_source() {
        assert!(Error::user("bad input").source().is_none());
    }

    #[test]
    fn source_chain_is_reachable_over_two_levels() {
        let root = std::io::Error::other("socket closed");
        let middle = Error::connectivity("handshake failed").with_source(root);
        let top = Error::retryable("query failed").with_source(middle);

        let first = top.source().expect("first level");
        assert_eq!(first.to_string(), "connectivity: handshake failed");
        let second = first.source().expect("second level");
        assert_eq!(second.to_string(), "socket closed");
        assert!(second.source().is_none());
    }

    #[test]
    fn error_is_send_sync_static() {
        fn assert_bounds<T: Send + Sync + 'static>() {}
        assert_bounds::<Error>();
    }

    #[test]
    fn result_alias_defaults_to_sdk_error() {
        fn fails() -> Result<()> {
            Err(Error::internal("boom"))
        }
        assert_eq!(fails().unwrap_err().category(), ErrorCategory::Internal);
    }
}
