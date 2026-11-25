//! Secret store: resolves a [`SecretUri`] to a [`Secret`] through the backend
//! of the URI scheme (ARCHITECTURE.md §6.2, §6.4, §7.4, ADR-0008).
//!
//! The core has one backend, [`KeychainBackend`] for `keychain://`. Backends
//! for cloud secret managers are extensions and are registered at runtime
//! (§3.3).

use crate::Owner;
use crate::logging::Redactor;
use crate::permissions::Permissions;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::manifest::ExtensionId;
use rivet_sdk::secret::{Secret, SecretUri};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};

/// The scheme of the built-in [`KeychainBackend`].
pub const KEYCHAIN_SCHEME: &str = "keychain";

/// The future that [`SecretBackend::resolve`] returns.
pub type SecretFuture<'a> = Pin<Box<dyn Future<Output = Result<Secret>> + Send + 'a>>;

/// A source of secrets for one URI scheme.
///
/// An implementation MUST NOT put a secret value in an error, in a log or in
/// a cache (§5.6, §6.4).
pub trait SecretBackend: Send + Sync {
    /// Reads the secret that `path` identifies. `path` is the part of the
    /// URI after `://`. It is an identifier, not a secret.
    ///
    /// Blocking work MUST run on the blocking pool (§5.1).
    fn resolve<'a>(&'a self, path: &'a str) -> SecretFuture<'a>;
}

/// The backend for `keychain://`: the keychain of the operating system.
///
/// | Platform | Store |
/// | --- | --- |
/// | macOS | Keychain Services, generic password |
/// | Windows | Credential Manager |
/// | Linux and other Unix | Secret Service (D-Bus) |
///
/// # Path
///
/// The URI is `keychain://<service>/<account>`.
///
/// - `<service>` is the text before the first `/`. It is the service name
///   of the keychain entry.
/// - `<account>` is all text after the first `/`. It is the account (user)
///   name of the keychain entry. It can contain `/`.
/// - Both parts must not be empty. The parts are used as written; there is
///   no percent-decoding, so a service name cannot contain `/`.
///
/// Example: `keychain://rivet/prod-db` reads the entry with the service
/// `rivet` and the account `prod-db`. On macOS,
/// `security add-generic-password -s rivet -a prod-db -w` creates it.
///
/// The entry must contain UTF-8 text.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeychainBackend;

impl SecretBackend for KeychainBackend {
    fn resolve<'a>(&'a self, path: &'a str) -> SecretFuture<'a> {
        Box::pin(async move {
            let (service, account) = keychain_entry(path)?;
            let (service, account) = (service.to_owned(), account.to_owned());
            // The keychain call blocks, and it can wait for the user (§5.1).
            tokio::task::spawn_blocking(move || {
                keyring::Entry::new(&service, &account)
                    .and_then(|entry| entry.get_password())
                    .map(Secret::from)
                    .map_err(|error| keychain_error(&service, &account, error))
            })
            .await
            // No source: a panic message has unknown content.
            .unwrap_or_else(|_| Err(Error::internal("the keychain task did not complete")))
        })
    }
}

/// Splits a `keychain://` path into the service and the account.
fn keychain_entry(path: &str) -> Result<(&str, &str)> {
    path.split_once('/')
        .filter(|(service, account)| !service.is_empty() && !account.is_empty())
        .ok_or_else(|| {
            Error::user(format!(
                "the secret URI {KEYCHAIN_SCHEME}://{path} must have the form \
                 {KEYCHAIN_SCHEME}://<service>/<account>"
            ))
        })
}

/// Turns a keychain failure into an SDK error that contains no secret data.
fn keychain_error(service: &str, account: &str, error: keyring::Error) -> Error {
    use keyring::Error as Keyring;
    let uri = format!("{KEYCHAIN_SCHEME}://{service}/{account}");
    match error {
        Keyring::NoEntry => Error::user(format!("the keychain has no entry for {uri}")),
        // These two variants carry the bytes of the entry. Drop them.
        Keyring::BadEncoding(_) | Keyring::BadDataFormat(..) => Error::user(format!(
            "the keychain entry for {uri} is not valid UTF-8 text"
        )),
        // This variant carries the entries. Drop them.
        Keyring::Ambiguous(_) => {
            Error::user(format!("the keychain has more than one entry for {uri}"))
        }
        Keyring::NoStorageAccess(_) => Error::auth(format!(
            "the keychain is locked or it denied access to {uri}"
        ))
        .with_source(error),
        Keyring::NoDefaultStore => {
            Error::connectivity("the keychain of the operating system is not available")
                .with_source(error)
        }
        _ => Error::internal(format!("the keychain failed to read {uri}")).with_source(error),
    }
}

/// Resolves secret URIs. One backend is registered per URI scheme.
///
/// - `keychain` is registered from the start ([`KeychainBackend`]). It has
///   no owner, so it cannot be removed.
/// - The store keeps no secret values. Each call reads the backend again
///   (§6.4).
/// - All methods take `&self` and are safe for concurrent use. Share the
///   store in an [`Arc`].
///
/// # Redaction
///
/// A store that was created with [`with_redactor`](Self::with_redactor)
/// registers each value it returns with the [`Redactor`]. The log output
/// then does not show the value, even if code logs it by mistake.
///
/// The value stays registered until the secret is given back with
/// [`forget`](Self::forget), or until the process ends. See [`Redactor`] for
/// the trade-off and the limits.
///
/// ```
/// use rivet_core::secrets::{SecretBackend, SecretFuture, SecretStore};
/// use rivet_sdk::secret::Secret;
/// use std::sync::Arc;
///
/// struct Fixed;
///
/// impl SecretBackend for Fixed {
///     fn resolve<'a>(&'a self, _path: &'a str) -> SecretFuture<'a> {
///         Box::pin(async { Ok(Secret::from(String::from("s3cr3t"))) })
///     }
/// }
///
/// # async fn example() -> rivet_sdk::error::Result<()> {
/// let store = SecretStore::new();
/// store.register("acme.aws".parse()?, "aws-sm", Arc::new(Fixed))?;
/// let secret = store.resolve(&"aws-sm://prod/db/password".parse()?).await?;
/// assert_eq!(secret.expose(), "s3cr3t");
/// # Ok(())
/// # }
/// ```
pub struct SecretStore {
    backends: RwLock<HashMap<String, Registration>>,
    redactor: Option<Redactor>,
}

struct Registration {
    /// `None` for the built-in backend.
    owner: Option<Owner>,
    backend: Arc<dyn SecretBackend>,
}

impl SecretStore {
    /// Creates a store with the keychain backend and without redaction.
    pub fn new() -> Self {
        let keychain = Registration {
            owner: None,
            backend: Arc::new(KeychainBackend),
        };
        Self {
            backends: RwLock::new(HashMap::from([(KEYCHAIN_SCHEME.to_owned(), keychain)])),
            redactor: None,
        }
    }

    /// Creates a store with the keychain backend. The store registers each
    /// value it returns with `redactor`.
    pub fn with_redactor(redactor: Redactor) -> Self {
        Self {
            redactor: Some(redactor),
            ..Self::new()
        }
    }

    /// Registers `backend` of the extension `owner` for the URI scheme
    /// `scheme`, for example `aws-sm`.
    ///
    /// # Errors
    ///
    /// - Returns a `user` error if `scheme` is not a scheme that a
    ///   [`SecretUri`] can have, for example `AWS-SM` or the empty text.
    /// - Returns a `policy` error if the scheme already has a backend. The
    ///   first registration stays.
    pub fn register(
        &self,
        owner: Owner,
        scheme: &str,
        backend: Arc<dyn SecretBackend>,
    ) -> Result<()> {
        // `SecretUri` owns the scheme grammar. The comparison refuses a
        // scheme such as `a://b`, where the parser stops at the first `://`.
        let well_formed = format!("{scheme}://x")
            .parse::<SecretUri>()
            .is_ok_and(|uri| uri.scheme() == scheme);
        if !well_formed {
            return Err(Error::user(format!(
                "{scheme:?} is not a valid secret URI scheme: a scheme is a lowercase letter, \
                 then lowercase letters, digits, `+`, `-` or `.`"
            )));
        }
        let mut backends = self
            .backends
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match backends.entry(scheme.to_owned()) {
            Entry::Occupied(_) => Err(Error::policy(format!(
                "a secret backend for the scheme `{scheme}` is already registered"
            ))),
            Entry::Vacant(free) => {
                free.insert(Registration {
                    owner: Some(owner),
                    backend,
                });
                Ok(())
            }
        }
    }

    /// Removes every backend of `owner`. Returns how many were removed.
    ///
    /// The built-in keychain backend has no owner and stays.
    pub fn unregister_owner(&self, owner: &Owner) -> usize {
        let mut backends = self
            .backends
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let before = backends.len();
        backends.retain(|_, registration| registration.owner.as_ref() != Some(owner));
        before - backends.len()
    }

    /// Reads the secret that `uri` references from the backend of its scheme.
    ///
    /// # Errors
    ///
    /// - Returns a `user` error that names the scheme if no backend is
    ///   registered for it.
    /// - Returns the error of the backend if the backend fails.
    pub async fn resolve(&self, uri: &SecretUri) -> Result<Secret> {
        let backend = self
            .backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(uri.scheme())
            .map(|registration| Arc::clone(&registration.backend))
            .ok_or_else(|| {
                Error::user(format!(
                    "no secret backend is registered for the scheme `{}`",
                    uri.scheme()
                ))
            })?;
        let secret = backend.resolve(uri.path()).await?;
        if let Some(redactor) = &self.redactor {
            redactor.register(&secret);
        }
        Ok(secret)
    }

    /// Takes back a secret that [`resolve`](Self::resolve) returned: removes
    /// its value from the redactor and drops the secret, which sets its
    /// memory to zero.
    ///
    /// Call this when the connection attempt that used the secret ends
    /// (§6.4). After this call the log output no longer hides the value.
    pub fn forget(&self, secret: Secret) {
        if let Some(redactor) = &self.redactor {
            redactor.forget(&secret);
        }
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The secret service of one extension (§7.4): reads a secret only in a
/// namespace that the user granted to the extension.
///
/// The host creates one service per extension. It is the only way for an
/// extension to get a secret value.
///
/// - Each read asks [`Permissions::check_secret`] first. A denied read calls
///   no backend.
/// - A namespace applies to every scheme (ADR-0020), so an extension can read
///   through a backend that another extension registered.
/// - The service gives no access to the [`SecretStore`]: an extension cannot
///   read out of its namespaces and cannot register or remove a backend.
/// - The grant is read at each call. After [`Permissions::revoke`] the next
///   read is denied. A [`Secret`] that the extension got before stays in the
///   memory of the extension: a revoke cannot take it back. To stop the use
///   of such a value, the host must deactivate the extension.
/// - The service has no `forget`. The redactor is shared by the process: an
///   extension must not remove a value that the host or another extension
///   still holds. Only the host calls [`SecretStore::forget`].
///
/// ```
/// use rivet_core::permissions::Permissions;
/// use rivet_core::secrets::{ExtensionSecrets, SecretStore};
/// use rivet_sdk::manifest::Manifest;
/// use std::sync::Arc;
///
/// # async fn example() -> rivet_sdk::error::Result<()> {
/// let manifest = Manifest::parse(
///     r#"
///     id = "acme.postgres"
///     version = "1.4.0"
///     sdk = ">=0.1.0, <0.2.0"
///
///     [capabilities]
///     secrets = ["acme-postgres"]
///     "#,
/// )?;
/// let permissions = Arc::new(Permissions::new());
/// permissions.grant(&manifest, manifest.capabilities.clone())?;
/// let secrets = ExtensionSecrets::new(Arc::new(SecretStore::new()), permissions, manifest.id);
///
/// let denied = secrets.resolve(&"keychain://other/prod".parse()?).await;
/// assert!(denied.is_err());
/// # Ok(())
/// # }
/// ```
///
/// The store is not reachable:
///
/// ```compile_fail
/// fn store(secrets: &rivet_core::secrets::ExtensionSecrets) {
///     let _ = &secrets.store;
/// }
/// ```
///
/// ```compile_fail
/// fn store(secrets: &rivet_core::secrets::ExtensionSecrets) {
///     let _: &rivet_core::secrets::SecretStore = &**secrets;
/// }
/// ```
pub struct ExtensionSecrets {
    store: Arc<SecretStore>,
    permissions: Arc<Permissions>,
    extension: ExtensionId,
}

impl ExtensionSecrets {
    /// Creates the secret service of `extension`.
    pub fn new(
        store: Arc<SecretStore>,
        permissions: Arc<Permissions>,
        extension: ExtensionId,
    ) -> Self {
        Self {
            store,
            permissions,
            extension,
        }
    }

    /// Reads the secret that `uri` references, as [`SecretStore::resolve`]
    /// does, if a granted namespace of the extension contains `uri`.
    ///
    /// # Errors
    ///
    /// - Returns the `policy` error of [`Permissions::check_secret`] if the
    ///   read is not granted. The denied read is logged and no backend is
    ///   called.
    /// - Returns the errors of [`SecretStore::resolve`].
    pub async fn resolve(&self, uri: &SecretUri) -> Result<Secret> {
        self.permissions.check_secret(&self.extension, uri)?;
        self.store.resolve(uri).await
    }
}

impl fmt::Debug for ExtensionSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtensionSecrets")
            .field("extension", &self.extension)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{Capture, Level, LogFormat, capture_logs};
    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::manifest::Manifest;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing::info;

    /// A backend that holds its secrets in memory.
    #[derive(Default)]
    struct InMemory(HashMap<&'static str, &'static str>);

    impl InMemory {
        fn with(entries: &[(&'static str, &'static str)]) -> Arc<Self> {
            Arc::new(Self(entries.iter().copied().collect()))
        }
    }

    impl SecretBackend for InMemory {
        fn resolve<'a>(&'a self, path: &'a str) -> SecretFuture<'a> {
            Box::pin(async move {
                self.0
                    .get(path)
                    .map(|value| Secret::from((*value).to_owned()))
                    .ok_or_else(|| Error::user(format!("no secret at `{path}`")))
            })
        }
    }

    fn owner() -> Owner {
        "acme.aws".parse().unwrap()
    }

    fn uri(text: &str) -> SecretUri {
        text.parse().expect(text)
    }

    /// The error as text in every form a log or a report can show.
    fn rendered(error: &Error) -> String {
        let mut text = format!("{error} {error:?} {error:#?} {}", error.message());
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            text.push_str(&format!(" {cause} {cause:?}"));
            source = cause.source();
        }
        text
    }

    #[tokio::test]
    async fn the_backend_is_chosen_by_the_uri_scheme() {
        let store = SecretStore::new();
        store
            .register(
                owner(),
                "aws-sm",
                InMemory::with(&[("prod/db", "aws-value")]),
            )
            .unwrap();
        store
            .register(
                owner(),
                "gcp-sm",
                InMemory::with(&[("prod/db", "gcp-value")]),
            )
            .unwrap();

        let aws = store.resolve(&uri("aws-sm://prod/db")).await.unwrap();
        assert_eq!(aws.expose(), "aws-value");
        let gcp = store.resolve(&uri("gcp-sm://prod/db")).await.unwrap();
        assert_eq!(gcp.expose(), "gcp-value");
    }

    #[tokio::test]
    async fn a_scheme_without_a_backend_is_a_user_error_that_names_the_scheme() {
        let store = SecretStore::new();
        let error = store.resolve(&uri("gcp-sm://prod/db")).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("`gcp-sm`"), "{error}");
    }

    #[tokio::test]
    async fn keychain_is_registered_from_the_start() {
        // The path has no account, so the keychain backend answers without
        // a call to the operating system.
        let error = SecretStore::new()
            .resolve(&uri("keychain://service-only"))
            .await
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(
            error.message().contains("keychain://<service>/<account>"),
            "{error}"
        );
    }

    #[test]
    fn a_second_backend_for_a_scheme_fails_and_the_first_stays() {
        let store = SecretStore::new();
        store
            .register(owner(), "aws-sm", InMemory::with(&[]))
            .unwrap();
        for scheme in ["aws-sm", KEYCHAIN_SCHEME] {
            let error = store
                .register(owner(), scheme, InMemory::with(&[]))
                .unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Policy);
            assert!(error.message().contains(scheme), "{error}");
        }
    }

    #[tokio::test]
    async fn a_scheme_that_no_secret_uri_can_have_is_a_user_error() {
        let store = SecretStore::new();
        for scheme in ["AWS-SM", "", "has space", "1aws", "aws://sm", "aws:", "äws"] {
            let error = store
                .register(owner(), scheme, InMemory::with(&[]))
                .expect_err(scheme);
            assert_eq!(error.category(), ErrorCategory::User, "{scheme}");
        }
        // Nothing was registered.
        assert_eq!(store.unregister_owner(&owner()), 0);
        for scheme in ["aws-sm", "a", "x+y.z-1"] {
            store
                .register(owner(), scheme, InMemory::with(&[]))
                .expect(scheme);
        }
    }

    #[tokio::test]
    async fn unregister_owner_removes_the_backends_of_that_owner_only() {
        let store = SecretStore::new();
        let other: Owner = "acme.gcp".parse().unwrap();
        for scheme in ["aws-sm", "aws-ps"] {
            store
                .register(owner(), scheme, InMemory::with(&[("a", "value")]))
                .unwrap();
        }
        store
            .register(other.clone(), "gcp-sm", InMemory::with(&[("a", "value")]))
            .unwrap();

        assert_eq!(store.unregister_owner(&owner()), 2);
        assert_eq!(store.unregister_owner(&owner()), 0);

        for scheme in ["aws-sm", "aws-ps"] {
            let error = store
                .resolve(&uri(&format!("{scheme}://a")))
                .await
                .unwrap_err();
            assert!(error.message().contains("no secret backend"), "{error}");
        }
        store.resolve(&uri("gcp-sm://a")).await.unwrap();
        // The scheme is free again, and the keychain backend is still there.
        store
            .register(other, "aws-sm", InMemory::with(&[]))
            .unwrap();
        let keychain = store.register(owner(), KEYCHAIN_SCHEME, InMemory::with(&[]));
        assert!(keychain.is_err());
    }

    #[tokio::test]
    async fn the_error_of_a_failing_backend_does_not_contain_a_secret_value() {
        let store = SecretStore::new();
        store
            .register(
                owner(),
                "aws-sm",
                InMemory::with(&[("prod/db", "hunter2-value")]),
            )
            .unwrap();
        let error = store
            .resolve(&uri("aws-sm://prod/other"))
            .await
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("prod/other"), "{error}");
        assert!(
            !rendered(&error).contains("hunter2"),
            "{}",
            rendered(&error)
        );
    }

    #[test]
    fn keychain_errors_do_not_contain_the_bytes_of_the_entry() {
        let bytes = || b"hunter2-value\xff".to_vec();
        let source = || {
            Box::new(std::io::Error::other("bad format"))
                as Box<dyn std::error::Error + Send + Sync>
        };
        for error in [
            keyring::Error::BadEncoding(bytes()),
            keyring::Error::BadDataFormat(bytes(), source()),
        ] {
            let error = keychain_error("rivet", "prod-db", error);
            assert_eq!(error.category(), ErrorCategory::User);
            assert!(error.message().contains("keychain://rivet/prod-db"));
            // `hunter2` as text and as the byte list that `Debug` prints.
            let text = rendered(&error);
            assert!(!text.contains("hunter2"), "{text}");
            assert!(!text.contains("104, 117, 110"), "{text}");
        }
    }

    #[test]
    fn keychain_errors_have_a_category_and_keep_the_source() {
        use std::error::Error as _;
        let platform = || {
            Box::new(std::io::Error::other("locked")) as Box<dyn std::error::Error + Send + Sync>
        };

        let missing = keychain_error("rivet", "prod-db", keyring::Error::NoEntry);
        assert_eq!(missing.category(), ErrorCategory::User);
        assert!(missing.message().contains("keychain://rivet/prod-db"));

        let locked = keychain_error("s", "a", keyring::Error::NoStorageAccess(platform()));
        assert_eq!(locked.category(), ErrorCategory::Auth);
        assert!(locked.source().is_some());

        let absent = keychain_error("s", "a", keyring::Error::NoDefaultStore);
        assert_eq!(absent.category(), ErrorCategory::Connectivity);

        let failed = keychain_error("s", "a", keyring::Error::PlatformFailure(platform()));
        assert_eq!(failed.category(), ErrorCategory::Internal);
        assert!(failed.source().is_some());
    }

    #[test]
    fn keychain_path_is_service_then_account() {
        assert_eq!(
            keychain_entry("rivet/prod-db").unwrap(),
            ("rivet", "prod-db")
        );
        assert_eq!(
            keychain_entry("rivet/team/db").unwrap(),
            ("rivet", "team/db")
        );
        for path in ["rivet", "rivet/", "/prod-db", "/"] {
            let error = keychain_entry(path).unwrap_err();
            assert_eq!(error.category(), ErrorCategory::User, "{path}");
        }
    }

    #[tokio::test]
    async fn a_value_from_the_store_does_not_appear_in_log_output() {
        let redactor = Redactor::new();
        let store = SecretStore::with_redactor(redactor.clone());
        store
            .register(
                owner(),
                "aws-sm",
                InMemory::with(&[("prod/db", "hunter2-\"value\"")]),
            )
            .unwrap();
        let secret = store.resolve(&uri("aws-sm://prod/db")).await.unwrap();

        for format in [LogFormat::Human, LogFormat::Json] {
            let capture = Capture::default();
            {
                let _guard = capture_logs(&capture.dispatch(Level::INFO, format, &redactor));
                // The mistake: code logs the exposed value.
                info!("connecting with password {}", secret.expose());
                info!(password = secret.expose(), debug = ?secret.expose(), "connecting");
            }
            let output = capture.text();
            assert_eq!(output.lines().count(), 2, "{output}");
            assert!(output.contains("connecting"), "{output}");
            assert!(!output.contains("hunter2"), "{format:?} leaked: {output}");
            assert!(!output.contains("value"), "{format:?} leaked: {output}");
        }

        // After `forget`, the value is no longer registered.
        store.forget(secret);
        assert_eq!(redactor.redact("hunter2-\"value\""), "hunter2-\"value\"");
    }

    #[tokio::test]
    async fn a_store_without_a_redactor_resolves_and_forgets() {
        let store = SecretStore::default();
        store
            .register(
                owner(),
                "aws-sm",
                InMemory::with(&[("prod/db", "hunter2-value")]),
            )
            .unwrap();
        let secret = store.resolve(&uri("aws-sm://prod/db")).await.unwrap();
        assert_eq!(secret.expose(), "hunter2-value");
        store.forget(secret);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_store_is_shared_between_tasks() {
        let store = Arc::new(SecretStore::with_redactor(Redactor::new()));
        store
            .register(
                owner(),
                "aws-sm",
                InMemory::with(&[("prod/db", "hunter2-value")]),
            )
            .unwrap();
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let secret = store.resolve(&uri("aws-sm://prod/db")).await?;
                    store.forget(secret);
                    Ok::<(), Error>(())
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }

    /// A backend that counts its calls.
    #[derive(Default)]
    struct Counting(AtomicUsize);

    impl SecretBackend for Counting {
        fn resolve<'a>(&'a self, _path: &'a str) -> SecretFuture<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(Secret::from(String::from("hunter2-value"))) })
        }
    }

    /// The secret service of `acme.postgres` with the granted namespace
    /// `acme-postgres`. The scheme `aws-sm` has a counting backend that
    /// another extension registered.
    fn extension_secrets(
        redactor: Redactor,
    ) -> (ExtensionSecrets, Arc<Permissions>, Arc<Counting>) {
        let manifest = Manifest::parse(
            "id = \"acme.postgres\"\nversion = \"1.0.0\"\nsdk = \">=0.1.0\"\n\
             [capabilities]\nsecrets = [\"acme-postgres\"]\n",
        )
        .unwrap();
        let permissions = Arc::new(Permissions::new());
        permissions
            .grant(&manifest, manifest.capabilities.clone())
            .unwrap();
        let backend = Arc::new(Counting::default());
        let store = Arc::new(SecretStore::with_redactor(redactor));
        store
            .register(owner(), "aws-sm", Arc::clone(&backend) as _)
            .unwrap();
        let secrets = ExtensionSecrets::new(store, Arc::clone(&permissions), manifest.id);
        (secrets, permissions, backend)
    }

    #[tokio::test]
    async fn an_extension_reads_a_secret_in_a_granted_namespace_only() {
        let (secrets, _, backend) = extension_secrets(Redactor::new());
        let secret = secrets
            .resolve(&uri("aws-sm://acme-postgres/prod"))
            .await
            .unwrap();
        assert_eq!(secret.expose(), "hunter2-value");
        assert_eq!(backend.0.load(Ordering::SeqCst), 1);

        // The permission check runs first: no backend is called.
        for denied in [
            "aws-sm://other/prod",
            "aws-sm://acme-postgres-2/prod",
            "aws-sm://acme-postgres/../other/prod",
        ] {
            let error = secrets.resolve(&uri(denied)).await.unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Policy, "{denied}");
        }
        assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_denied_read_names_the_extension_and_the_resource_and_is_logged() {
        let redactor = Redactor::new();
        let (secrets, _, backend) = extension_secrets(redactor.clone());
        let capture = Capture::default();
        let error = {
            let _guard = tracing::dispatcher::set_default(&capture.dispatch(
                Level::WARN,
                LogFormat::Human,
                &redactor,
            ));
            secrets.resolve(&uri("aws-sm://other/prod")).await
        }
        .unwrap_err();

        assert_eq!(error.category(), ErrorCategory::Policy);
        let output = capture.text();
        assert_eq!(output.lines().count(), 1, "{output}");
        for part in ["acme.postgres", "secrets", "aws-sm://other/prod"] {
            assert!(error.message().contains(part), "no {part} in: {error}");
            assert!(output.contains(part), "no {part} in: {output}");
        }
        assert!(output.contains("permission denied"), "{output}");
        assert!(!rendered(&error).contains("hunter2"));
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_debug_form_of_the_service_shows_the_extension_only() {
        let (secrets, _, _) = extension_secrets(Redactor::new());
        let _secret = secrets
            .resolve(&uri("aws-sm://acme-postgres/prod"))
            .await
            .unwrap();
        assert_eq!(
            format!("{secrets:?}"),
            "ExtensionSecrets { extension: ExtensionId(\"acme.postgres\"), .. }"
        );
    }

    #[tokio::test]
    async fn a_value_from_the_service_is_registered_with_the_redactor() {
        let redactor = Redactor::new();
        let (secrets, _, _) = extension_secrets(redactor.clone());
        assert_eq!(redactor.redact("hunter2-value"), "hunter2-value");
        let _secret = secrets
            .resolve(&uri("aws-sm://acme-postgres/prod"))
            .await
            .unwrap();
        assert!(!redactor.redact("hunter2-value").contains("hunter2"));
    }

    #[tokio::test]
    async fn after_revoke_the_next_read_is_denied() {
        let (secrets, permissions, backend) = extension_secrets(Redactor::new());
        let granted = uri("aws-sm://acme-postgres/prod");
        secrets.resolve(&granted).await.unwrap();

        assert!(permissions.revoke(&"acme.postgres".parse().unwrap()));
        let error = secrets.resolve(&granted).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    }

    /// Reads a real entry from the keychain of this machine.
    ///
    /// Ignored: CI runs on headless Linux without a secret service, and on a
    /// desktop the keychain can ask the user for permission. Run it with
    /// `cargo test -p rivet-core -- --ignored real_keychain`.
    #[tokio::test]
    #[ignore = "needs the keychain of the operating system"]
    async fn real_keychain_entry_is_resolved() {
        let (service, account) = ("rivet-test-secret-store", "issue-9");
        let entry = keyring::Entry::new(service, account).unwrap();
        entry.set_password("hunter2-value").unwrap();

        let store = SecretStore::new();
        let found = store
            .resolve(&uri(&format!("keychain://{service}/{account}")))
            .await;
        // Remove the test entry before any assertion can fail.
        entry.delete_credential().unwrap();
        let missing = store
            .resolve(&uri(&format!("keychain://{service}/{account}")))
            .await;

        assert_eq!(found.unwrap().expose(), "hunter2-value");
        assert_eq!(missing.unwrap_err().category(), ErrorCategory::User);
    }
}
