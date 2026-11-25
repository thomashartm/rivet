//! Secret store: resolves a [`SecretUri`] to a [`Secret`] through the backend
//! of the URI scheme (ARCHITECTURE.md §6.2, §6.4, §7.4, ADR-0008).
//!
//! The core has one backend, [`KeychainBackend`] for `keychain://`. Backends
//! for cloud secret managers are extensions and are registered at runtime
//! (§3.3).

use crate::Owner;
use crate::logging::{MIN_REDACTED_LEN, Redactor};
use crate::permissions::Permissions;
use crate::wasm::guest_text;
use rivet_sdk::error::{Error, Result};
use rivet_sdk::manifest::ExtensionId;
use rivet_sdk::secret::{Secret, SecretUri};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tracing::warn;

/// The scheme of the built-in [`KeychainBackend`].
pub const KEYCHAIN_SCHEME: &str = "keychain";

/// The schemes that only a built-in extension can register: an extension
/// whose id starts with the segment [`BUILT_IN_PUBLISHER`] (ADR-0020).
pub(crate) const BUILT_IN_SCHEMES: [&str; 2] = ["aws-sm", "gcp-sm"];

/// The publisher segment of the built-in extensions.
const BUILT_IN_PUBLISHER: &str = "rivet";

/// The time limit of one read of a backend that an extension registered: the
/// default of the call time limit of an extension (ADR-0021). The limit does
/// not depend on who reads. A read that takes longer
/// fails with a `retryable` error, and the future of the backend is dropped
/// (ADR-0020). The extension is not failed for it.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The maximum number of different secret values that the [`Redactor`] holds
/// for one extension (ADR-0020). Each registered value makes each log line
/// slower, so the number has a limit.
pub const MAX_VALUES_PER_OWNER: usize = 256;

/// A URI is cut to this length in an error.
/// The same limit as for a resource in a permission error.
const MAX_SHOWN_BYTES: usize = crate::permissions::MAX_RESOURCE_BYTES;

/// Returns `text` for an error message: cut to [`MAX_SHOWN_BYTES`], and with
/// each control character escaped so that it cannot start a line in a log.
fn shown(text: &str) -> String {
    crate::logging::shown(text, MAX_SHOWN_BYTES)
}

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
                "the secret URI {KEYCHAIN_SCHEME}://{} must have the form \
                 {KEYCHAIN_SCHEME}://<service>/<account>",
                shown(path)
            ))
        })
}

/// Turns a keychain failure into an SDK error that contains no secret data.
fn keychain_error(service: &str, account: &str, error: keyring::Error) -> Error {
    use keyring::Error as Keyring;
    let uri = shown(&format!("{KEYCHAIN_SCHEME}://{service}/{account}"));
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
/// - The store has no cache. Each call reads the backend again (§6.4).
/// - All methods take `&self` and are safe for concurrent use. Share the
///   store in an [`Arc`].
///
/// # Redaction
///
/// A store that was created with [`with_redactor`](Self::with_redactor)
/// registers each value it returns with the [`Redactor`]. The log output
/// then does not show the value, even if code logs it by mistake. See
/// [`Redactor`] for the trade-off and the limits.
///
/// | Reader | The value stays registered until |
/// | --- | --- |
/// | The host ([`resolve`](Self::resolve)) | [`forget`](Self::forget), or the process ends |
/// | An extension ([`ExtensionSecrets`]) | [`unregister_owner`](Self::unregister_owner) for this extension |
///
/// For an extension, the store keeps one copy of each different value in
/// memory that is set to zero, at most [`MAX_VALUES_PER_OWNER`] values. A
/// read of one more value is refused.
///
/// A value shorter than [`MIN_REDACTED_LEN`] bytes is returned and is not
/// hidden. Each read of such a value writes one `warn` event with the URI and
/// without the value (ADR-0022).
///
/// A value from a backend of an extension that is equal to the id of the
/// reading extension or of an extension that has a backend is refused with
/// a `policy` error. A value from the keychain is always registered. To hide
/// it would hide the id in the audit log. Known limit: a backend of an
/// extension can still return other words of a log line as values, and the
/// log then hides these words.
///
/// # Scheme names
///
/// Until a manifest declares its schemes (ADR-0020), the name of a scheme
/// shows who can register it:
///
/// | Scheme | Extension |
/// | --- | --- |
/// | `keychain` | None. It is the backend of the core. |
/// | `aws-sm`, `gcp-sm` | The id starts with the segment `rivet`. |
/// | Each other scheme | The scheme is the first segment of the id (the publisher), or starts with it and `-` or `.`: `acme.vault` can register `acme` and `acme-vault`. |
///
/// The store does not prove that an extension with the publisher `rivet` is
/// from the project.
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
/// store.register("acme.vault".parse()?, "acme-vault", Arc::new(Fixed))?;
/// let secret = store.resolve(&"acme-vault://prod/db/password".parse()?).await?;
/// assert_eq!(secret.expose(), "s3cr3t");
/// # Ok(())
/// # }
/// ```
pub struct SecretStore {
    backends: RwLock<HashMap<String, Registration>>,
    redactor: Option<Redactor>,
    /// The values that are registered with the redactor for each extension
    /// that read them: one registration for each entry. Empty without a
    /// redactor.
    read_by: Mutex<HashMap<Owner, Vec<Secret>>>,
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
            read_by: Mutex::default(),
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
    /// `scheme`, for example `acme-vault`.
    ///
    /// # Errors
    ///
    /// - Returns a `user` error if `scheme` is not a scheme that a
    ///   [`SecretUri`] can have, for example `AWS-SM` or the empty text.
    /// - Returns a `policy` error if `owner` cannot register a scheme with
    ///   this name. See [Scheme names](Self#scheme-names).
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
        let publisher = owner.as_str().split('.').next().unwrap_or_default();
        let permitted = if BUILT_IN_SCHEMES.contains(&scheme) {
            publisher == BUILT_IN_PUBLISHER
        } else {
            scheme
                .strip_prefix(publisher)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['-', '.']))
        };
        // `keychain` passes this check for the publisher `keychain`. It is
        // registered from the start, so it fails as a second registration.
        if !permitted {
            return Err(Error::policy(format!(
                "the extension `{owner}` cannot register the secret URI scheme `{}`: \
                 the scheme must be `{publisher}` or start with `{publisher}-` or `{publisher}.`",
                shown(scheme)
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
    ///
    /// It also removes from the redactor the values that `owner` read
    /// through its [`ExtensionSecrets`]. Call it when the extension can no
    /// longer run code: a read of `owner` that ends after this call
    /// registers its value again, and that value stays until the next call.
    /// This is a known limit (ADR-0020): the log then hides more, not less.
    pub fn unregister_owner(&self, owner: &Owner) -> usize {
        let read = self
            .read_by
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(owner);
        if let Some(redactor) = &self.redactor {
            for secret in read.iter().flatten() {
                redactor.forget(secret);
            }
        }
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
    /// A read of a backend of an extension has the limit [`READ_TIMEOUT`]:
    /// the backend is guest code. A read of the keychain has no limit: the
    /// caller sets one.
    ///
    /// # Errors
    ///
    /// - Returns a `user` error that names the scheme if no backend is
    ///   registered for it.
    /// - Returns the error of the backend if the backend fails. The error of
    ///   a backend of an extension keeps its category only: its text is
    ///   redacted, cleaned and cut as each text from an extension, and it
    ///   follows a text of the store that names the scheme. Its source is
    ///   dropped.
    /// - Returns a `retryable` error if a backend of an extension does not
    ///   answer in [`READ_TIMEOUT`].
    /// - Returns a `policy` error if a backend of an extension returns a
    ///   value that is equal to the id of an extension that has a backend.
    ///   See [Redaction](Self#redaction).
    pub async fn resolve(&self, uri: &SecretUri) -> Result<Secret> {
        self.resolve_for(None, uri).await
    }

    /// [`resolve`](Self::resolve) for the extension `reader`, or for the
    /// host (`None`).
    async fn resolve_for(&self, reader: Option<&Owner>, uri: &SecretUri) -> Result<Secret> {
        let scheme = uri.scheme();
        let (backend, of_extension) = self
            .backends
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(scheme)
            .map(|registration| {
                (
                    Arc::clone(&registration.backend),
                    registration.owner.is_some(),
                )
            })
            .ok_or_else(|| {
                Error::user(format!(
                    "no secret backend is registered for the scheme `{}`",
                    shown(scheme)
                ))
            })?;
        let read = backend.resolve(uri.path());
        // The limit is for a backend of an extension, for each reader: the
        // backend is guest code. The keychain can ask the user, who can
        // need more time (ADR-0020).
        let result = if of_extension {
            let Ok(result) = tokio::time::timeout(READ_TIMEOUT, read).await else {
                return Err(Error::retryable(format!(
                    "the secret backend for the scheme `{}` did not answer in {} s",
                    shown(scheme),
                    READ_TIMEOUT.as_secs()
                )));
            };
            result
        } else {
            read.await
        };
        let secret = match result {
            Err(error) if of_extension => return Err(self.backend_error(scheme, &error)),
            result => result?,
        };
        if secret.expose().len() < MIN_REDACTED_LEN {
            // The event has the URI and never the value (ADR-0022).
            warn!(
                uri = %shown(&uri.to_string()),
                reader = reader.map_or("core", Owner::as_str),
                "a secret value is shorter than {MIN_REDACTED_LEN} bytes; the log cannot hide it"
            );
        }
        if let Some(redactor) = &self.redactor {
            self.register_value(redactor, reader, of_extension, &secret)?;
        }
        Ok(secret)
    }

    /// Builds the error for a failure of a backend of an extension. The text
    /// of such a backend is text from a guest (ADR-0020).
    ///
    /// The source is dropped: guest code made it, it has no length limit, and
    /// it can hold a secret value that is not registered for redaction yet.
    fn backend_error(&self, scheme: &str, error: &Error) -> Error {
        let redactor = self.redactor.clone().unwrap_or_default();
        let text = guest_text(&redactor, error.message());
        let message = format!(
            "the secret backend for the scheme `{}` failed: {text}",
            shown(scheme)
        );
        Error::new(error.category(), message)
    }

    /// Registers the value of `secret` with `redactor`: for the extension
    /// `reader` until [`unregister_owner`](Self::unregister_owner), for the
    /// host (`None`) until [`forget`](Self::forget).
    fn register_value(
        &self,
        redactor: &Redactor,
        reader: Option<&Owner>,
        of_extension: bool,
        secret: &Secret,
    ) -> Result<()> {
        let value = secret.expose();
        let is_id = |id: Option<&Owner>| id.is_some_and(|id| id.as_str() == value);
        // A value of the keychain backend is always registered (ADR-0020).
        let is_known_id = of_extension
            && (is_id(reader)
                || self
                    .backends
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .values()
                    .any(|registration| is_id(registration.owner.as_ref())));
        if is_known_id {
            // The text has no value and no id: the value is the id.
            return Err(Error::policy(
                "the secret value is equal to the id of an extension: the log cannot hide it \
                 and show the id",
            ));
        }
        let Some(reader) = reader else {
            redactor.register(secret);
            return Ok(());
        };
        // The redactor ignores such a value: no entry is necessary.
        if value.len() < MIN_REDACTED_LEN {
            return Ok(());
        }
        let mut read_by = self.read_by.lock().unwrap_or_else(PoisonError::into_inner);
        let values = read_by.entry(reader.clone()).or_default();
        if values.iter().any(|known| known.expose() == value) {
            return Ok(());
        }
        if values.len() >= MAX_VALUES_PER_OWNER {
            return Err(Error::policy(format!(
                "the extension `{reader}` read {MAX_VALUES_PER_OWNER} different secret values, \
                 which is the limit: a new value is refused until the extension is unloaded"
            )));
        }
        redactor.register(secret);
        values.push(Secret::from(value.to_owned()));
        if values.len() == MAX_VALUES_PER_OWNER {
            // Here and not at each refused read: one event for each time
            // the limit is reached.
            warn!(
                extension = %reader,
                limit = MAX_VALUES_PER_OWNER,
                "an extension read the maximum number of different secret values; \
                 the next new value is refused"
            );
        }
        Ok(())
    }

    /// Takes back a secret that [`resolve`](Self::resolve) returned to the
    /// host: removes its value from the redactor and drops the secret, which
    /// sets its memory to zero.
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
///   no backend. The read asks again when the backend has answered: a
///   revoke during the read denies it, and the value is dropped.
/// - The service exists only for a store with a [`Redactor`], so each value
///   that an extension gets is hidden in the log (§7.4).
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
///   still holds. The values that the extension read stay hidden until the
///   host calls [`SecretStore::unregister_owner`] for it; this includes a
///   value of a denied read.
/// - An extension can read [`MAX_VALUES_PER_OWNER`] (256) different values.
///   Then a read of a new value is refused with a `policy` error; a value
///   that the extension read before can still be read. A secret that rotates
///   is a new value at each rotation, so such an extension reaches the limit
///   and is then refused. The values stay after [`Permissions::revoke`] and
///   after the service is dropped. The only recovery is to unload the
///   extension ([`SecretStore::unregister_owner`]).
///
/// ```
/// use rivet_core::logging::Redactor;
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
/// let store = Arc::new(SecretStore::with_redactor(Redactor::new()));
/// let secrets = ExtensionSecrets::new(store, permissions, manifest.id)?;
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
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if `store` has no [`Redactor`]
    /// ([`SecretStore::new`]): the log could show a value that the extension
    /// got (§7.4).
    pub fn new(
        store: Arc<SecretStore>,
        permissions: Arc<Permissions>,
        extension: ExtensionId,
    ) -> Result<Self> {
        if store.redactor.is_none() {
            return Err(Error::internal(format!(
                "the secret service of the extension `{extension}` needs a secret store with \
                 a redactor"
            )));
        }
        Ok(Self {
            store,
            permissions,
            extension,
        })
    }

    /// Reads the secret that `uri` references, as [`SecretStore::resolve`]
    /// does, if a granted namespace of the extension contains `uri`.
    ///
    /// # Errors
    ///
    /// - Returns the `policy` error of [`Permissions::check_secret`] if the
    ///   read is not granted. The denied read is logged and no backend is
    ///   called.
    /// - Returns the same error if the grant ends during the read of the
    ///   backend.
    /// - Returns a `retryable` error if a backend of an extension does not
    ///   answer in [`READ_TIMEOUT`]. A read of the keychain has no limit.
    /// - Returns the errors of [`SecretStore::resolve`].
    /// - Returns a `policy` error if the value is equal to the id of the
    ///   extension, or if the extension has read
    ///   [`MAX_VALUES_PER_OWNER`] different values and this is a new one.
    pub async fn resolve(&self, uri: &SecretUri) -> Result<Secret> {
        self.permissions.check_secret(&self.extension, uri)?;
        let secret = self.store.resolve_for(Some(&self.extension), uri).await?;
        // The grant can end while the backend works. The value is dropped
        // here; it stays registered with the redactor.
        self.permissions.check_secret(&self.extension, uri)?;
        Ok(secret)
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
    use crate::logging::{Capture, Level, LogFormat, REDACTED, capture_logs};
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
        "rivet.aws".parse().unwrap()
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
        for scheme in ["aws-sm", "rivet", "rivet-x+y.z-1"] {
            store
                .register(owner(), scheme, InMemory::with(&[]))
                .expect(scheme);
        }
    }

    #[tokio::test]
    async fn unregister_owner_removes_the_backends_of_that_owner_only() {
        let store = SecretStore::new();
        let other: Owner = "rivet.gcp".parse().unwrap();
        for scheme in ["aws-sm", "rivet-ps"] {
            store
                .register(owner(), scheme, InMemory::with(&[("a", "value")]))
                .unwrap();
        }
        store
            .register(other.clone(), "gcp-sm", InMemory::with(&[("a", "value")]))
            .unwrap();

        assert_eq!(store.unregister_owner(&owner()), 2);
        assert_eq!(store.unregister_owner(&owner()), 0);

        for scheme in ["aws-sm", "rivet-ps"] {
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

    /// [`service_with`] a counting backend.
    fn extension_secrets(
        redactor: Redactor,
    ) -> (ExtensionSecrets, Arc<Permissions>, Arc<Counting>) {
        let backend = Arc::new(Counting::default());
        let (secrets, permissions, _) = service_with(&redactor, Arc::clone(&backend) as _);
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
            let _guard = capture_logs(&capture.dispatch(Level::WARN, LogFormat::Human, &redactor));
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

    /// A backend that waits in each read until the test releases it.
    #[derive(Default)]
    struct Gated {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl SecretBackend for Gated {
        fn resolve<'a>(&'a self, _path: &'a str) -> SecretFuture<'a> {
            Box::pin(async {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(Secret::from(String::from("hunter2-value")))
            })
        }
    }

    /// A backend that returns the path as the value, so the caller chooses
    /// the value.
    struct Echo;

    impl SecretBackend for Echo {
        fn resolve<'a>(&'a self, path: &'a str) -> SecretFuture<'a> {
            Box::pin(async move { Ok(Secret::from(path.to_owned())) })
        }
    }

    /// A backend that fails with the error that `0` builds.
    struct Failing(fn() -> Error);

    impl SecretBackend for Failing {
        fn resolve<'a>(&'a self, _path: &'a str) -> SecretFuture<'a> {
            Box::pin(async { Err((self.0)()) })
        }
    }

    fn reader() -> Owner {
        "acme.postgres".parse().unwrap()
    }

    /// Awaits a read that must end at [`READ_TIMEOUT`]. A read without the
    /// limit fails the test here; without this bound it waits without end.
    async fn bounded<T>(read: impl Future<Output = T>) -> T {
        tokio::time::timeout(READ_TIMEOUT * 2, read)
            .await
            .expect("the read has no time limit")
    }

    /// Adds `backend` for the scheme `built-in` as the keychain is added:
    /// without an owner.
    fn register_built_in(store: &SecretStore, backend: Arc<dyn SecretBackend>) {
        store
            .backends
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                String::from("built-in"),
                Registration {
                    owner: None,
                    backend,
                },
            );
    }

    /// The secret service of `acme.postgres` (namespace `acme-postgres`) on
    /// a store in which `rivet.aws` owns `backend` for the scheme `aws-sm`.
    fn service_with(
        redactor: &Redactor,
        backend: Arc<dyn SecretBackend>,
    ) -> (ExtensionSecrets, Arc<Permissions>, Arc<SecretStore>) {
        let manifest = Manifest::parse(
            "id = \"acme.postgres\"\nversion = \"1.0.0\"\nsdk = \">=0.1.0\"\n\
             [capabilities]\nsecrets = [\"acme-postgres\"]\n",
        )
        .unwrap();
        let permissions = Arc::new(Permissions::new());
        permissions
            .grant(&manifest, manifest.capabilities.clone())
            .unwrap();
        let store = Arc::new(SecretStore::with_redactor(redactor.clone()));
        store.register(owner(), "aws-sm", backend).unwrap();
        let secrets =
            ExtensionSecrets::new(Arc::clone(&store), Arc::clone(&permissions), manifest.id)
                .unwrap();
        (secrets, permissions, store)
    }

    #[tokio::test]
    async fn a_revoke_during_the_backend_read_denies_the_read() {
        let redactor = Redactor::new();
        let backend = Arc::new(Gated::default());
        let (secrets, permissions, store) = service_with(&redactor, Arc::clone(&backend) as _);
        let granted = uri("aws-sm://acme-postgres/prod");

        let revoke_during_the_read = async {
            backend.entered.notified().await;
            assert!(permissions.revoke(&reader()));
            backend.release.notify_one();
        };
        let (result, ()) = tokio::join!(secrets.resolve(&granted), revoke_during_the_read);

        let error = result.expect_err("the read ended after the revoke");
        assert_eq!(error.category(), ErrorCategory::Policy);
        assert!(!rendered(&error).contains("hunter2"));
        // The value was in memory: it stays hidden in the log until the
        // reader is released.
        assert_eq!(redactor.redact("hunter2-value"), REDACTED);
        store.unregister_owner(&reader());
        assert_eq!(redactor.redact("hunter2-value"), "hunter2-value");
    }

    #[tokio::test(start_paused = true)]
    async fn a_backend_that_does_not_answer_fails_after_the_time_limit() {
        let (secrets, _, _) = service_with(&Redactor::new(), Arc::new(Gated::default()));
        let start = tokio::time::Instant::now();
        let read = uri("aws-sm://acme-postgres/prod");
        let error = bounded(secrets.resolve(&read)).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Retryable);
        assert!(error.message().contains("`aws-sm`"), "{error}");
        assert_eq!(start.elapsed(), READ_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_core_read_of_an_extension_backend_has_the_time_limit_too() {
        let (_, _, store) = service_with(&Redactor::new(), Arc::new(Gated::default()));
        let start = tokio::time::Instant::now();
        let read = uri("aws-sm://acme-postgres/prod");
        let error = bounded(store.resolve(&read)).await.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Retryable);
        assert!(error.message().contains("`aws-sm`"), "{error}");
        assert_eq!(start.elapsed(), READ_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_built_in_backend_that_does_not_answer_has_no_time_limit() {
        let built_in = Arc::new(Gated::default());
        let (secrets, _, store) = service_with(&Redactor::new(), Arc::new(Gated::default()));
        register_built_in(&store, Arc::clone(&built_in) as _);
        let read = uri("built-in://acme-postgres/prod");
        let mut resolve = std::pin::pin!(secrets.resolve(&read));
        let waited = tokio::time::timeout(READ_TIMEOUT * 10, &mut resolve).await;
        assert!(waited.is_err(), "the read ended without an answer");
        built_in.release.notify_one();
        assert_eq!(resolve.await.unwrap().expose(), "hunter2-value");
    }

    #[tokio::test]
    async fn a_value_that_is_an_extension_id_is_refused_and_does_not_hide_the_audit_log() {
        let redactor = Redactor::new();
        let backend = InMemory::with(&[
            ("acme-postgres/reader", "acme.postgres"),
            ("acme-postgres/owner", "rivet.aws"),
            ("acme-postgres/prod", "hunter2-value"),
        ]);
        let (secrets, _, store) = service_with(&redactor, backend);
        let capture = Capture::default();
        {
            let _guard = capture_logs(&capture.dispatch(Level::WARN, LogFormat::Human, &redactor));
            for id in ["reader", "owner"] {
                let read = uri(&format!("aws-sm://acme-postgres/{id}"));
                let error = secrets.resolve(&read).await.expect_err(id);
                assert_eq!(error.category(), ErrorCategory::Policy, "{id}");
                assert!(!rendered(&error).contains("acme.postgres"), "{error}");
            }
            // The host reads the id of a backend owner.
            let error = store.resolve(&uri("aws-sm://acme-postgres/owner")).await;
            assert_eq!(error.unwrap_err().category(), ErrorCategory::Policy);
            // A denied read: the audit line must show the extension.
            secrets
                .resolve(&uri("aws-sm://other/prod"))
                .await
                .unwrap_err();
        }
        let output = capture.text();
        assert!(output.contains("extension=acme.postgres"), "{output}");
        assert_eq!(redactor.redact("rivet.aws"), "rivet.aws");

        // Each other value is still hidden.
        let read = uri("aws-sm://acme-postgres/prod");
        let secret = secrets.resolve(&read).await.unwrap();
        assert_eq!(redactor.redact(secret.expose()), REDACTED);
    }

    #[tokio::test]
    async fn a_built_in_value_that_is_an_extension_id_is_registered() {
        let redactor = Redactor::new();
        let (secrets, _, store) = service_with(&redactor, InMemory::with(&[]));
        let built_in = InMemory::with(&[
            ("acme-postgres/reader", "acme.postgres"),
            ("acme-postgres/owner", "rivet.aws"),
        ]);
        register_built_in(&store, built_in);

        // An extension reads its id, and the host reads the id of a backend
        // owner: a secret of the user is never left without redaction.
        let read = uri("built-in://acme-postgres/reader");
        assert_eq!(
            secrets.resolve(&read).await.unwrap().expose(),
            "acme.postgres"
        );
        assert_eq!(redactor.redact("acme.postgres"), REDACTED);
        let read = uri("built-in://acme-postgres/owner");
        assert_eq!(store.resolve(&read).await.unwrap().expose(), "rivet.aws");
        assert_eq!(redactor.redact("rivet.aws"), REDACTED);
    }

    #[tokio::test]
    async fn unregister_owner_removes_the_values_that_the_owner_read_from_the_redactor() {
        let redactor = Redactor::new();
        let (secrets, _, store) = service_with(&redactor, Arc::new(Echo));
        // Two reads of one value are one entry.
        for path in ["acme-postgres/1", "acme-postgres/1", "acme-postgres/2"] {
            secrets
                .resolve(&uri(&format!("aws-sm://{path}")))
                .await
                .unwrap();
        }
        let of_the_host = store.resolve(&uri("aws-sm://acme-postgres/2")).await;
        assert_eq!(
            redactor.redact("acme-postgres/1 acme-postgres/2"),
            format!("{REDACTED} {REDACTED}")
        );

        // The owner of the backend is not the reader.
        assert_eq!(store.unregister_owner(&reader()), 0);
        assert_eq!(
            redactor.redact("acme-postgres/1 acme-postgres/2"),
            format!("acme-postgres/1 {REDACTED}")
        );
        // The registration of the host is still there, exactly once.
        store.forget(of_the_host.unwrap());
        assert_eq!(redactor.redact("acme-postgres/2"), "acme-postgres/2");
    }

    #[tokio::test]
    async fn an_extension_cannot_fill_the_redactor_without_limit() {
        let redactor = Redactor::new();
        let (secrets, _, store) = service_with(&redactor, Arc::new(Echo));
        let read = |name: &str| uri(&format!("aws-sm://acme-postgres/{name}"));
        let capture = Capture::default();
        let refused = {
            let _guard = capture_logs(&capture.dispatch(Level::WARN, LogFormat::Human, &redactor));
            for n in 0..MAX_VALUES_PER_OWNER {
                secrets.resolve(&read(&format!("value-{n}"))).await.unwrap();
            }
            // A known value is not a new entry.
            secrets.resolve(&read("value-0")).await.unwrap();
            let refused = secrets.resolve(&read("one-too-many")).await;
            let _ = secrets.resolve(&read("two-too-many")).await;
            refused
        };
        let error = refused.expect_err("the limit is reached");
        assert_eq!(error.category(), ErrorCategory::Policy);
        assert!(!rendered(&error).contains("one-too-many"));
        // The refused value is not in the redactor, and the log says why once.
        assert_eq!(redactor.redact("one-too-many"), "one-too-many");
        let output = capture.text();
        assert_eq!(output.lines().count(), 1, "{output}");
        assert!(output.contains("acme.postgres"), "{output}");

        // The limit is for one extension, and it ends when the host
        // releases the extension.
        let of_the_host = store.resolve(&read("three-too-many")).await;
        assert_eq!(redactor.redact(of_the_host.unwrap().expose()), REDACTED);
        store.unregister_owner(&reader());
        assert_eq!(redactor.redact("value-0 value-255"), "value-0 value-255");
        secrets.resolve(&read("two-too-many")).await.unwrap();
    }

    #[test]
    fn the_name_of_a_scheme_shows_who_can_register_it() {
        let store = SecretStore::new();
        let acme: Owner = "acme.vault".parse().unwrap();
        for scheme in [
            "aws-sm",
            "gcp-sm",
            KEYCHAIN_SCHEME,
            "rivet",
            "acm",
            "acmevault",
            "evil-acme",
        ] {
            let error = store
                .register(acme.clone(), scheme, Arc::new(Echo))
                .expect_err(scheme);
            assert_eq!(error.category(), ErrorCategory::Policy, "{scheme}");
            assert!(error.message().contains(scheme), "{error}");
        }
        for scheme in ["acme", "acme-vault", "acme.vault"] {
            store
                .register(acme.clone(), scheme, Arc::new(Echo))
                .expect(scheme);
        }
        for scheme in ["aws-sm", "gcp-sm", "rivet-ps"] {
            store
                .register(owner(), scheme, Arc::new(Echo))
                .expect(scheme);
        }
        for scheme in [KEYCHAIN_SCHEME, "acme-2"] {
            let error = store.register(owner(), scheme, Arc::new(Echo));
            assert_eq!(error.expect_err(scheme).category(), ErrorCategory::Policy);
        }
        let keychain: Owner = "keychain.x".parse().unwrap();
        let error = store.register(keychain, KEYCHAIN_SCHEME, Arc::new(Echo));
        assert_eq!(error.unwrap_err().category(), ErrorCategory::Policy);
    }

    #[test]
    fn a_store_without_a_redactor_gets_no_secret_service() {
        let error = ExtensionSecrets::new(
            Arc::new(SecretStore::new()),
            Arc::new(Permissions::new()),
            reader(),
        )
        .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Internal);
    }

    #[tokio::test]
    async fn a_long_uri_is_cut_in_an_error() {
        const MIB: usize = 1024 * 1024;
        let store = SecretStore::new();
        let no_backend = uri(&format!("{}://x", "a".repeat(MIB)));
        let no_account = uri(&format!("keychain://{}", "a".repeat(MIB)));
        for long in [&no_backend, &no_account] {
            let error = store.resolve(long).await.unwrap_err();
            assert_eq!(error.category(), ErrorCategory::User);
            assert!(error.message().len() < MAX_SHOWN_BYTES + 300);
            assert!(error.message().contains(&"a".repeat(MAX_SHOWN_BYTES)));
        }
        let control = uri("keychain://line\nbreak\u{1b}[2J");
        let error = store.resolve(&control).await.unwrap_err();
        assert!(!error.message().contains(['\n', '\u{1b}']), "{error:?}");
        assert!(error.message().contains("line\\nbreak"), "{error}");

        let entry = keychain_error("s", &"é".repeat(MIB), keyring::Error::NoEntry);
        assert!(entry.message().len() < MAX_SHOWN_BYTES + 300);
    }

    #[tokio::test]
    async fn a_text_over_the_limit_is_cut_at_a_character_and_gets_the_mark() {
        // The first `MAX_SHOWN_BYTES` bytes, then the mark.
        let long = "a".repeat(MAX_SHOWN_BYTES + 1);
        let error = SecretStore::new()
            .resolve(&uri(&format!("{long}://x")))
            .await
            .unwrap_err();
        assert_eq!(
            error.message(),
            format!(
                "no secret backend is registered for the scheme `{}…`",
                "a".repeat(MAX_SHOWN_BYTES)
            )
        );
        // A text of exactly the limit is not cut.
        let exact = "a".repeat(MAX_SHOWN_BYTES);
        let error = keychain_entry(&exact).unwrap_err();
        assert!(error.message().contains(&format!("//{exact} must")));

        // `é` is two bytes. It is kept whole if it ends at the limit, and
        // left out if the limit is in it.
        for (fits, expected) in [(2, "é…"), (1, "…")] {
            let start = "a".repeat(MAX_SHOWN_BYTES - fits);
            let error = keychain_entry(&format!("{start}éé")).unwrap_err();
            assert_eq!(
                error.message(),
                format!(
                    "the secret URI keychain://{start}{expected} must have the form \
                     keychain://<service>/<account>"
                )
            );
        }
    }

    #[tokio::test]
    async fn a_value_too_short_for_redaction_is_one_warning_without_the_value() {
        let redactor = Redactor::new();
        let backend = InMemory::with(&[
            ("acme-postgres/short", "zq9"),
            ("acme-postgres/prod", "zq9x"),
        ]);
        let (secrets, _, store) = service_with(&redactor, backend);
        let read = |name: &str| uri(&format!("aws-sm://acme-postgres/{name}"));
        let lines = |read: SecretUri, of_extension: bool| {
            let (secrets, store, redactor) = (&secrets, &store, &redactor);
            async move {
                let capture = Capture::default();
                {
                    let _guard =
                        capture_logs(&capture.dispatch(Level::WARN, LogFormat::Human, redactor));
                    if of_extension {
                        secrets.resolve(&read).await.unwrap();
                    } else {
                        store.resolve(&read).await.unwrap();
                    }
                }
                capture.text()
            }
        };

        let output = lines(read("short"), true).await;
        assert_eq!(output.lines().count(), 1, "{output}");
        for part in [
            "WARN",
            "shorter than 4 bytes",
            "uri=aws-sm://acme-postgres/short",
            "reader=\"acme.postgres\"",
        ] {
            assert!(output.contains(part), "no {part} in: {output}");
        }
        assert!(!output.contains("zq9"), "{output}");

        let output = lines(read("short"), false).await;
        assert_eq!(output.lines().count(), 1, "{output}");
        assert!(output.contains("reader=\"core\""), "{output}");
        assert!(!output.contains("zq9"), "{output}");

        // A value of the minimum length is redacted: no event.
        assert_eq!(lines(read("prod"), true).await, "");
    }

    #[tokio::test]
    async fn the_error_of_an_extension_backend_is_wrapped() {
        let redactor = Redactor::new();
        redactor.register(&Secret::from(String::from("hunter2-value")));
        let store = SecretStore::with_redactor(redactor);
        let failing = Failing(|| {
            let long = "x".repeat(1 << 20);
            Error::auth(format!("denied\n\u{1b}[2J for hunter2-value {long}"))
                .with_source(std::io::Error::other("source with unknown content"))
        });
        store
            .register(owner(), "aws-sm", Arc::new(failing))
            .unwrap();
        let error = store.resolve(&uri("aws-sm://prod/db")).await.unwrap_err();

        // The category stays. The text is the text of the store, then the
        // text of the backend: redacted, cut, and with no control character.
        assert_eq!(error.category(), ErrorCategory::Auth);
        let start = "the secret backend for the scheme `aws-sm` failed: \
                     denied  [2J for [REDACTED] xxx";
        assert!(
            error.message().starts_with(start),
            "{:.120}",
            error.message()
        );
        // The limit of each text from an extension: 8 KiB.
        assert!(error.message().len() < 8 * 1024 + 300);
        assert!(!rendered(&error).contains("unknown content"));
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
