//! Permission service: holds the capabilities that were granted to each
//! extension and decides each resource access (ARCHITECTURE.md §4.7, §7.3,
//! §7.4).
//!
//! The service decides. It does not open a connection, a file or a secret.
//! The code that reaches the resource (a host import) asks first.
//!
//! # Rules
//!
//! - Deny by default: an extension without a grant gets no access.
//! - A grant uses the capability types of the manifest
//!   ([`Capabilities`]). It cannot contain more than the manifest requests.
//! - A denied access returns a `policy` error and writes one `warn` log
//!   event. Both name the extension, the capability and the requested
//!   resource. A resource is a host and port, a path, a secret URI or a
//!   clipboard operation. It is never a secret value. A requested host is
//!   cut to 255 bytes (the maximum length of a DNS name) in both.
//!
//! # Network
//!
//! - The host must be equal to a granted host. The comparison ignores ASCII
//!   case. There is no wildcard and a subdomain is not included.
//! - If the two hosts are IP addresses, the addresses are compared, so
//!   `[::1]`, `::1` and `0:0:0:0:0:0:0:1` are equal. Only the standard text
//!   forms are addresses; `127.1` is compared as text. Brackets are valid
//!   for an IPv6 address only: `[127.0.0.1]` is not `127.0.0.1`.
//! - The port must be in the port list of that host.
//! - The service does no name resolution. A granted name does not grant the
//!   addresses of the name, and a granted address does not grant its names.
//!   The caller MUST connect to the host that it checked.
//!
//! # Filesystem
//!
//! - A scope path is absolute, or starts with `~`, the home directory of the
//!   user. Any other scope path grants nothing, and so does a scope path
//!   with a `..` component.
//! - The home directory is read one time, when the service is created
//!   ([`Permissions::new`]). It comes from the operating system or the
//!   process environment only. A later change of the home directory does
//!   not move a `~` scope: it needs a restart of the process.
//! - The requested path must be absolute.
//! - The requested path and the scope path are resolved before they are
//!   compared: symbolic links and `..` are followed with
//!   [`std::fs::canonicalize`]. A path that does not exist yet is resolved
//!   from its nearest existing ancestor; the missing part must not contain
//!   `..`. A symbolic link whose target does not exist is denied.
//! - The resolved path must be the scope path or below it. Whole path
//!   components are compared: the scope `/data` does not include
//!   `/database`.
//! - [`FilesystemAccess::Read`] is allowed in each scope.
//!   [`FilesystemAccess::ReadWrite`] (each operation that changes the
//!   filesystem) is allowed only in a `read-write` scope.
//! - Limit: the test for symbolic links runs on Unix only. The symbolic
//!   link rules are not tested on Windows.
//!
//! # Secrets
//!
//! A secret namespace is the first segments of the path of a [`SecretUri`].
//! Segments are separated by `/`.
//!
//! - The namespace `acme-postgres` includes `keychain://acme-postgres/prod`
//!   and `aws-sm://acme-postgres/prod/password`. It does not include
//!   `keychain://acme-postgres-2/prod`.
//! - The namespace `prod/db` includes `aws-sm://prod/db/password`.
//! - The scheme is not part of the namespace. A namespace covers every
//!   backend scheme: the grant `prod/db` gives access to
//!   `keychain://prod/db/...`, to `aws-sm://prod/db/...` and to the same
//!   path in each backend that an extension registers later.
//! - A namespace that contains `://`, for example `aws-sm://prod`, grants
//!   nothing. This form is reserved for a later namespace that is limited
//!   to one scheme (ADR-0020).
//! - The comparison is exact and case-sensitive. A URI path with a `.` or
//!   `..` segment, an empty segment (`//`, or a `/` at the end) or a `%`
//!   (an encoded segment) is denied: a backend can read such a path as a
//!   path out of the namespace.
//!
//! # Update review
//!
//! The service stores the capabilities that the installed manifest
//! requested, together with the grant. [`Permissions::review_update`]
//! compares a new manifest with that request, not with the grant, so a
//! partial grant does not cause a new review (ADR-0020).
//!
//! # Clipboard
//!
//! Read and write are granted separately.
//!
//! # Example
//!
//! ```
//! use rivet_core::permissions::Permissions;
//! use rivet_sdk::manifest::Manifest;
//!
//! let manifest = Manifest::parse(
//!     r#"
//!     id = "acme.postgres"
//!     version = "1.4.0"
//!     sdk = ">=0.1.0, <0.2.0"
//!
//!     [[capabilities.network]]
//!     host = "db.example.com"
//!     ports = [5432]
//!     "#,
//! )?;
//! let permissions = Permissions::new();
//! permissions.grant(&manifest, manifest.capabilities.clone())?;
//!
//! assert!(permissions.check_network(&manifest.id, "db.example.com", 5432).is_ok());
//! assert!(permissions.check_network(&manifest.id, "db.example.com", 22).is_err());
//! # Ok::<(), rivet_sdk::error::Error>(())
//! ```

use rivet_sdk::error::{Error, Result};
use rivet_sdk::manifest::{Capabilities, ClipboardAccess, ExtensionId, FilesystemAccess, Manifest};
use rivet_sdk::secret::SecretUri;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use std::sync::{PoisonError, RwLock};
use tracing::warn;

/// The granted capabilities of each extension. See the
/// [module documentation](self) for the rules.
///
/// All methods take `&self` and are safe for concurrent use. Share the
/// service in an [`Arc`](std::sync::Arc). Grants are kept in memory only.
#[derive(Debug)]
pub struct Permissions {
    grants: RwLock<HashMap<ExtensionId, Grant>>,
    /// The directory that `~` in a scope path refers to.
    home: Option<PathBuf>,
}

/// What the service stores for one extension.
#[derive(Debug)]
struct Grant {
    /// The capabilities that the installed manifest requested.
    requested: Capabilities,
    /// The part of `requested` that the user granted.
    granted: Capabilities,
}

impl Default for Permissions {
    fn default() -> Self {
        Self::new()
    }
}

impl Permissions {
    /// Creates a service without grants. Reads the home directory of the
    /// user here, one time; `~` in a scope path refers to it for the life of
    /// the service.
    pub fn new() -> Self {
        Self::with_home(std::env::home_dir())
    }

    fn with_home(home: Option<PathBuf>) -> Self {
        Self {
            grants: RwLock::default(),
            home,
        }
    }

    /// Sets the grant of the extension of `manifest`. A grant that the
    /// extension already has is replaced.
    ///
    /// `capabilities` can be less than the manifest requests. Each entry
    /// must be covered by the manifest; see [`added_capabilities`] for the
    /// rules.
    ///
    /// # Errors
    ///
    /// Returns a `policy` error if `capabilities` contains more than the
    /// manifest requests. The grant of the extension does not change.
    pub fn grant(&self, manifest: &Manifest, capabilities: Capabilities) -> Result<()> {
        if !added_capabilities(&manifest.capabilities, &capabilities).is_empty() {
            return Err(Error::policy(format!(
                "the grant for the extension `{}` contains a capability that its manifest \
                 does not request",
                manifest.id
            )));
        }
        let grant = Grant {
            requested: manifest.capabilities.clone(),
            granted: capabilities,
        };
        self.write().insert(manifest.id.clone(), grant);
        Ok(())
    }

    /// Removes all granted capabilities of `extension`. Returns `false` if
    /// it had no grant.
    pub fn revoke(&self, extension: &ExtensionId) -> bool {
        self.write().remove(extension).is_some()
    }

    /// Does the update review for a new manifest version (§4.7, ADR-0020).
    /// Returns the capabilities that `manifest` adds to the capabilities
    /// that the installed manifest requested (the manifest of the last
    /// [`grant`](Self::grant) or review); see [`added_capabilities`].
    ///
    /// - It adds nothing: the grant of the user is kept, also a partial
    ///   grant. A capability that the new version no longer requests is
    ///   removed from the grant. A `read-write` scope that the new version
    ///   requests as `read` becomes `read`.
    /// - It adds one or more capabilities: the grant is removed. The
    ///   extension has no access until a new [`grant`](Self::grant) after
    ///   the review.
    /// - The extension has no grant: all capabilities of `manifest` are
    ///   returned and no grant is created.
    pub fn review_update(&self, manifest: &Manifest) -> Capabilities {
        let mut grants = self.write();
        let Some(grant) = grants.get_mut(&manifest.id) else {
            return manifest.capabilities.clone();
        };
        let added = added_capabilities(&grant.requested, &manifest.capabilities);
        if added.is_empty() {
            grant.requested = manifest.capabilities.clone();
            cut_to(&mut grant.granted, &manifest.capabilities);
        } else {
            grants.remove(&manifest.id);
        }
        added
    }

    /// Checks that `extension` may connect to `host` on `port`.
    ///
    /// # Errors
    ///
    /// Returns a `policy` error if the host and port are not granted.
    pub fn check_network(&self, extension: &ExtensionId, host: &str, port: u16) -> Result<()> {
        let allowed = self.granted(extension, |granted| allows_network(granted, host, port));
        // `host` comes from the extension: its length has no limit.
        let resource = if host.len() > MAX_HOST_BYTES {
            let cut = &host[..host.floor_char_boundary(MAX_HOST_BYTES)];
            format!("{cut}…:{port}")
        } else {
            format!("{host}:{port}")
        };
        allow(allowed, extension, "network", &resource)
    }

    /// Checks that `extension` may access `path` and returns the resolved
    /// path. `access` is [`FilesystemAccess::Read`] for a read and
    /// [`FilesystemAccess::ReadWrite`] for each operation that changes the
    /// filesystem.
    ///
    /// # Blocking
    ///
    /// This function reads the filesystem to resolve symbolic links. In
    /// async code, call it in [`tokio::task::spawn_blocking`], in the same
    /// closure that opens the file: the file operation is blocking work too,
    /// and one closure keeps the time between check and use short.
    ///
    /// # Limit: time of check, time of use
    ///
    /// The decision is correct for the filesystem at the time of the call. A
    /// process that can change a directory in the scope can replace a
    /// component with a symbolic link after the check. To keep this window
    /// small, the caller MUST open the returned path, not `path`, and SHOULD
    /// not follow a symbolic link in the last component when it opens it.
    ///
    /// # Errors
    ///
    /// Returns a `policy` error if no granted scope with the necessary
    /// access contains the resolved path, or if the path cannot be resolved.
    pub fn check_filesystem(
        &self,
        extension: &ExtensionId,
        path: &Path,
        access: FilesystemAccess,
    ) -> Result<PathBuf> {
        // The scopes are copied so that the lock is not held during file I/O.
        let scopes = self.granted(extension, |granted| granted.filesystem.clone());
        resolve(path)
            .ok()
            .filter(|resolved| {
                scopes.iter().flatten().any(|scope| {
                    covers(scope.access, access)
                        && scope_root(&scope.path, self.home.as_deref())
                            .and_then(|root| resolve(&root).ok())
                            .is_some_and(|root| resolved.starts_with(root))
                })
            })
            .ok_or_else(|| {
                let capability = match access {
                    FilesystemAccess::Read => "filesystem read",
                    FilesystemAccess::ReadWrite => "filesystem read-write",
                };
                denied(extension, capability, &path.display().to_string())
            })
    }

    /// Checks that `extension` may read the secret that `uri` references.
    ///
    /// # Errors
    ///
    /// Returns a `policy` error if no granted namespace contains `uri`. The
    /// error names the URI, which is a reference and not a secret value.
    pub fn check_secret(&self, extension: &ExtensionId, uri: &SecretUri) -> Result<()> {
        let allowed = self.granted(extension, |granted| {
            granted
                .secrets
                .iter()
                .any(|namespace| in_namespace(namespace, uri.path()))
        });
        allow(allowed, extension, "secrets", uri.as_str())
    }

    /// Checks that `extension` may do the clipboard operation `access`.
    ///
    /// # Errors
    ///
    /// Returns a `policy` error if the operation is not granted.
    pub fn check_clipboard(&self, extension: &ExtensionId, access: ClipboardAccess) -> Result<()> {
        let allowed = self.granted(extension, |granted| granted.clipboard.contains(&access));
        let resource = match access {
            ClipboardAccess::Read => "read",
            ClipboardAccess::Write => "write",
        };
        allow(allowed, extension, "clipboard", resource)
    }

    /// Applies `read` to the grant of `extension`. `None`: no grant.
    fn granted<T>(
        &self,
        extension: &ExtensionId,
        read: impl FnOnce(&Capabilities) -> T,
    ) -> Option<T> {
        self.grants
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(extension)
            .map(|grant| read(&grant.granted))
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<ExtensionId, Grant>> {
        self.grants.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Returns the capabilities in `requested` that `granted` does not cover.
/// The result is empty ([`Capabilities::is_empty`]) if `requested` adds
/// nothing.
///
/// Use it for the update review (§4.7): `granted` is the grant or the
/// capabilities of the installed version, `requested` is the capabilities of
/// the new version.
///
/// An entry is covered when:
///
/// - network: the host has the port in `granted`. The hosts are compared as
///   in a network check. The result lists only the ports that are not
///   covered. A host that is not in `granted` is not covered, also with an
///   empty port list.
/// - filesystem: `granted` has a scope with the same `path` text and the
///   same access or `read-write`. Paths are not resolved, so a path below a
///   granted path is reported as added.
/// - secrets: `granted` has the same namespace text. A namespace below a
///   granted namespace is reported as added.
/// - clipboard: `granted` has the same operation.
pub fn added_capabilities(granted: &Capabilities, requested: &Capabilities) -> Capabilities {
    let mut added = Capabilities::default();
    for scope in &requested.network {
        let mut missing = scope.clone();
        missing
            .ports
            .retain(|port| !allows_network(granted, &scope.host, *port));
        let known_host = || {
            granted
                .network
                .iter()
                .any(|have| same_host(&have.host, &scope.host))
        };
        if !missing.ports.is_empty() || !known_host() {
            added.network.push(missing);
        }
    }
    added.filesystem = requested
        .filesystem
        .iter()
        .filter(|want| {
            !granted
                .filesystem
                .iter()
                .any(|have| have.path == want.path && covers(have.access, want.access))
        })
        .cloned()
        .collect();
    added.secrets = requested
        .secrets
        .iter()
        .filter(|namespace| !granted.secrets.contains(namespace))
        .cloned()
        .collect();
    added.clipboard = requested
        .clipboard
        .iter()
        .filter(|access| !granted.clipboard.contains(access))
        .copied()
        .collect();
    added
}

/// Removes from `granted` what `requested` does not contain. A `read-write`
/// scope that is requested as `read` becomes `read`.
fn cut_to(granted: &mut Capabilities, requested: &Capabilities) {
    for scope in &mut granted.network {
        let host = &scope.host;
        scope
            .ports
            .retain(|port| allows_network(requested, host, *port));
    }
    granted.network.retain(|scope| !scope.ports.is_empty());
    granted.filesystem.retain_mut(|have| {
        let mut wanted = requested
            .filesystem
            .iter()
            .filter(|want| want.path == have.path)
            .peekable();
        let keep = wanted.peek().is_some();
        if !wanted.any(|want| covers(want.access, have.access)) {
            have.access = FilesystemAccess::Read;
        }
        keep
    });
    granted
        .secrets
        .retain(|namespace| requested.secrets.contains(namespace));
    granted
        .clipboard
        .retain(|access| requested.clipboard.contains(access));
}

/// The maximum length of a DNS name. A longer requested host is cut to it
/// in the log and in the error.
const MAX_HOST_BYTES: usize = 255;

/// Turns a decision into a result. `None` (no grant) is a denial.
fn allow(
    allowed: Option<bool>,
    extension: &ExtensionId,
    capability: &str,
    resource: &str,
) -> Result<()> {
    if allowed == Some(true) {
        Ok(())
    } else {
        Err(denied(extension, capability, resource))
    }
}

/// Logs a denied access and builds its error.
fn denied(extension: &ExtensionId, capability: &str, resource: &str) -> Error {
    // `resource` comes from an untrusted extension. The debug form escapes
    // control characters, so it cannot add a line to the log.
    warn!(extension = %extension, capability, resource = ?resource, "permission denied");
    Error::policy(format!(
        "the extension `{extension}` does not have the capability `{capability}` for {resource:?}"
    ))
}

fn allows_network(granted: &Capabilities, host: &str, port: u16) -> bool {
    granted
        .network
        .iter()
        .any(|scope| same_host(&scope.host, host) && scope.ports.contains(&port))
}

fn same_host(granted: &str, requested: &str) -> bool {
    match (ip_address(granted), ip_address(requested)) {
        (Some(granted), Some(requested)) => granted == requested,
        (None, None) => granted.eq_ignore_ascii_case(requested),
        _ => false,
    }
}

/// Parses an IP address literal. An IPv6 address can have the `[]` of a
/// URL; an IPv4 address in brackets is not an address.
fn ip_address(host: &str) -> Option<IpAddr> {
    match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        None => host.parse().ok(),
    }
}

/// `true` if a scope with the access `have` permits the access `want`.
fn covers(have: FilesystemAccess, want: FilesystemAccess) -> bool {
    have == FilesystemAccess::ReadWrite || want == FilesystemAccess::Read
}

fn in_namespace(namespace: &str, path: &str) -> bool {
    let mut segments = path.split('/');
    // `://` is reserved for a per-scheme namespace (ADR-0020). A backend can
    // decode `%2e%2e` or drop an empty segment, so both are denied.
    !namespace.contains("://")
        && !path.contains('%')
        && !path
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
        && namespace
            .split('/')
            .all(|part| segments.next() == Some(part))
}

/// The directory of a scope path: absolute, or `~` replaced by `home`.
/// `None` for any other path and for a path with a `..` component.
fn scope_root(path: &str, home: Option<&Path>) -> Option<PathBuf> {
    let path = Path::new(path);
    if path.components().any(|part| part == Component::ParentDir) {
        return None;
    }
    match path.strip_prefix("~") {
        Ok(below_home) => home.map(|home| home.join(below_home)),
        Err(_) => path.is_absolute().then(|| path.to_path_buf()),
    }
}

/// Resolves symbolic links and `..` in `path`. For a path that does not
/// exist, the nearest existing ancestor is resolved and the missing names
/// are appended.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    let invalid = |reason: &str| io::Error::new(io::ErrorKind::InvalidInput, reason.to_owned());
    if !path.is_absolute() {
        return Err(invalid("the path is not absolute"));
    }
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // A symbolic link without a target: a write would create
                // the target, which can be out of the scope.
                if existing.symlink_metadata().is_ok() {
                    return Err(invalid("a symbolic link has no target"));
                }
                // Only a plain name can be appended again without a change
                // of meaning; `..` below a missing directory cannot.
                let (Some(Component::Normal(name)), Some(parent)) =
                    (existing.components().next_back(), existing.parent())
                else {
                    return Err(invalid("a missing part of the path contains `..`"));
                };
                missing.push(name);
                existing = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{Capture, Level, LogFormat, Redactor};
    use rivet_sdk::error::ErrorCategory;
    use rivet_sdk::manifest::{FilesystemScope, NetworkScope};
    use std::fs;
    use tracing::dispatcher::with_default;

    /// A manifest of `acme.postgres` with the `[capabilities]` content
    /// `capabilities` (TOML).
    fn manifest(capabilities: &str) -> Manifest {
        Manifest::parse(&format!(
            "id = \"acme.postgres\"\nversion = \"1.0.0\"\nsdk = \">=0.1.0\"\n{capabilities}"
        ))
        .expect(capabilities)
    }

    /// A service where `acme.postgres` has all capabilities of the manifest.
    fn granted(capabilities: &str) -> (Permissions, ExtensionId) {
        let manifest = manifest(capabilities);
        let permissions = Permissions::new();
        permissions
            .grant(&manifest, manifest.capabilities.clone())
            .unwrap();
        (permissions, manifest.id)
    }

    fn filesystem(scopes: &[(&Path, &str)]) -> String {
        scopes
            .iter()
            .map(|(path, access)| {
                format!(
                    "[[capabilities.filesystem]]\npath = '{}'\naccess = \"{access}\"\n",
                    path.display()
                )
            })
            .collect()
    }

    fn uri(text: &str) -> SecretUri {
        text.parse().expect(text)
    }

    #[track_caller]
    fn assert_denied<T: std::fmt::Debug>(result: Result<T>, parts: &[&str]) {
        let error = result.unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy, "{error}");
        for part in parts {
            assert!(error.message().contains(part), "no {part} in: {error}");
        }
    }

    const ALL: &str = r#"
        [capabilities]
        secrets = ["acme-postgres"]
        clipboard = ["read", "write"]
        [[capabilities.network]]
        host = "db.example.com"
        ports = [5432]
        [[capabilities.filesystem]]
        path = "/"
        access = "read-write"
    "#;

    /// Asserts that `extension` is denied in each capability.
    #[track_caller]
    fn assert_no_access(permissions: &Permissions, extension: &ExtensionId) {
        let id = extension.as_str();
        assert_denied(
            permissions.check_network(extension, "db.example.com", 5432),
            &[id, "network", "db.example.com:5432"],
        );
        let dir = tempfile::tempdir().unwrap();
        let path = format!("{:?}", dir.path().display().to_string());
        assert_denied(
            permissions.check_filesystem(extension, dir.path(), FilesystemAccess::Read),
            &[id, "filesystem read", &path],
        );
        assert_denied(
            permissions.check_secret(extension, &uri("keychain://acme-postgres/prod")),
            &[id, "secrets", "keychain://acme-postgres/prod"],
        );
        assert_denied(
            permissions.check_clipboard(extension, ClipboardAccess::Read),
            &[id, "clipboard", "read"],
        );
        assert_denied(
            permissions.check_clipboard(extension, ClipboardAccess::Write),
            &[id, "clipboard", "write"],
        );
    }

    #[test]
    fn the_service_is_shareable_between_threads() {
        fn shareable<T: Send + Sync>() {}
        shareable::<Permissions>();
    }

    #[test]
    fn an_extension_without_a_grant_gets_no_access() {
        let (permissions, _) = granted(ALL);
        assert_no_access(&permissions, &"acme.other".parse().unwrap());
        assert_no_access(&Permissions::new(), &"acme.postgres".parse().unwrap());
    }

    #[test]
    fn a_grant_gives_access_and_revoke_removes_all_of_it() {
        let (permissions, id) = granted(ALL);
        let dir = tempfile::tempdir().unwrap();
        permissions
            .check_network(&id, "db.example.com", 5432)
            .unwrap();
        permissions
            .check_filesystem(&id, dir.path(), FilesystemAccess::ReadWrite)
            .unwrap();
        permissions
            .check_secret(&id, &uri("keychain://acme-postgres/prod"))
            .unwrap();
        permissions
            .check_clipboard(&id, ClipboardAccess::Read)
            .unwrap();
        permissions
            .check_clipboard(&id, ClipboardAccess::Write)
            .unwrap();

        assert!(permissions.revoke(&id));
        assert!(!permissions.revoke(&id));
        assert_no_access(&permissions, &id);
    }

    #[test]
    fn network_needs_a_granted_host_and_port() {
        let (permissions, id) = granted(
            r#"
            [[capabilities.network]]
            host = "DB.example.com"
            ports = [5432, 6432]
            [[capabilities.network]]
            host = "::1"
            ports = [5432]
            [[capabilities.network]]
            host = "10.0.0.5"
            ports = [22]
            "#,
        );
        for (host, port) in [
            ("db.example.com", 5432),
            ("db.EXAMPLE.com", 6432),
            ("::1", 5432),
            ("[::1]", 5432),
            ("0:0:0:0:0:0:0:1", 5432),
            ("10.0.0.5", 22),
        ] {
            permissions
                .check_network(&id, host, port)
                .unwrap_or_else(|error| panic!("{host}:{port}: {error}"));
        }
        for (host, port) in [
            ("db.example.com", 22),
            ("example.com", 5432),
            ("x.db.example.com", 5432),
            ("db.example.com.evil.org", 5432),
            ("db.example.com.", 5432),
            ("::2", 5432),
            ("10.0.0.5", 5432),
            ("10.0.0.05", 22),
            ("::ffff:10.0.0.5", 22),
        ] {
            assert_denied(
                permissions.check_network(&id, host, port),
                &["network", &format!("{host}:{port}")],
            );
        }
    }

    /// R-28e: brackets are the URL form of an IPv6 address only.
    #[test]
    fn brackets_are_not_removed_from_an_ipv4_address() {
        let (permissions, id) =
            granted("[[capabilities.network]]\nhost = \"127.0.0.1\"\nports = [5432]\n");
        permissions.check_network(&id, "127.0.0.1", 5432).unwrap();
        assert_denied(
            permissions.check_network(&id, "[127.0.0.1]", 5432),
            &["network", "[127.0.0.1]:5432"],
        );
    }

    /// R-28f: the host comes from the extension and has no length limit.
    #[test]
    fn a_long_host_is_cut_in_the_error() {
        let (permissions, id) = granted(ALL);
        let error = permissions
            .check_network(&id, &"a".repeat(100_000), 443)
            .unwrap_err();
        let cut = format!("{}…:443", "a".repeat(255));
        assert!(error.message().contains(&cut), "{}", error.message().len());
        assert!(!error.message().contains(&"a".repeat(256)));

        // The cut is on a character boundary: `é` has 2 bytes.
        let error = permissions
            .check_network(&id, &"é".repeat(200), 443)
            .unwrap_err();
        let cut = format!("{}…:443", "é".repeat(127));
        assert!(error.message().contains(&cut), "{error}");
        assert!(!error.message().contains(&"é".repeat(128)));

        // A host of the maximum length is not cut.
        let host = "a".repeat(255);
        let error = permissions.check_network(&id, &host, 443).unwrap_err();
        assert!(error.message().contains(&format!("{host}:443")), "{error}");
    }

    #[test]
    fn filesystem_access_stays_in_the_scope() {
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("data");
        let sibling = dir.path().join("database");
        fs::create_dir_all(scope.join("sub")).unwrap();
        fs::create_dir(&sibling).unwrap();
        fs::write(scope.join("in.txt"), "").unwrap();
        fs::write(sibling.join("out.txt"), "").unwrap();
        let (permissions, id) = granted(&filesystem(&[(&scope, "read")]));
        let read = |path: PathBuf| permissions.check_filesystem(&id, &path, FilesystemAccess::Read);
        let root = scope.canonicalize().unwrap();

        assert_eq!(read(scope.clone()).unwrap(), root);
        assert_eq!(read(scope.join("in.txt")).unwrap(), root.join("in.txt"));
        // `..` that stays in the scope.
        assert_eq!(
            read(scope.join("sub/../in.txt")).unwrap(),
            root.join("in.txt")
        );
        // A file that does not exist yet, also below a missing directory.
        assert_eq!(read(scope.join("new.txt")).unwrap(), root.join("new.txt"));
        assert_eq!(
            read(scope.join("a/b/new.txt")).unwrap(),
            root.join("a/b/new.txt")
        );

        for outside in [
            // The parent and a sibling whose name starts with the scope name.
            dir.path().to_path_buf(),
            sibling.join("out.txt"),
            sibling.join("new.txt"),
            // `..` that leaves the scope, from existing and missing parts.
            scope.join("../database/out.txt"),
            scope.join("sub/../../database/new.txt"),
            scope.join("missing/../../database/out.txt"),
            scope.join("missing/../in.txt"),
            // A file is not a directory.
            scope.join("in.txt/below"),
            // A relative path depends on the working directory.
            PathBuf::from("data/in.txt"),
        ] {
            // The error has the debug form of the path as the extension gave it.
            let text = format!("{:?}", outside.display().to_string());
            assert_denied(read(outside), &["filesystem read", &text]);
        }
    }

    #[test]
    fn filesystem_write_needs_a_read_write_scope() {
        let dir = tempfile::tempdir().unwrap();
        let (config, cache) = (dir.path().join("config"), dir.path().join("cache"));
        fs::create_dir(&config).unwrap();
        fs::create_dir(&cache).unwrap();
        let (permissions, id) = granted(&filesystem(&[(&config, "read"), (&cache, "read-write")]));

        for (path, access) in [
            (config.join("a"), FilesystemAccess::Read),
            (cache.join("a"), FilesystemAccess::Read),
            (cache.join("a"), FilesystemAccess::ReadWrite),
        ] {
            permissions.check_filesystem(&id, &path, access).unwrap();
        }
        assert_denied(
            permissions.check_filesystem(&id, &config.join("a"), FilesystemAccess::ReadWrite),
            &["filesystem read-write", "config"],
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_cannot_leave_the_scope() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("scope");
        let outside = dir.path().join("outside");
        fs::create_dir_all(scope.join("real")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "").unwrap();
        fs::write(scope.join("real/in.txt"), "").unwrap();
        symlink(&outside, scope.join("dir-link")).unwrap();
        symlink(outside.join("secret.txt"), scope.join("file-link")).unwrap();
        symlink(outside.join("not-there"), scope.join("dangling")).unwrap();
        symlink(scope.join("real"), scope.join("inner-link")).unwrap();
        // The scope itself is reached through a link.
        symlink(&scope, dir.path().join("scope-link")).unwrap();
        let (permissions, id) = granted(&filesystem(&[(
            &dir.path().join("scope-link"),
            "read-write",
        )]));
        let write =
            |path: PathBuf| permissions.check_filesystem(&id, &path, FilesystemAccess::ReadWrite);

        let root = scope.canonicalize().unwrap();
        assert_eq!(
            write(scope.join("inner-link/in.txt")).unwrap(),
            root.join("real/in.txt")
        );
        assert_eq!(
            write(dir.path().join("scope-link/real/new.txt")).unwrap(),
            root.join("real/new.txt")
        );
        for escape in [
            "dir-link",
            "dir-link/secret.txt",
            "dir-link/new.txt",
            "file-link",
            "dangling",
            "dangling/new.txt",
            "inner-link/../../outside/secret.txt",
        ] {
            assert_denied(write(scope.join(escape)), &["filesystem", escape]);
        }
    }

    #[test]
    fn a_scope_path_is_absolute_or_below_home() {
        let home = Path::new("/home/u");
        let root = |path| scope_root(path, Some(home));
        assert_eq!(root("~").unwrap(), Path::new("/home/u"));
        assert_eq!(
            root("~/.postgresql").unwrap(),
            Path::new("/home/u/.postgresql")
        );
        assert_eq!(scope_root("~/.postgresql", None), None);
        assert_eq!(root("~other/.ssh"), None);
        assert_eq!(root("relative/dir"), None);
        assert_eq!(root("/a/../b"), None);
        assert_eq!(root("~/.."), None);

        let dir = tempfile::tempdir().unwrap();
        assert_eq!(root(dir.path().to_str().unwrap()).unwrap(), dir.path());
    }

    /// Defence in depth: `Manifest::parse` can reject these scope paths, so
    /// they are set after the parse.
    #[test]
    fn a_relative_scope_path_or_one_with_a_parent_component_grants_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        for scope in [
            "relative".to_owned(),
            format!("{}/..", home.display()),
            "~/..".to_owned(),
        ] {
            let mut manifest = manifest(&filesystem(&[(Path::new("/"), "read")]));
            manifest.capabilities.filesystem[0].path.clone_from(&scope);
            let permissions = Permissions::with_home(Some(home.clone()));
            permissions
                .grant(&manifest, manifest.capabilities.clone())
                .unwrap();
            for path in [dir.path().join("relative"), home.join("file")] {
                assert_denied(
                    permissions.check_filesystem(&manifest.id, &path, FilesystemAccess::Read),
                    &["filesystem read"],
                );
            }
        }
    }

    /// R-26, R-27b: `~` is the home directory that the service got when it
    /// was created. The test does not change the process environment.
    #[test]
    fn a_home_scope_uses_the_home_directory_of_the_service() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join(".postgresql")).unwrap();
        let root = home.path().canonicalize().unwrap();
        let below =
            manifest("[[capabilities.filesystem]]\npath = \"~/.postgresql\"\naccess = \"read\"\n");
        let all = manifest("[[capabilities.filesystem]]\npath = \"~\"\naccess = \"read\"\n");
        let service = |manifest: &Manifest, home: Option<PathBuf>| {
            let permissions = Permissions::with_home(home);
            permissions
                .grant(manifest, manifest.capabilities.clone())
                .unwrap();
            permissions
        };
        let id = &below.id;

        let permissions = service(&below, Some(home.path().to_path_buf()));
        let read = |path: PathBuf| permissions.check_filesystem(id, &path, FilesystemAccess::Read);
        assert_eq!(
            read(home.path().join(".postgresql/root.crt")).unwrap(),
            root.join(".postgresql/root.crt")
        );
        let mut denied = vec![
            home.path().join(".ssh/id"),
            outside.path().join(".postgresql/root.crt"),
        ];
        // The home directory of the process is not a scope.
        denied.extend(std::env::home_dir().map(|home| home.join(".postgresql/root.crt")));
        for path in denied {
            assert_denied(read(path), &["filesystem read"]);
        }

        let permissions = service(&all, Some(home.path().to_path_buf()));
        assert_eq!(
            permissions
                .check_filesystem(id, &home.path().join(".ssh/id"), FilesystemAccess::Read)
                .unwrap(),
            root.join(".ssh/id")
        );

        // Without a home directory, `~` grants nothing.
        let permissions = service(&all, None);
        assert_denied(
            permissions.check_filesystem(id, home.path(), FilesystemAccess::Read),
            &["filesystem read"],
        );
    }

    #[test]
    fn secrets_need_a_granted_namespace() {
        let (permissions, id) =
            granted("[capabilities]\nsecrets = [\"acme-postgres\", \"prod/db\"]\n");
        for allowed in [
            "keychain://acme-postgres/prod",
            "aws-sm://acme-postgres/prod/password",
            "keychain://acme-postgres",
            "aws-sm://prod/db/password",
        ] {
            permissions
                .check_secret(&id, &uri(allowed))
                .unwrap_or_else(|error| panic!("{allowed}: {error}"));
        }
        for denied in [
            "keychain://acme-postgres-2/prod",
            "keychain://acme/prod",
            "keychain://Acme-Postgres/prod",
            "keychain://other/acme-postgres",
            "aws-sm://prod/database/password",
            "aws-sm://prod",
            "keychain://acme-postgres/../other/prod",
            "keychain://acme-postgres/./prod",
        ] {
            assert_denied(
                permissions.check_secret(&id, &uri(denied)),
                &["acme.postgres", "secrets", denied],
            );
        }
    }

    /// R-28b: a backend can decode `%2e%2e` or drop an empty segment, and
    /// then read a secret out of the namespace.
    #[test]
    fn a_secret_path_with_an_empty_or_encoded_segment_is_denied() {
        let (permissions, id) = granted("[capabilities]\nsecrets = [\"acme-postgres\"]\n");
        for denied in [
            "keychain://acme-postgres/%2e%2e/other",
            "keychain://acme-postgres//other",
            "keychain://acme-postgres/",
            "keychain://acme-postgres/a%2Fb",
        ] {
            assert_denied(
                permissions.check_secret(&id, &uri(denied)),
                &["acme.postgres", "secrets", denied],
            );
        }
    }

    /// ADR-0020: the form `scheme://...` is reserved for a later per-scheme
    /// namespace. Until then it grants nothing. `Manifest::parse` rejects
    /// such a namespace, so it is set after the parse (defence in depth).
    #[test]
    fn a_secret_namespace_with_a_scheme_grants_nothing() {
        let mut manifest = manifest("[capabilities]\nsecrets = [\"other\"]\n");
        manifest.capabilities.secrets = ["aws-sm://prod", "a://b", "other"]
            .map(str::to_owned)
            .into();
        let permissions = Permissions::new();
        permissions
            .grant(&manifest, manifest.capabilities.clone())
            .unwrap();
        let id = manifest.id;
        for denied in [
            "aws-sm://prod/password",
            "aws-sm://prod",
            "keychain://aws-sm://prod/password",
            "keychain://aws-sm://prod",
            "keychain://a://b",
            "a://b",
        ] {
            assert_denied(
                permissions.check_secret(&id, &uri(denied)),
                &["acme.postgres", "secrets"],
            );
        }
        permissions
            .check_secret(&id, &uri("aws-sm://other/password"))
            .unwrap();
    }

    #[test]
    fn clipboard_read_and_write_are_granted_separately() {
        let (reader, id) = granted("[capabilities]\nclipboard = [\"read\"]\n");
        reader.check_clipboard(&id, ClipboardAccess::Read).unwrap();
        assert_denied(
            reader.check_clipboard(&id, ClipboardAccess::Write),
            &["clipboard", "write"],
        );

        let (writer, id) = granted("[capabilities]\nclipboard = [\"write\"]\n");
        writer.check_clipboard(&id, ClipboardAccess::Write).unwrap();
        assert_denied(
            writer.check_clipboard(&id, ClipboardAccess::Read),
            &["clipboard", "read"],
        );
    }

    const REQUESTED: &str = r#"
        [capabilities]
        secrets = ["acme-postgres"]
        clipboard = ["read"]
        [[capabilities.network]]
        host = "db.example.com"
        ports = [5432]
        [[capabilities.filesystem]]
        path = "~/.postgresql"
        access = "read"
    "#;

    #[test]
    fn a_grant_cannot_contain_more_than_the_manifest_requests() {
        let requested = manifest(REQUESTED);
        let permissions = Permissions::new();
        let network = |host: &str, ports: Vec<u16>| {
            Capabilities::new().with_network([NetworkScope::new(host, ports)])
        };
        let filesystem = |path: &str, access| {
            Capabilities::new().with_filesystem([FilesystemScope::new(path, access)])
        };
        for more in [
            Capabilities::new().with_secrets(["aws".to_owned()]),
            Capabilities::new().with_clipboard([ClipboardAccess::Write]),
            network("db.example.com", vec![5432, 22]),
            network("other.example.com", vec![5432]),
            filesystem("~/.postgresql", FilesystemAccess::ReadWrite),
            filesystem("~", FilesystemAccess::Read),
        ] {
            let error = permissions.grant(&requested, more.clone()).unwrap_err();
            assert_eq!(error.category(), ErrorCategory::Policy, "{more:?}");
            assert!(error.message().contains("acme.postgres"), "{error}");
        }
        assert_no_access(&permissions, &requested.id);

        // A failed grant does not change the grant that exists.
        permissions
            .grant(
                &requested,
                Capabilities::new().with_clipboard([ClipboardAccess::Read]),
            )
            .unwrap();
        permissions
            .grant(&requested, manifest(ALL).capabilities)
            .unwrap_err();
        permissions
            .check_clipboard(&requested.id, ClipboardAccess::Read)
            .unwrap();
        // A part of the request can be granted: the rest stays denied.
        assert_denied(
            permissions.check_network(&requested.id, "db.example.com", 5432),
            &["network"],
        );
    }

    /// R-28a: a host without ports gives no access now, but it is not in
    /// the manifest.
    #[test]
    fn a_grant_cannot_contain_a_host_that_the_manifest_does_not_request() {
        let requested = manifest(REQUESTED);
        let permissions = Permissions::new();
        let host_without_ports =
            |host: &str| Capabilities::new().with_network([NetworkScope::new(host, [])]);
        let error = permissions
            .grant(&requested, host_without_ports("other.example.com"))
            .unwrap_err();
        assert_eq!(error.category(), ErrorCategory::Policy);
        permissions
            .grant(&requested, host_without_ports("DB.example.com"))
            .unwrap();
        assert_no_access(&permissions, &requested.id);
    }

    #[test]
    fn added_capabilities_lists_what_the_grant_does_not_cover() {
        let old = manifest(REQUESTED).capabilities;
        assert!(added_capabilities(&old, &old).is_empty());
        assert!(added_capabilities(&old, &Capabilities::new()).is_empty());
        assert_eq!(added_capabilities(&Capabilities::new(), &old), old);

        let new = manifest(
            r#"
            [capabilities]
            secrets = ["acme-postgres", "aws"]
            clipboard = ["read", "write"]
            [[capabilities.network]]
            host = "DB.example.com"
            ports = [5432, 6432]
            [[capabilities.network]]
            host = "replica.example.com"
            ports = [5432]
            [[capabilities.filesystem]]
            path = "~/.postgresql"
            access = "read-write"
            [[capabilities.filesystem]]
            path = "~/.cache"
            access = "read"
            "#,
        )
        .capabilities;
        let expected = manifest(
            r#"
            [capabilities]
            secrets = ["aws"]
            clipboard = ["write"]
            [[capabilities.network]]
            host = "DB.example.com"
            ports = [6432]
            [[capabilities.network]]
            host = "replica.example.com"
            ports = [5432]
            [[capabilities.filesystem]]
            path = "~/.postgresql"
            access = "read-write"
            [[capabilities.filesystem]]
            path = "~/.cache"
            access = "read"
            "#,
        )
        .capabilities;
        assert_eq!(added_capabilities(&old, &new), expected);
        // The new version requests less: nothing is added.
        assert!(added_capabilities(&new, &old).is_empty());
    }

    #[test]
    fn an_update_that_adds_a_capability_removes_the_grant() {
        let (permissions, id) = granted(REQUESTED);
        let update = manifest(&format!(
            "{REQUESTED}[[capabilities.network]]\nhost = \"replica.example.com\"\nports = [5432]\n"
        ));
        let added = permissions.review_update(&update);
        assert_eq!(added.network.len(), 1);
        assert_eq!(added.network[0].host, "replica.example.com");
        let mut rest = added.clone();
        rest.network.clear();
        assert!(rest.is_empty());
        assert_no_access(&permissions, &id);

        // Without a grant, the review lists all capabilities.
        assert_eq!(permissions.review_update(&update), update.capabilities);
        assert_no_access(&permissions, &id);
    }

    #[test]
    fn an_update_that_adds_nothing_keeps_the_grant() {
        let (permissions, id) = granted(REQUESTED);
        assert!(permissions.review_update(&manifest(REQUESTED)).is_empty());
        permissions
            .check_network(&id, "db.example.com", 5432)
            .unwrap();

        // The new version requests less: the grant follows.
        let less = manifest("[capabilities]\nclipboard = [\"read\"]\n");
        assert!(permissions.review_update(&less).is_empty());
        permissions
            .check_clipboard(&id, ClipboardAccess::Read)
            .unwrap();
        assert_denied(
            permissions.check_network(&id, "db.example.com", 5432),
            &["network"],
        );
    }

    /// R-24: the review compares the new request with the old request, not
    /// with the grant.
    #[test]
    fn an_update_that_adds_nothing_keeps_a_partial_grant() {
        const REQUEST: &str =
            "[capabilities]\nsecrets = [\"acme-postgres\"]\nclipboard = [\"read\", \"write\"]\n";
        let requested = manifest(REQUEST);
        let id = &requested.id;
        let partial = || Capabilities::new().with_secrets(["acme-postgres".to_owned()]);
        let secret = uri("keychain://acme-postgres/prod");
        let permissions = Permissions::new();
        permissions.grant(&requested, partial()).unwrap();

        assert!(permissions.review_update(&requested).is_empty());
        permissions.check_secret(id, &secret).unwrap();
        // The review does not grant what the user did not grant.
        assert_denied(
            permissions.check_clipboard(id, ClipboardAccess::Read),
            &["clipboard"],
        );

        // Only what the new version adds to the old request is returned.
        let more =
            manifest(&REQUEST.replace("[\"acme-postgres\"]", "[\"acme-postgres\", \"aws\"]"));
        assert_eq!(
            permissions.review_update(&more),
            Capabilities::new().with_secrets(["aws".to_owned()])
        );
        assert_no_access(&permissions, id);

        // The new version requests less: the partial grant is cut.
        permissions.grant(&requested, partial()).unwrap();
        let less = manifest("[capabilities]\nclipboard = [\"read\", \"write\"]\n");
        assert!(permissions.review_update(&less).is_empty());
        assert_no_access(&permissions, id);
        // The cut request is the base of the next review.
        assert_eq!(permissions.review_update(&requested), partial());
    }

    #[test]
    fn an_update_that_requests_less_access_to_a_path_cuts_the_grant() {
        let dir = tempfile::tempdir().unwrap();
        let (permissions, id) = granted(&filesystem(&[(dir.path(), "read-write")]));
        let read_only = manifest(&filesystem(&[(dir.path(), "read")]));
        assert!(permissions.review_update(&read_only).is_empty());
        permissions
            .check_filesystem(&id, dir.path(), FilesystemAccess::Read)
            .unwrap();
        assert_denied(
            permissions.check_filesystem(&id, dir.path(), FilesystemAccess::ReadWrite),
            &["filesystem read-write"],
        );
    }

    #[test]
    fn each_denied_access_is_logged_once_and_allowed_access_is_not() {
        let (permissions, id) = granted(REQUESTED);
        let dir = tempfile::tempdir().unwrap();
        for format in [LogFormat::Human, LogFormat::Json] {
            let capture = Capture::default();
            with_default(
                &capture.dispatch(Level::WARN, format, &Redactor::new()),
                || {
                    permissions
                        .check_network(&id, "db.example.com", 5432)
                        .unwrap();
                    permissions
                        .check_network(&id, "evil.org\nWARN forged", 443)
                        .unwrap_err();
                    permissions
                        .check_filesystem(&id, dir.path(), FilesystemAccess::ReadWrite)
                        .unwrap_err();
                    permissions
                        .check_secret(&id, &uri("aws-sm://prod/db"))
                        .unwrap_err();
                    permissions
                        .check_clipboard(&id, ClipboardAccess::Write)
                        .unwrap_err();
                },
            );
            let output = capture.text();
            let lines: Vec<_> = output.lines().collect();
            assert_eq!(lines.len(), 4, "{output}");
            let expected = [
                ("network", "evil.org\\\\nWARN forged:443".to_owned()),
                (
                    "filesystem read-write",
                    dir.path().file_name().unwrap().to_str().unwrap().to_owned(),
                ),
                ("secrets", "aws-sm://prod/db".to_owned()),
                ("clipboard", "write".to_owned()),
            ];
            for (line, (capability, resource)) in lines.iter().zip(expected) {
                // JSON escapes the backslash of the debug form once more.
                let resource = match format {
                    LogFormat::Human => resource.replace("\\\\", "\\"),
                    LogFormat::Json => resource,
                };
                for part in [
                    "WARN",
                    "permission denied",
                    "acme.postgres",
                    capability,
                    &resource,
                ] {
                    assert!(line.contains(part), "{format:?}: no {part} in: {line}");
                }
            }
        }
    }
}
