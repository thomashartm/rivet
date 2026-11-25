//! Service registry: typed, versioned services that extensions look up by id
//! (ARCHITECTURE.md §2.3, §4.6).

use crate::Owner;
use rivet_sdk::error::{Error, Result};
use semver::{Version, VersionReq};
use std::any::{Any, type_name};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, PoisonError, RwLock};

struct Registration {
    owner: Owner,
    /// Holds an `Arc<S>`; `S` is the type given to `register`.
    service: Box<dyn Any + Send + Sync>,
}

/// A registry of services. A service has an id, a version and a Rust type.
///
/// All methods take `&self` and are safe for concurrent use. Share the
/// registry in an [`Arc`].
///
/// ```
/// use rivet_core::registry::ServiceRegistry;
/// use semver::{Version, VersionReq};
/// use std::sync::Arc;
///
/// let registry = ServiceRegistry::new();
/// let service: Arc<str> = Arc::from("hello");
/// registry.register("ext.a".into(), "greeting", Version::new(1, 2, 0), service)?;
///
/// let range = VersionReq::parse("^1")?;
/// let found = registry.lookup::<str>("greeting", &range)?;
/// assert_eq!(&*found, "hello");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Default)]
pub struct ServiceRegistry {
    services: RwLock<HashMap<String, BTreeMap<Version, Registration>>>,
}

impl ServiceRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `service` as version `version` of the service `id`.
    ///
    /// `S` can be a trait object type, for example `dyn AuthProvider`.
    /// [`lookup`](Self::lookup) must name the same `S`.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if this id and version are already
    /// registered. The first registration stays.
    pub fn register<S>(
        &self,
        owner: Owner,
        id: &str,
        version: Version,
        service: Arc<S>,
    ) -> Result<()>
    where
        S: ?Sized + Send + Sync + 'static,
    {
        let mut services = self
            .services
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match services.entry(id.to_owned()).or_default().entry(version) {
            Entry::Occupied(taken) => Err(Error::internal(format!(
                "service `{id}` version {} is already registered by `{}`",
                taken.key(),
                taken.get().owner
            ))),
            Entry::Vacant(free) => {
                free.insert(Registration {
                    owner,
                    service: Box::new(service),
                });
                Ok(())
            }
        }
    }

    /// Returns the highest version of the service `id` that matches `range`.
    ///
    /// # Errors
    ///
    /// - `user` error if no registered version of `id` matches `range`. The
    ///   message names the id and the range.
    /// - `internal` error if the service was registered with a type other
    ///   than `S`.
    pub fn lookup<S>(&self, id: &str, range: &VersionReq) -> Result<Arc<S>>
    where
        S: ?Sized + Send + Sync + 'static,
    {
        let services = self.services.read().unwrap_or_else(PoisonError::into_inner);
        let (version, registration) = services
            .get(id)
            .and_then(|versions| {
                versions
                    .iter()
                    .rev()
                    .find(|(version, _)| range.matches(version))
            })
            .ok_or_else(|| {
                Error::user(format!(
                    "no registered service `{id}` matches the version range `{range}`"
                ))
            })?;
        registration
            .service
            .downcast_ref::<Arc<S>>()
            .cloned()
            .ok_or_else(|| {
                Error::internal(format!(
                    "service `{id}` version {version} is not of type `{}`",
                    type_name::<S>()
                ))
            })
    }

    /// Removes one version of the service `id`. Returns `false` if it was
    /// not registered.
    pub fn unregister(&self, id: &str, version: &Version) -> bool {
        let mut services = self
            .services
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(versions) = services.get_mut(id) else {
            return false;
        };
        let removed = versions.remove(version).is_some();
        if versions.is_empty() {
            services.remove(id);
        }
        removed
    }

    /// Removes every registration of `owner`. Returns how many were removed.
    pub fn unregister_owner(&self, owner: &Owner) -> usize {
        let mut services = self
            .services
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let mut removed = 0;
        services.retain(|_, versions| {
            let before = versions.len();
            versions.retain(|_, registration| registration.owner != *owner);
            removed += before - versions.len();
            !versions.is_empty()
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;

    trait Greeter: Send + Sync {
        fn greet(&self) -> String;
    }

    struct Fixed(&'static str);

    impl Greeter for Fixed {
        fn greet(&self) -> String {
            self.0.to_owned()
        }
    }

    fn greeter(text: &'static str) -> Arc<dyn Greeter> {
        Arc::new(Fixed(text))
    }

    fn version(text: &str) -> Version {
        Version::parse(text).expect("valid version")
    }

    fn range(text: &str) -> VersionReq {
        VersionReq::parse(text).expect("valid range")
    }

    fn owner(text: &str) -> Owner {
        text.into()
    }

    #[test]
    fn register_lookup_and_unregister_a_typed_service() {
        let registry = ServiceRegistry::new();
        registry
            .register(
                owner("ext.a"),
                "greeter",
                version("1.0.0"),
                greeter("hello"),
            )
            .expect("register");

        let found = registry
            .lookup::<dyn Greeter>("greeter", &range("^1"))
            .expect("lookup");
        assert_eq!(found.greet(), "hello");

        assert!(registry.unregister("greeter", &version("1.0.0")));
        assert!(!registry.unregister("greeter", &version("1.0.0")));
        assert!(
            registry
                .lookup::<dyn Greeter>("greeter", &range("^1"))
                .is_err()
        );
    }

    #[test]
    fn lookup_returns_the_highest_version_in_the_range() {
        let registry = ServiceRegistry::new();
        for (v, text) in [
            ("1.0.0", "one"),
            ("1.4.2", "best"),
            ("1.2.0", "mid"),
            ("2.0.0", "two"),
        ] {
            registry
                .register(owner("ext.a"), "greeter", version(v), greeter(text))
                .expect("register");
        }

        let found = registry
            .lookup::<dyn Greeter>("greeter", &range("^1"))
            .expect("lookup");
        assert_eq!(found.greet(), "best");
    }

    #[test]
    fn lookup_without_a_match_names_the_id_and_the_range() {
        let registry = ServiceRegistry::new();
        registry
            .register(owner("ext.a"), "greeter", version("1.0.0"), greeter("one"))
            .expect("register");

        for id in ["greeter", "unknown"] {
            let error = registry
                .lookup::<dyn Greeter>(id, &range(">=2.0.0"))
                .err()
                .expect("no match");
            assert_eq!(error.category(), ErrorCategory::User);
            assert!(error.message().contains(id), "{error}");
            assert!(error.message().contains(">=2.0.0"), "{error}");
        }
    }

    #[test]
    fn lookup_with_the_wrong_type_is_an_error() {
        let registry = ServiceRegistry::new();
        registry
            .register(owner("ext.a"), "greeter", version("1.0.0"), greeter("one"))
            .expect("register");

        let error = registry
            .lookup::<String>("greeter", &range("^1"))
            .expect_err("wrong type");
        assert_eq!(error.category(), ErrorCategory::Internal);
        assert!(error.message().contains("greeter"), "{error}");
    }

    #[test]
    fn registering_the_same_id_and_version_twice_fails() {
        let registry = ServiceRegistry::new();
        registry
            .register(
                owner("ext.a"),
                "greeter",
                version("1.0.0"),
                greeter("first"),
            )
            .expect("register");

        let error = registry
            .register(
                owner("ext.b"),
                "greeter",
                version("1.0.0"),
                greeter("second"),
            )
            .expect_err("duplicate");
        assert!(error.message().contains("greeter"), "{error}");
        assert!(error.message().contains("1.0.0"), "{error}");

        let found = registry
            .lookup::<dyn Greeter>("greeter", &range("^1"))
            .expect("lookup");
        assert_eq!(found.greet(), "first");
    }

    #[test]
    fn unregister_owner_removes_all_registrations_of_that_owner_only() {
        let registry = ServiceRegistry::new();
        let (a, b) = (owner("ext.a"), owner("ext.b"));
        registry
            .register(a.clone(), "greeter", version("1.0.0"), greeter("a1"))
            .expect("register");
        registry
            .register(a.clone(), "other", version("0.1.0"), Arc::new(7_u32))
            .expect("register");
        registry
            .register(b, "greeter", version("1.1.0"), greeter("b1"))
            .expect("register");

        assert_eq!(registry.unregister_owner(&a), 2);
        assert_eq!(registry.unregister_owner(&a), 0);

        assert!(registry.lookup::<u32>("other", &range("*")).is_err());
        assert!(
            registry
                .lookup::<dyn Greeter>("greeter", &range("=1.0.0"))
                .is_err()
        );
        let left = registry
            .lookup::<dyn Greeter>("greeter", &range("^1"))
            .expect("lookup");
        assert_eq!(left.greet(), "b1");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_register_lookup_and_unregister() {
        let registry = Arc::new(ServiceRegistry::new());
        let tasks: Vec<_> = (0..32_u64)
            .map(|n| {
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    let owner = format!("ext.{}", n % 4);
                    registry
                        .register(owner, "number", Version::new(1, n, 0), Arc::new(n))
                        .expect("register");
                    let exact = VersionReq::parse(&format!("=1.{n}.0")).expect("valid range");
                    assert_eq!(
                        *registry.lookup::<u64>("number", &exact).expect("lookup"),
                        n
                    );
                    // Any version can be the highest while other tasks register.
                    registry
                        .lookup::<u64>("number", &VersionReq::STAR)
                        .expect("lookup any");
                })
            })
            .collect();
        for task in tasks {
            task.await.expect("task");
        }

        assert_eq!(
            *registry
                .lookup::<u64>("number", &range("^1"))
                .expect("lookup"),
            31
        );
        let removed: usize = (0..4)
            .map(|n| registry.unregister_owner(&format!("ext.{n}")))
            .sum();
        assert_eq!(removed, 32);
    }
}
