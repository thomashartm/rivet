//! Command bus and event bus (ARCHITECTURE.md §2.3, §4.6).
//!
//! - [`CommandBus`]: named request/response with exactly one handler per name.
//! - [`EventBus`]: publish/subscribe of typed events, at-most-once per
//!   subscriber, with bounded buffers.
//!
//! An event subscription has no owner. It ends when its [`Subscription`] is
//! dropped.

use crate::Owner;
use rivet_sdk::error::{Error, Result};
use std::any::{Any, TypeId, type_name};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use tokio::sync::broadcast;

type Handler<A, R> =
    Arc<dyn Fn(A) -> Pin<Box<dyn Future<Output = Result<R>> + Send>> + Send + Sync>;

struct Registration {
    owner: Owner,
    /// Holds a `Handler<A, R>`.
    handler: Box<dyn Any + Send + Sync>,
}

/// Named commands. A command has one asynchronous handler, a typed argument
/// and a typed response.
///
/// All methods take `&self` and are safe for concurrent use. Share the bus
/// in an [`Arc`].
///
/// ```
/// use rivet_core::bus::CommandBus;
///
/// # async fn example() -> rivet_sdk::error::Result<()> {
/// let bus = CommandBus::new();
/// bus.register("ext.a".into(), "text.len", |text: String| async move {
///     Ok(text.len())
/// })?;
///
/// let length: usize = bus.execute("text.len", String::from("rivet")).await?;
/// assert_eq!(length, 5);
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct CommandBus {
    handlers: RwLock<HashMap<String, Registration>>,
}

impl CommandBus {
    /// Creates a bus without handlers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `handler` as the one handler of the command `name`.
    ///
    /// A command with more than one argument takes a tuple or a struct as `A`.
    ///
    /// # Errors
    ///
    /// Returns an `internal` error if `name` already has a handler. The
    /// first handler stays.
    pub fn register<A, R, F, Fut>(&self, owner: Owner, name: &str, handler: F) -> Result<()>
    where
        A: Send + 'static,
        R: Send + 'static,
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<R>> + Send + 'static,
    {
        let handler: Handler<A, R> = Arc::new(move |args| Box::pin(handler(args)));
        let mut handlers = self
            .handlers
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match handlers.entry(name.to_owned()) {
            Entry::Occupied(taken) => Err(Error::internal(format!(
                "command `{name}` already has a handler, registered by `{}`",
                taken.get().owner
            ))),
            Entry::Vacant(free) => {
                free.insert(Registration {
                    owner,
                    handler: Box::new(handler),
                });
                Ok(())
            }
        }
    }

    /// Runs the handler of the command `name` with `args` and returns its
    /// response.
    ///
    /// # Errors
    ///
    /// - `user` error if `name` has no handler.
    /// - `internal` error if `A` and `R` are not the types of the handler.
    /// - Any error that the handler returns.
    pub async fn execute<A, R>(&self, name: &str, args: A) -> Result<R>
    where
        A: Send + 'static,
        R: Send + 'static,
    {
        // The lock is released before the handler runs.
        let handler = {
            let handlers = self.handlers.read().unwrap_or_else(PoisonError::into_inner);
            let registration = handlers
                .get(name)
                .ok_or_else(|| Error::user(format!("unknown command `{name}`")))?;
            registration
                .handler
                .downcast_ref::<Handler<A, R>>()
                .cloned()
                .ok_or_else(|| {
                    Error::internal(format!(
                        "command `{name}` does not take `{}` and return `{}`",
                        type_name::<A>(),
                        type_name::<R>()
                    ))
                })?
        };
        handler(args).await
    }

    /// Removes the handler of the command `name`. Returns `false` if there
    /// was none. A call that is already running finishes.
    pub fn unregister(&self, name: &str) -> bool {
        self.handlers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name)
            .is_some()
    }

    /// Removes every handler of `owner`. Returns how many were removed.
    pub fn unregister_owner(&self, owner: &Owner) -> usize {
        let mut handlers = self
            .handlers
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let before = handlers.len();
        handlers.retain(|_, registration| registration.owner != *owner);
        before - handlers.len()
    }
}

/// Publish/subscribe of typed events. The Rust type of an event selects its
/// subscribers.
///
/// Each subscriber gets each event at most once. Each event type has one
/// buffer of a fixed size. If a subscriber is too slow, the oldest events
/// are overwritten and the subscriber gets [`Received::Missed`].
///
/// All methods take `&self` and are safe for concurrent use. Share the bus
/// in an [`Arc`].
///
/// ```
/// use rivet_core::bus::{EventBus, Received};
/// use std::num::NonZeroU16;
///
/// #[derive(Clone, Debug, PartialEq)]
/// struct SchemaChanged(u32);
///
/// # async fn example() {
/// let bus = EventBus::new(NonZeroU16::MIN.saturating_add(15));
/// let mut subscription = bus.subscribe::<SchemaChanged>();
/// bus.publish(SchemaChanged(1));
/// assert_eq!(
///     subscription.recv().await,
///     Some(Received::Event(SchemaChanged(1)))
/// );
/// # }
/// ```
pub struct EventBus {
    capacity: usize,
    /// One `broadcast::Sender<E>` for each event type `E`.
    channels: RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
}

impl EventBus {
    /// Creates a bus that buffers at least `capacity` events for each event
    /// type. Tokio rounds the number up to a power of two.
    pub fn new(capacity: NonZeroU16) -> Self {
        Self {
            capacity: capacity.get().into(),
            channels: RwLock::default(),
        }
    }

    /// Sends `event` to the current subscribers of the type `E`. Returns how
    /// many subscribers there are.
    ///
    /// This method does not wait. Without subscribers, the event is dropped.
    pub fn publish<E>(&self, event: E) -> usize
    where
        E: Clone + Send + 'static,
    {
        self.channels
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&TypeId::of::<E>())
            .and_then(|channel| channel.downcast_ref::<broadcast::Sender<E>>())
            .and_then(|sender| sender.send(event).ok())
            .unwrap_or(0)
    }

    /// Subscribes to the events of the type `E` that are published from now
    /// on.
    pub fn subscribe<E>(&self) -> Subscription<E>
    where
        E: Clone + Send + 'static,
    {
        let mut channels = self
            .channels
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let existing = channels
            .get(&TypeId::of::<E>())
            .and_then(|channel| channel.downcast_ref::<broadcast::Sender<E>>());
        let receiver = match existing {
            Some(sender) => sender.subscribe(),
            None => {
                let (sender, receiver) = broadcast::channel(self.capacity);
                channels.insert(TypeId::of::<E>(), Box::new(sender));
                receiver
            }
        };
        Subscription { receiver }
    }
}

/// What a [`Subscription`] receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received<E> {
    /// The next event.
    Event(E),
    /// The subscriber was too slow. This number of events was dropped for
    /// this subscriber. The next call returns the oldest event that is left.
    Missed(u64),
}

/// The receiving end of [`EventBus::subscribe`]. Drop it to unsubscribe.
pub struct Subscription<E> {
    receiver: broadcast::Receiver<E>,
}

impl<E: Clone> Subscription<E> {
    /// Waits for the next event. Returns `None` when the [`EventBus`] was
    /// dropped and no buffered event is left.
    pub async fn recv(&mut self) -> Option<Received<E>> {
        match self.receiver.recv().await {
            Ok(event) => Some(Received::Event(event)),
            Err(broadcast::error::RecvError::Lagged(missed)) => Some(Received::Missed(missed)),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_sdk::error::ErrorCategory;
    use std::sync::Arc;

    fn owner(text: &str) -> Owner {
        text.into()
    }

    fn capacity(n: u16) -> NonZeroU16 {
        NonZeroU16::new(n).expect("non-zero")
    }

    #[derive(Debug, Clone, PartialEq)]
    struct SchemaChanged(u32);

    #[derive(Debug, Clone, PartialEq)]
    struct ConnectionLost(&'static str);

    // --- Command bus ---

    #[tokio::test]
    async fn command_takes_a_typed_argument_and_returns_a_typed_response() {
        let bus = CommandBus::new();
        bus.register(owner("ext.a"), "text.len", |text: String| async move {
            Ok(text.len())
        })
        .expect("register");

        let length: usize = bus
            .execute("text.len", String::from("rivet"))
            .await
            .expect("execute");
        assert_eq!(length, 5);
    }

    #[tokio::test]
    async fn handler_error_reaches_the_caller() {
        let bus = CommandBus::new();
        bus.register(owner("ext.a"), "fail", |(): ()| async {
            Err::<(), _>(Error::policy("blocked"))
        })
        .expect("register");

        let error = bus.execute::<(), ()>("fail", ()).await.expect_err("fails");
        assert_eq!(error.category(), ErrorCategory::Policy);
    }

    #[tokio::test]
    async fn second_handler_for_the_same_name_fails() {
        let bus = CommandBus::new();
        bus.register(owner("ext.a"), "answer", |(): ()| async { Ok(1_u8) })
            .expect("register");

        let error = bus
            .register(owner("ext.b"), "answer", |(): ()| async { Ok(2_u8) })
            .expect_err("duplicate");
        assert!(error.message().contains("answer"), "{error}");

        let answer: u8 = bus.execute("answer", ()).await.expect("execute");
        assert_eq!(answer, 1);
    }

    #[tokio::test]
    async fn command_without_a_handler_is_a_user_error() {
        let bus = CommandBus::new();
        let error = bus
            .execute::<(), ()>("connection.open", ())
            .await
            .expect_err("no handler");
        assert_eq!(error.category(), ErrorCategory::User);
        assert!(error.message().contains("connection.open"), "{error}");
    }

    #[tokio::test]
    async fn mismatched_argument_or_response_type_is_an_error() {
        let bus = CommandBus::new();
        bus.register(owner("ext.a"), "text.len", |text: String| async move {
            Ok(text.len())
        })
        .expect("register");

        let wrong_argument = bus.execute::<u32, usize>("text.len", 1).await;
        let wrong_response = bus
            .execute::<String, String>("text.len", String::new())
            .await;
        for error in [
            wrong_argument.map(drop).expect_err("argument"),
            wrong_response.map(drop).expect_err("response"),
        ] {
            assert_eq!(error.category(), ErrorCategory::Internal);
            assert!(error.message().contains("text.len"), "{error}");
        }
    }

    #[tokio::test]
    async fn unregister_removes_one_handler_and_unregister_owner_all_of_an_owner() {
        let bus = CommandBus::new();
        let (a, b) = (owner("ext.a"), owner("ext.b"));
        for (owner, name) in [(&a, "a.one"), (&a, "a.two"), (&a, "a.three"), (&b, "b.one")] {
            bus.register(owner.clone(), name, |(): ()| async { Ok(()) })
                .expect("register");
        }

        assert!(bus.unregister("a.three"));
        assert!(!bus.unregister("a.three"));
        assert_eq!(bus.unregister_owner(&a), 2);
        assert_eq!(bus.unregister_owner(&a), 0);

        assert!(bus.execute::<(), ()>("a.one", ()).await.is_err());
        assert!(bus.execute::<(), ()>("a.two", ()).await.is_err());
        bus.execute::<(), ()>("b.one", ()).await.expect("execute");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_commands_and_one_winner_per_name() {
        let bus = Arc::new(CommandBus::new());

        // 16 tasks race to register the same name: exactly one wins.
        let racers: Vec<_> = (0..16_u64)
            .map(|n| {
                let bus = Arc::clone(&bus);
                tokio::spawn(async move {
                    bus.register(format!("ext.{n}"), "double", |n: u64| async move {
                        tokio::task::yield_now().await;
                        Ok(n * 2)
                    })
                    .is_ok()
                })
            })
            .collect();
        let mut winners = 0;
        for racer in racers {
            winners += usize::from(racer.await.expect("task"));
        }
        assert_eq!(winners, 1);

        let callers: Vec<_> = (0..64_u64)
            .map(|n| {
                let bus = Arc::clone(&bus);
                tokio::spawn(async move { bus.execute::<u64, u64>("double", n).await })
            })
            .collect();
        for (n, caller) in (0..).zip(callers) {
            assert_eq!(caller.await.expect("task").expect("execute"), n * 2);
        }
    }

    // --- Event bus ---

    #[tokio::test]
    async fn every_subscriber_receives_each_event_exactly_once() {
        let bus = EventBus::new(capacity(8));
        let mut subscribers = [bus.subscribe(), bus.subscribe(), bus.subscribe()];

        for n in 0..3 {
            assert_eq!(bus.publish(SchemaChanged(n)), 3);
        }
        // Closing the bus ends each subscription after the buffered events.
        drop(bus);

        for subscriber in &mut subscribers {
            for n in 0..3 {
                assert_eq!(
                    subscriber.recv().await,
                    Some(Received::Event(SchemaChanged(n)))
                );
            }
            assert_eq!(subscriber.recv().await, None);
        }
    }

    #[tokio::test]
    async fn events_are_routed_by_type() {
        let bus = EventBus::new(capacity(8));
        let mut schema = bus.subscribe::<SchemaChanged>();
        let mut lost = bus.subscribe::<ConnectionLost>();

        assert_eq!(bus.publish(ConnectionLost("db1")), 1);
        assert_eq!(bus.publish(SchemaChanged(1)), 1);
        drop(bus);

        assert_eq!(schema.recv().await, Some(Received::Event(SchemaChanged(1))));
        assert_eq!(schema.recv().await, None);
        assert_eq!(
            lost.recv().await,
            Some(Received::Event(ConnectionLost("db1")))
        );
        assert_eq!(lost.recv().await, None);
    }

    #[tokio::test]
    async fn publish_without_subscribers_drops_the_event() {
        let bus = EventBus::new(capacity(8));
        assert_eq!(bus.publish(SchemaChanged(1)), 0);

        // A later subscriber does not receive earlier events.
        let mut late = bus.subscribe::<SchemaChanged>();
        assert_eq!(bus.publish(SchemaChanged(2)), 1);
        assert_eq!(late.recv().await, Some(Received::Event(SchemaChanged(2))));

        drop(late);
        assert_eq!(bus.publish(SchemaChanged(3)), 0);
    }

    #[tokio::test]
    async fn slow_subscriber_does_not_block_the_publisher_and_learns_what_it_missed() {
        let bus = EventBus::new(capacity(4));
        let mut slow = bus.subscribe::<SchemaChanged>();

        // `publish` is not async: it cannot wait for the subscriber, which
        // receives nothing while this loop runs.
        for n in 0..100 {
            assert_eq!(bus.publish(SchemaChanged(n)), 1);
        }
        drop(bus);

        // The buffer kept only the newest 4 events; the other 96 are reported.
        assert_eq!(slow.recv().await, Some(Received::Missed(96)));
        for n in 96..100 {
            assert_eq!(slow.recv().await, Some(Received::Event(SchemaChanged(n))));
        }
        assert_eq!(slow.recv().await, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_publishers_and_subscribers() {
        const PUBLISHERS: u32 = 8;
        const EVENTS: u32 = 50;
        // The buffer holds every event, so no subscriber can lag.
        let bus = Arc::new(EventBus::new(capacity(512)));

        let subscribers: Vec<_> = (0..4)
            .map(|_| {
                let mut subscription = bus.subscribe::<SchemaChanged>();
                tokio::spawn(async move {
                    let mut seen = Vec::new();
                    while let Some(received) = subscription.recv().await {
                        match received {
                            Received::Event(SchemaChanged(n)) => seen.push(n),
                            Received::Missed(count) => panic!("missed {count} events"),
                        }
                    }
                    seen.sort_unstable();
                    seen
                })
            })
            .collect();

        let publishers: Vec<_> = (0..PUBLISHERS)
            .map(|p| {
                let bus = Arc::clone(&bus);
                tokio::spawn(async move {
                    for n in 0..EVENTS {
                        bus.publish(SchemaChanged(p * EVENTS + n));
                    }
                })
            })
            .collect();
        for publisher in publishers {
            publisher.await.expect("task");
        }
        drop(bus);

        let expected: Vec<u32> = (0..PUBLISHERS * EVENTS).collect();
        for subscriber in subscribers {
            assert_eq!(subscriber.await.expect("task"), expected);
        }
    }
}
