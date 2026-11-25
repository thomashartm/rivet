//! Public UI extension contract for rivet (ARCHITECTURE.md §4.2): the
//! contracts of the UI extension points view, command and panel.
//!
//! An extension that contributes one of them sets `requires_ui = true` in its
//! manifest (§4.4). The crate contains contracts and plain data only (§3.3).
//! It has no rendering types: a contract here says what a contribution is,
//! not how the UI shell draws it. A UI extension gets all its data through
//! the Engine API (§3.3).
//!
//! The rules of [`rivet_sdk::extension`] apply to these contracts too.

#![warn(missing_docs)]

use rivet_sdk::error::Result;
use rivet_sdk::extension::{BoxFuture, Contract};
use rivet_sdk::manifest::ExtensionPoint;

/// The identity of a UI contribution. The UI shell uses it to register the
/// contribution and to show it to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UiDescriptor {
    /// The name of the contribution inside the extension. It is the `id` of
    /// the contribution in the manifest.
    pub id: String,
    /// The text that the UI shell shows for the contribution.
    pub title: String,
}

impl UiDescriptor {
    /// Creates a descriptor.
    ///
    /// ```
    /// use rivet_ui_sdk::UiDescriptor;
    ///
    /// let descriptor = UiDescriptor::new("grid", "Result grid");
    /// assert_eq!(descriptor.title, "Result grid");
    /// ```
    pub fn new(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
        }
    }
}

/// The contract of [`ExtensionPoint::UiView`]: a view in the main area of a
/// window, for example an editor or a grid.
pub trait UiView: Send + Sync {
    /// Describes the view.
    fn descriptor(&self) -> UiDescriptor;
}

/// The contract of [`ExtensionPoint::UiCommand`]: an action that the user
/// starts from the UI.
pub trait UiCommand: Send + Sync {
    /// Describes the command.
    fn descriptor(&self) -> UiDescriptor;

    /// Runs the command.
    fn run(&self) -> BoxFuture<'_, Result<()>>;
}

/// The contract of [`ExtensionPoint::UiPanel`]: a panel at the side of a
/// window, for example a navigator.
pub trait UiPanel: Send + Sync {
    /// Describes the panel.
    fn descriptor(&self) -> UiDescriptor;
}

impl Contract for dyn UiView {
    const POINT: ExtensionPoint = ExtensionPoint::UiView;
}
impl Contract for dyn UiCommand {
    const POINT: ExtensionPoint = ExtensionPoint::UiCommand;
}
impl Contract for dyn UiPanel {
    const POINT: ExtensionPoint = ExtensionPoint::UiPanel;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};

    use rivet_sdk::error::{Error, ErrorCategory};

    use super::*;

    /// Runs a future that is always ready, without an async runtime.
    fn block_on<T>(mut future: BoxFuture<'_, T>) -> T {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the mock future is always ready"),
        }
    }

    /// The mock is a view, a command and a panel. The command fails when it
    /// runs a second time.
    #[derive(Default)]
    struct Mock {
        ran: AtomicBool,
    }

    fn descriptor(id: &str) -> UiDescriptor {
        UiDescriptor {
            id: id.into(),
            title: format!("Mock {id}"),
        }
    }

    impl UiView for Mock {
        fn descriptor(&self) -> UiDescriptor {
            descriptor("view")
        }
    }

    impl UiCommand for Mock {
        fn descriptor(&self) -> UiDescriptor {
            descriptor("command")
        }

        fn run(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                if self.ran.swap(true, Ordering::SeqCst) {
                    return Err(Error::user("the command ran before"));
                }
                Ok(())
            })
        }
    }

    impl UiPanel for Mock {
        fn descriptor(&self) -> UiDescriptor {
            descriptor("panel")
        }
    }

    #[test]
    fn ui_view_describes_itself() {
        let view: Box<dyn UiView> = Box::new(Mock::default());
        assert_eq!(view.descriptor(), descriptor("view"));
    }

    #[test]
    fn ui_command_describes_itself_and_runs() {
        let command: Arc<dyn UiCommand> = Arc::new(Mock::default());
        assert_eq!(command.descriptor().title, "Mock command");
        block_on(command.run()).unwrap();
        let error = block_on(command.run()).unwrap_err();
        assert_eq!(error.category(), ErrorCategory::User);
    }

    #[test]
    fn ui_panel_describes_itself() {
        let panel: Box<dyn UiPanel> = Box::new(Mock::default());
        assert_eq!(panel.descriptor(), descriptor("panel"));
    }

    #[test]
    fn every_ui_extension_point_has_exactly_one_contract() {
        const MAPPED: [ExtensionPoint; 3] = [
            <dyn UiView as Contract>::POINT,
            <dyn UiCommand as Contract>::POINT,
            <dyn UiPanel as Contract>::POINT,
        ];
        let mut contracts = [0; MAPPED.len()];
        for point in MAPPED {
            let index = match point {
                ExtensionPoint::UiView => 0,
                ExtensionPoint::UiCommand => 1,
                ExtensionPoint::UiPanel => 2,
                headless => panic!("the contract of {headless:?} is in rivet-sdk"),
            };
            assert!(point.is_ui());
            contracts[index] += 1;
        }
        assert_eq!(contracts, [1; MAPPED.len()]);
    }

    #[test]
    fn every_contract_is_a_send_and_sync_trait_object() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn UiView>();
        assert_send_sync::<dyn UiCommand>();
        assert_send_sync::<dyn UiPanel>();
    }
}
