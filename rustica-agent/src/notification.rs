use std::sync::mpsc::{channel, Sender};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

#[derive(Debug, PartialEq)]
pub enum TouchEvent {
    /// A request started waiting for a touch
    Notify,
    /// No request is waiting for a touch any more
    Dismiss,
}

struct State {
    /// Requests currently waiting for a touch
    waiting: usize,
    events: Sender<TouchEvent>,
}

/// Tells the user a hardware key is waiting for a touch. `on_event` is called
/// in order on a dedicated thread, so signing threads never run it or wait on
/// it while holding a card.
pub struct TouchNotifier {
    state: Mutex<State>,
    thread: Option<JoinHandle<()>>,
}

impl TouchNotifier {
    pub fn new(on_event: impl FnMut(TouchEvent) + Send + 'static) -> Self {
        let (events, received_events) = channel();
        // Runs until the notifier is dropped. If it can't start, signing still works
        let thread = thread::Builder::new()
            .name("touch-notifier".to_string())
            .spawn(move || received_events.into_iter().for_each(on_event))
            .map_err(|e| error!("Unable to start the touch notifier thread: {e}"))
            .ok();

        Self {
            state: Mutex::new(State { waiting: 0, events }),
            thread,
        }
    }
}

impl Drop for TouchNotifier {
    /// Waits for queued events, so `on_event` never runs after the notifier is gone
    fn drop(&mut self) {
        // Replacing the only sender closes the channel, ending the thread once it has caught up
        self.state.get_mut().unwrap().events = channel().0;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Marks one request as waiting for a touch until dropped
pub(crate) struct TouchNotificationGuard<'a>(&'a TouchNotifier);

impl Drop for TouchNotificationGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.waiting -= 1;
        if state.waiting == 0 {
            // Fails only if the notifier thread is gone
            let _ = state.events.send(TouchEvent::Dismiss);
        }
    }
}

/// Notify if a notifier is configured and a touch is required. Hold the
/// returned guard until the signing operation has finished.
pub(crate) fn notify_touch(
    notifier: &Option<TouchNotifier>,
    touch_required: bool,
) -> Option<TouchNotificationGuard<'_>> {
    let notifier = notifier.as_ref().filter(|_| touch_required)?;
    let mut state = notifier.state.lock().unwrap();
    state.waiting += 1;
    let _ = state.events.send(TouchEvent::Notify);
    Some(TouchNotificationGuard(notifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dismisses_once_no_request_is_waiting() {
        let (sender, received) = channel();
        let notifier = Some(TouchNotifier::new(move |event| {
            // Slow, so the events are only all there if dropping the notifier waited
            thread::sleep(Duration::from_millis(20));
            sender.send(event).unwrap();
        }));

        let first = notify_touch(&notifier, true);
        let second = notify_touch(&notifier, true);
        drop(first);
        drop(second);
        drop(notifier);

        assert_eq!(
            received.try_iter().collect::<Vec<_>>(),
            [TouchEvent::Notify, TouchEvent::Notify, TouchEvent::Dismiss]
        );
    }
}
