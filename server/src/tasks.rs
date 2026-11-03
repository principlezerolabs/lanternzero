//! Short-lived background work the server starts on its own: backfills,
//! instant payment pushes, and webhook deliveries.
//!
//! [`Tasks`] counts what is running, so a test can wait until it has all
//! finished ([`Tasks::settle`]) and then check that something did *not*
//! happen, instead of sleeping and hoping that was long enough.
//! Long-running loops (`push::run`, `chain::run`, and so on) are not
//! tracked: they never finish.

use std::future::Future;

use tokio::sync::watch;

#[derive(Debug)]
pub struct Tasks {
    running: watch::Sender<usize>,
}

impl Default for Tasks {
    fn default() -> Self {
        Self {
            running: watch::Sender::new(0),
        }
    }
}

/// Counts one task as running until it is dropped, so a task that panics
/// or is aborted still stops counting.
struct Running(watch::Sender<usize>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

impl Tasks {
    /// Runs `task` on the current Tokio runtime, counted until it ends.
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.running.send_modify(|n| *n += 1);
        let running = Running(self.running.clone());
        tokio::spawn(async move {
            let _running = running;
            task.await;
        });
    }

    /// How many tasks are running.
    pub fn running(&self) -> usize {
        *self.running.borrow()
    }

    /// Waits until no task is running, including tasks started meanwhile
    /// (a backfill a wake started, say).
    pub async fn settle(&self) {
        let mut rx = self.running.subscribe();
        // The sender lives in `self`, so this can't fail.
        let _ = rx.wait_for(|n| *n == 0).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn settle_waits_for_tasks_and_the_tasks_they_start() {
        let tasks = Arc::new(Tasks::default());
        let done = Arc::new(AtomicUsize::new(0));
        let (t, d) = (tasks.clone(), done.clone());
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let d2 = d.clone();
            t.spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                d2.fetch_add(1, Ordering::SeqCst);
            });
            d.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(tasks.running(), 1);
        tasks.settle().await;
        assert_eq!(done.load(Ordering::SeqCst), 2);
        assert_eq!(tasks.running(), 0);
        // Nothing running: returns at once.
        tasks.settle().await;
    }

    #[tokio::test]
    async fn a_panicking_task_stops_counting() {
        let tasks = Tasks::default();
        tasks.spawn(async { panic!("task failed") });
        tasks.settle().await;
        assert_eq!(tasks.running(), 0);
    }
}
