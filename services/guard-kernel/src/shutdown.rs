//! Closing admission is distinct from undoing already committed authority.
//! Connection permits survive cancelled RPCs until their driver tasks end.
use std::{io, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, watch};

pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct Shutdown {
    requests: Arc<Semaphore>,
    connections: Option<Arc<Semaphore>>,
    started: watch::Sender<bool>,
}

impl Shutdown {
    pub(crate) fn new(requests: Arc<Semaphore>, connections: Option<Arc<Semaphore>>) -> Self {
        let (started, _) = watch::channel(false);
        Self {
            requests,
            connections,
            started,
        }
    }

    pub fn begin(&self) {
        self.requests.close();
        if let Some(connections) = &self.connections {
            connections.close();
        }
        // Persist the state even when no listener/handshake has subscribed yet.
        // A startup TERM must not disappear between registration and binding.
        self.started.send_replace(true);
    }

    pub(crate) async fn started(&self) {
        let mut state = self.started.subscribe();
        loop {
            if *state.borrow_and_update() {
                return;
            }
            if state.changed().await.is_err() {
                return;
            }
        }
    }

    pub async fn drained(&self) -> io::Result<()> {
        self.wait(DRAIN_TIMEOUT).await
    }

    async fn wait(&self, limit: Duration) -> io::Result<()> {
        if !self.requests.is_closed()
            || self
                .connections
                .as_ref()
                .is_some_and(|value| !value.is_closed())
        {
            return Err(io::Error::other("shutdown admission must be closed first"));
        }
        tokio::time::timeout(limit, async {
            let mut poll = tokio::time::interval(Duration::from_millis(10));
            loop {
                let requests_done = self.requests.available_permits() == crate::REQUEST_CAPACITY;
                let connections_done = self.connections.as_ref().is_none_or(|value| {
                    value.available_permits() == crate::state::CONNECTION_CAPACITY
                });
                if requests_done && connections_done {
                    return;
                }
                poll.tick().await;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bounded workload drain exceeded"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kernel, profile::Profile};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tonic::{Code, Response};

    #[tokio::test]
    async fn shutdown_waits_for_requests_and_actual_database_driver_permits() {
        let requests = Arc::new(Semaphore::new(crate::REQUEST_CAPACITY));
        let connections = Arc::new(Semaphore::new(crate::state::CONNECTION_CAPACITY));
        let request = requests.clone().try_acquire_owned().unwrap();
        let connection = connections.clone().try_acquire_owned().unwrap();
        let shutdown = Shutdown::new(requests.clone(), Some(connections.clone()));
        assert!(shutdown.wait(Duration::from_millis(20)).await.is_err());
        shutdown.begin();
        assert!(requests.clone().try_acquire_owned().is_err());
        assert!(connections.clone().try_acquire_owned().is_err());
        drop(request);
        let error = shutdown.wait(Duration::from_millis(20)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(connection);
        shutdown.wait(Duration::from_secs(1)).await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_denies_new_rpc_before_polling_its_authority_work() {
        let kernel = Kernel::new_with_profile(
            "http://127.0.0.1:1".into(),
            &[1u8; 32],
            Profile::Development,
            None,
        )
        .unwrap();
        let shutdown = kernel.shutdown_control();
        shutdown.begin();
        let calls = AtomicUsize::new(0);
        let result = kernel
            .bounded(async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Response::new(()))
            })
            .await;
        assert_eq!(result.unwrap_err().code(), Code::Unavailable);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        shutdown.drained().await.unwrap();
    }

    #[tokio::test]
    async fn late_listener_subscribers_observe_a_shutdown_already_started() {
        let shutdown = Shutdown::new(Arc::new(Semaphore::new(crate::REQUEST_CAPACITY)), None);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), shutdown.started())
                .await
                .is_err()
        );
        shutdown.begin();
        tokio::time::timeout(Duration::from_secs(1), shutdown.started())
            .await
            .unwrap();
        shutdown.drained().await.unwrap();
    }
}
