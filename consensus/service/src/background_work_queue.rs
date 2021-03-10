// Copyright (c) 2018-2021 The MobileCoin Foundation

//! BackgroundWorkQueue: A data structure that wraps crossbeam_channel queues
//! for background message processing by a worker thread. It allows multiple
//! threads to send messages to the queue.

use mc_util_metered_channel::{self, Receiver, Sender};
use mc_util_metrics::IntGauge;
use std::{io, sync::Arc, thread};

enum QueueMsg<T> {
    Handle(T),
    StopRequested,
}

#[derive(Debug)]
pub enum BackgroundWorkQueueError {
    ThreadSpawnFailed(io::Error),
    SendFailed,
    RecvFailed,
    AlreadyStarted,
    JoinFailed(String),
}

pub struct BackgroundWorkQueue<T: Send + 'static> {
    join_handle: Option<thread::JoinHandle<Result<(), BackgroundWorkQueueError>>>,
    sender: Sender<QueueMsg<T>>,
    receiver: Receiver<QueueMsg<T>>,
}

pub type BackgroundWorkQueueSenderFn<T> =
    Arc<dyn Fn(T) -> Result<(), BackgroundWorkQueueError> + Sync + Send>;

impl<T: Send + 'static> BackgroundWorkQueue<T> {
    pub fn new(gauge: &IntGauge) -> Self {
        let (sender, receiver) = mc_util_metered_channel::unbounded(gauge);

        Self {
            join_handle: None,
            sender,
            receiver,
        }
    }

    pub fn start<F: Fn(T) + Send + 'static>(
        &mut self,
        thread_name: String,
        handle_func: F,
    ) -> Result<(), BackgroundWorkQueueError> {
        if self.join_handle.is_some() {
            return Err(BackgroundWorkQueueError::AlreadyStarted);
        }

        let thread_receiver = self.receiver.clone();
        let join_handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || loop {
                match thread_receiver.recv() {
                    // Successfully received something from the queue
                    Ok(msg) => {
                        match msg {
                            // Request to call our handler function
                            QueueMsg::Handle(msg) => handle_func(msg),

                            // Request to stop the thread
                            QueueMsg::StopRequested => {
                                return Ok(());
                            }
                        };
                    }

                    // Error receiving from queue
                    Err(_err) => {
                        return Err(BackgroundWorkQueueError::RecvFailed);
                    }
                }
            })
            .map_err(BackgroundWorkQueueError::ThreadSpawnFailed)?;

        self.join_handle = Some(join_handle);

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), BackgroundWorkQueueError> {
        // Send a stop request. We ignore return value since we might already be
        // stopped.
        let _ = self.send_msg(QueueMsg::StopRequested);

        self.join()
    }

    pub fn join(&mut self) -> Result<(), BackgroundWorkQueueError> {
        if let Some(join_handle) = self.join_handle.take() {
            return join_handle
                .join()
                .map_err(|e| BackgroundWorkQueueError::JoinFailed(format!("{:?}", e)))?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn send(&self, msg: T) -> Result<(), BackgroundWorkQueueError> {
        self.send_msg(QueueMsg::Handle(msg))
    }

    #[allow(dead_code)]
    pub fn get_sender_fn(&self) -> BackgroundWorkQueueSenderFn<T> {
        let sender = self.sender.clone();
        Arc::new(move |msg| {
            sender
                .send(QueueMsg::Handle(msg))
                .or(Err(BackgroundWorkQueueError::SendFailed))
        })
    }

    fn send_msg(&self, msg: QueueMsg<T>) -> Result<(), BackgroundWorkQueueError> {
        self.sender
            .send(msg)
            .or(Err(BackgroundWorkQueueError::SendFailed))
    }
}

impl<T: Send + 'static> Drop for BackgroundWorkQueue<T> {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
