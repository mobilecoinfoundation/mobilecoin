// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Custom Future implementations for the block streaming client

use crate::error::{Error as ClientError, LockReason};
use futures::{
    task::{Context, Poll},
    Future, Stream,
};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{
    BlockStreamComponents, Error as StreamError, Result as StreamResult,
};
use mc_transaction_core::{ring_signature::KeyImage, BlockIndex};
use pin_project::pin_project;
use std::{
    pin::Pin,
    sync::{Arc, RwLock},
};

/// Enum to allow monadic results other than Some & None for
/// stream types were None would terminate the stream. Useful for
/// stream combinations like Scan --> Filter_Map
pub enum Ready<T> {
    /// Value with data container to indicate a value is ready
    Ready(T),

    /// Indicates to subsequent future/stream upstream is not ready
    NotReady,
}

/// Future for writing blocks to LedgerDB
pub struct WriteBlock<L: Ledger> {
    ledger: Arc<RwLock<L>>,
    stream_components: Option<BlockStreamComponents>,
}

impl<L: Ledger> WriteBlock<L> {
    /// Initialize future with ledger copy & block data
    pub fn new(ledger: Arc<RwLock<L>>, stream_components: BlockStreamComponents) -> Self {
        Self {
            ledger,
            stream_components: Some(stream_components),
        }
    }

    /// future to error Attempt to write block, an error result here results
    /// in the future returning Poll:Pending
    fn write_block(&mut self) -> Result<BlockStreamComponents, ClientError> {
        let block_index: BlockIndex;
        {
            let stream_components = self.stream_components.as_ref().unwrap();
            {
                let read_only_ledger = self.ledger.try_read()?;
                block_index = stream_components.block_data.block().index;
                let current_index = read_only_ledger.num_blocks()? + 1;
                if current_index < block_index {
                    return Err(ClientError::BlockIndexTooFar(block_index, current_index));
                }
            }

            let mut write_ledger = self.ledger.try_write()?;
            write_ledger.append_block(
                stream_components.block_data.block(),
                stream_components.block_data.contents(),
                stream_components.block_data.signature().clone(),
            )?;
        }
        Ok(self.stream_components.take().unwrap())
    }
}

impl<L: Ledger> Future for WriteBlock<L> {
    type Output = StreamResult<BlockStreamComponents>;

    ///Attempt to write block and return the block index written
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut().write_block() {
            Ok(component) => Poll::Ready(Ok(component)),
            Err(err) => match err {
                ClientError::BlockIndexTooFar(_, _) => Poll::Pending,
                ClientError::Locked(reason) => {
                    if reason == LockReason::WouldBlock {
                        Poll::Pending
                    } else {
                        Poll::Ready(Err(StreamError::DBAccess))
                    }
                }
                _ => Poll::Ready(Err(StreamError::DBAccess)),
            },
        }
    }
}

/// Future for reading ledger db
pub struct ReadLedger<'a, L: Ledger> {
    ledger: Arc<RwLock<L>>,
    method: ReadRequest<'a>,
}

/// List of read requests to make against ledgerdb
pub enum ReadRequest<'a> {
    /// Contains key image method
    ContainsKeyImage(&'a KeyImage),
}

/// List of responses from ledgerdb
pub enum ReadResponse {
    /// Key image response
    ContainsKeyImage(bool),
}

impl<'a, L: Ledger> ReadLedger<'a, L> {
    /// Initialize future with ledger copy & read method
    pub fn new(ledger: Arc<RwLock<L>>, method: ReadRequest<'a>) -> Self {
        Self { ledger, method }
    }

    /// Attempt to do requested read
    fn do_read(&mut self) -> Result<ReadResponse, ClientError> {
        {
            {
                let r_ledger = self.ledger.try_read()?;
                match &self.method {
                    ReadRequest::ContainsKeyImage(key_image) => {
                        let contains = r_ledger.contains_key_image(key_image)?;
                        Ok(ReadResponse::ContainsKeyImage(contains))
                    }
                }
            }
        }
    }
}

impl<'a, L: Ledger> Future for ReadLedger<'a, L> {
    type Output = StreamResult<ReadResponse>;

    ///Attempt to write block and return the block index written
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut().do_read() {
            Ok(read_result) => Poll::Ready(Ok(read_result)),
            Err(err) => match err {
                ClientError::Locked(reason) => {
                    if reason == LockReason::WouldBlock {
                        Poll::Pending
                    } else {
                        Poll::Ready(Err(StreamError::DBAccess))
                    }
                }
                _ => Poll::Ready(Err(StreamError::DBAccess)),
            },
        }
    }
}

/// Stream that allows db write futures to be passed through
#[pin_project]
pub struct LedgerStream<L: Ledger, US: Stream<Item = StreamResult<BlockStreamComponents>>> {
    ledger: Arc<RwLock<L>>,
    #[pin]
    upstream: US,
}

impl<L: Ledger, US: Stream<Item = StreamResult<BlockStreamComponents>>> LedgerStream<L, US> {
    /// Initialize new ledger stream with ledger and upstream
    pub fn new(ledger: L, upstream: US) -> Self {
        Self {
            ledger: Arc::new(RwLock::new(ledger)),
            upstream,
        }
    }
}

impl<L: Ledger, US: Stream<Item = StreamResult<BlockStreamComponents>>> Stream
    for LedgerStream<L, US>
{
    type Item = WriteBlock<L>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ledger = self.ledger.clone();
        let this = self.project();
        match this.upstream.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                if let Some(block_result) = result {
                    let write_future = WriteBlock::new(ledger, block_result.unwrap());
                    Poll::Ready(Some(write_future))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use futures::StreamExt;
    use mc_common::logger::{log, test_with_logger, Logger};
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_ledger_streaming_api::test_utils::stream::get_raw_stream_with_n_components;
    use std::sync::Arc;

    #[test_with_logger]
    fn future_drives_correctly(logger: Logger) {
        let mock_ledger = get_mock_ledger(0);
        let dest_ledger = Arc::new(RwLock::new(mock_ledger));
        let ledger_ref = dest_ledger.clone();
        let stream = get_raw_stream_with_n_components(30);
        let mut stream2 = stream
            .map(move |block_data| WriteBlock::new(ledger_ref.clone(), block_data.unwrap()))
            .buffered(2000);

        futures::executor::block_on(async move {
            let mut index: u64;
            while let Some(block_component) = stream2.next().await {
                index = block_component.unwrap().block_data.block().index;
                if index >= 30 {
                    log::info!(logger, "wrote {} blocks with ledger future", index);
                    break;
                }
            }
        });

        let ledger = dest_ledger.read().unwrap();
        assert_eq!(30, ledger.num_blocks().unwrap());
    }
}
