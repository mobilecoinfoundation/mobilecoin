// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Block sink that uploads [ArchiveBlock]s and [ArchiveBlocks], using a
//! [ProtoWriter].

pub use mc_ledger_streaming_api::DEFAULT_MERGED_BLOCKS_BUCKET_SIZES;

#[cfg(feature = "local")]
use crate::LocalFileProtoWriter;
use crate::ProtoWriter;
#[cfg(feature = "s3")]
use crate::S3ClientProtoWriter;
use futures::{Stream, StreamExt};
use mc_api::{block_num_to_s3block_path, merged_block_num_to_s3block_path};
use mc_common::logger::{log, Logger};
use mc_ledger_db::Ledger;
use mc_ledger_streaming_api::{ArchiveBlock, ArchiveBlocks, BlockData, Error, Result};
#[cfg(any(feature = "local", feature = "s3"))]
use std::path::PathBuf;
use std::{collections::VecDeque, convert::TryFrom};

/// A block sink that writes [ArchiveBlock] and [ArchiveBlocks] to files, with
/// the help of a [ProtoWriter], e.g. to S3 or local files.
pub struct ArchiveBlockSink<W: ProtoWriter, L: Ledger> {
    writer: W,
    ledger: L,
    merged_blocks_bucket_sizes: Vec<usize>,
    logger: Logger,
}

#[cfg(feature = "s3")]
impl<L: Ledger> ArchiveBlockSink<S3ClientProtoWriter, L> {
    /// Instantiate a sink uploading to the given path under the given region.
    pub fn new_s3(region: aws_sdk_s3::Region, path: PathBuf, ledger: L, logger: Logger) -> Self {
        Self::new(
            S3ClientProtoWriter::new(region, path),
            ledger,
            DEFAULT_MERGED_BLOCKS_BUCKET_SIZES.to_vec(),
            logger,
        )
    }

    /// Instantiate a sink uploading to the given path with the given S3 Config.
    pub fn new_s3_config(
        config: aws_sdk_s3::Config,
        path: PathBuf,
        ledger: L,
        logger: Logger,
    ) -> Self {
        Self::new(
            S3ClientProtoWriter::from_config(config, path),
            ledger,
            DEFAULT_MERGED_BLOCKS_BUCKET_SIZES.to_vec(),
            logger,
        )
    }
}

#[cfg(feature = "local")]
impl<L: Ledger> ArchiveBlockSink<LocalFileProtoWriter, L> {
    /// Instantiate an [AcrhiveBlockSink] with a [LocalFileProtoWriter] rooted
    /// at the given path.
    pub fn new_local(path: PathBuf, ledger: L, logger: Logger) -> Self {
        Self::new(
            LocalFileProtoWriter::new(path),
            ledger,
            DEFAULT_MERGED_BLOCKS_BUCKET_SIZES.to_vec(),
            logger,
        )
    }
}

impl<W: ProtoWriter, L: Ledger> ArchiveBlockSink<W, L> {
    /// Instantiate a sink with the given config.
    pub fn new(
        writer: W,
        ledger: L,
        merged_blocks_bucket_sizes: Vec<usize>,
        logger: Logger,
    ) -> Self {
        log::debug!(
            logger,
            "Creating ArchiveBlockSink with writer={:#?}",
            writer
        );
        Self {
            writer,
            ledger,
            merged_blocks_bucket_sizes,
            logger,
        }
    }

    /// Consume the given `Stream`.
    /// The returned value is a `Stream` where the `Output` type is
    /// `Result<()>`; it is executed entirely for its side effects, while
    /// propagating errors back to the caller.
    pub fn consume<'s, S: Stream<Item = Result<BlockData>>>(
        &'s mut self,
        stream: S,
    ) -> impl Stream<Item = Result<()>> + 's
    where
        S: 's,
    {
        let writer = &self.writer;
        let ledger = &self.ledger;
        let logger = &self.logger;
        let merged_blocks_bucket_sizes = &self.merged_blocks_bucket_sizes;
        stream.then(move |result| {
            let mut writer = writer.clone();
            async move {
                match result {
                    Ok(block_data) => {
                        let index = block_data.block().index;
                        let writer_mut = &mut writer;
                        write_single_block(&block_data, writer_mut).await?;
                        maybe_write_merged_blocks(
                            index,
                            merged_blocks_bucket_sizes,
                            ledger,
                            writer_mut,
                            logger,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
        })
    }
}

async fn maybe_write_merged_blocks<'s>(
    last_index: u64,
    merged_blocks_bucket_sizes: &'s [usize],
    ledger: &'s impl Ledger,
    writer: &'s impl ProtoWriter,
    logger: &'s Logger,
) -> Result<()> {
    let mut cache = VecDeque::new();
    for bucket in merged_blocks_bucket_sizes.iter().rev() {
        let bucket = *bucket;
        let bucket_u64 = bucket as u64;
        debug_assert!(
            bucket % 10 == 0,
            "Expected bucket to be a multiple of 10, got {}",
            bucket
        );

        if last_index == 0 || last_index % bucket_u64 != 0 {
            continue;
        }

        log::debug!(logger, "Writing merged block of size {}", bucket);

        // Get the last N blocks.
        cache.reserve(bucket);
        while cache.len() < bucket {
            let index = last_index - (cache.len() as u64);
            // TODO: Switch this blocking call to an async method, or use `spawn_blocking`.
            let block = ledger.get_block_data(index).map_err(|e| {
                Error::Other(format!(
                    "Failed to get block with index {} from ledger: {}",
                    index, e
                ))
            })?;
            cache.push_front(block);
        }

        write_merged_block(cache.make_contiguous(), bucket, writer).await?;
    }
    Ok(())
}

async fn write_single_block(block_data: &BlockData, writer: &mut impl ProtoWriter) -> Result<()> {
    let index = block_data.block().index;
    let proto = ArchiveBlock::from(block_data);
    let dest = block_num_to_s3block_path(index);
    writer.upload(&proto, &dest).await
}

async fn write_merged_block(
    items: &[BlockData],
    bucket_size: usize,
    writer: &mut impl ProtoWriter,
) -> Result<()> {
    assert_eq!(items.len(), bucket_size);
    let indexes = items
        .iter()
        .map(|block_data| block_data.block().index)
        .collect::<Vec<_>>();
    debug_assert!(
        indexes.windows(2).all(|w| w[0] == w[1] - 1),
        // Additional args evaluated on failure only.
        "Expected contiguous block indexes, got {:?}",
        indexes,
    );
    let proto = ArchiveBlocks::from(items);
    let dest = merged_block_num_to_s3block_path(bucket_size, indexes[0]);
    writer.upload(&proto, &dest).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, future::ready, Future};
    use mc_common::{logger::test_with_logger, HashMap};
    use mc_ledger_db::MockLedger;
    use mc_ledger_streaming_api::{
        test_utils::{make_blocks, MockStream},
        Streamer,
    };
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Debug, Default)]
    struct MockWriter {
        pub calls: Arc<Mutex<HashMap<String, Vec<PathBuf>>>>,
    }

    impl MockWriter {
        pub fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(HashMap::default())),
            }
        }

        fn log_call(&mut self, name: &str, dest: &Path) {
            let name = name.to_owned();
            let dest = dest.to_path_buf();
            let mut calls = self.calls.lock().unwrap();
            let dests = calls.entry(name.clone()).or_default();
            println!(
                "MockWriter.upload({}, {}) #{}",
                name,
                dest.display(),
                dests.len()
            );
            dests.push(dest);
        }
    }

    impl ProtoWriter for MockWriter {
        fn upload<'up, M: protobuf::Message>(
            &'up mut self,
            proto: &'up M,
            dest: &'up Path,
        ) -> Self::Future<'up> {
            self.log_call(proto.descriptor().name(), dest);
            ready(Ok(()))
        }

        type Future<'u> = impl Future<Output = Result<()>> + 'u;
    }

    #[test_with_logger]
    fn exercise_basic(logger: Logger) {
        let writer = MockWriter::new();
        let writer_calls = writer.calls.clone();
        let items = make_blocks(11);
        let source = MockStream::from_blocks(items.clone());
        let mut ledger = MockLedger::new();
        ledger
            .expect_get_block_data()
            .returning(move |index| Ok(items[index as usize].clone()));

        let mut sink = ArchiveBlockSink::new(writer, ledger, [10].to_vec(), logger);

        let stream = source.get_stream(0).expect("get_stream");
        let result_stream = sink.consume(stream);
        let result_future = result_stream.for_each(async move |res| {
            res.expect("unexpected error");
        });
        block_on(result_future);

        let calls = writer_calls.lock().unwrap();
        assert_eq!(calls["ArchiveBlock"].len(), 11);
        assert_eq!(calls["ArchiveBlocks"].len(), 1);
    }

    #[test_with_logger]
    fn propagates_ledger_errors(logger: Logger) {
        let writer = MockWriter::new();
        let writer_calls = writer.calls.clone();
        let items = make_blocks(11);
        let source = MockStream::from_blocks(items.clone());
        let mut ledger = MockLedger::new();
        ledger.expect_get_block_data().returning(move |index| {
            if index < 5 {
                Ok(items[index as usize].clone())
            } else {
                Err(mc_ledger_db::Error::NotFound)
            }
        });

        let mut sink = ArchiveBlockSink::new(writer, ledger, [10].to_vec(), logger);

        let stream = source.get_stream(0).expect("get_stream");
        let result_stream = sink.consume(stream);
        let mut got_error = false;
        let result_future = result_stream.for_each(|res| {
            match res {
                Ok(_) => {}
                Err(_) => got_error = true,
            }
            ready(())
        });
        block_on(result_future);

        assert!(got_error);
        let calls = writer_calls.lock().unwrap();
        assert_eq!(calls["ArchiveBlock"].len(), 11);
    }

    #[test_with_logger]
    fn propagates_stream_errors(logger: Logger) {
        let writer = MockWriter::new();
        let writer_calls = writer.calls.clone();
        let mut items: Vec<Result<BlockData>> = make_blocks(11).into_iter().map(Ok).collect();
        items[1] = Err(Error::Other("test".to_string()));
        items[8] = Err(Error::Other("test".to_string()));
        let source = MockStream::new(items.clone());
        let mut ledger = MockLedger::new();
        ledger.expect_get_block_data().returning(move |index| {
            items[index as usize]
                .as_ref()
                .map(|block_data| block_data.clone())
                .map_err(|_| mc_ledger_db::Error::NotFound)
        });

        let mut sink = ArchiveBlockSink::new(writer, ledger, [10].to_vec(), logger);

        let stream = source.get_stream(0).expect("get_stream");
        let result_stream = sink.consume(stream);
        let mut got_error = false;
        let result_future = result_stream.for_each(|res| {
            match res {
                Ok(_) => {}
                Err(_) => got_error = true,
            }
            ready(())
        });
        block_on(result_future);

        assert!(got_error);
        let calls = writer_calls.lock().unwrap();
        assert_eq!(calls["ArchiveBlock"].len(), 9);
    }
}
