// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains responses that are returned by Fog Overseer.

use mc_fog_types::ingest_common::IngestSummary;
use serde::Serialize;

/// The ingest summaries for the Fog Ingest cluster that Fog Overser is
/// monitoring.
#[derive(Serialize)]
pub struct GetIngestSummariesResponse {
    pub ingest_summaries: Vec<IngestSummary>,
}
