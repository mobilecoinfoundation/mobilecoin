// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains responses that are returned by Fog Overseer.

use mc_fog_types::ingest_common::IngestSummary;
use mc_fog_uri::FogIngestUri;
use serde::Serialize;
use std::collections::HashMap;

/// The ingest summaries for the Fog Ingest cluster that Fog Overser is
/// monitoring. If an ingest summary can't be retrieved for a given node, then
/// an error message, rather than an ingest summary, is returned for that node.
#[derive(Serialize)]
pub struct GetIngestSummariesResponse {
    pub ingest_summaries: HashMap<FogIngestUri, Result<IngestSummary, String>>,
}
