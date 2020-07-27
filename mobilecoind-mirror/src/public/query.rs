// Copyright (c) 2018-2020 MobileCoin Inc.

//! Utility entity for managing queries submitted over our rocket endpoint and resolved by the GRPC
//! polling mechanism.

use mc_mobilecoind_mirror::mobilecoind_mirror_api::{QueryRequest, QueryResponse};
use rand::RngCore;
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

/// The length of the randomly generated query id that is used to tie requests and responses
/// together.
const QUERY_ID_LEN: usize = 8;

/// The maximum amount of time to wait for a query to complete.
const QUERY_MAX_DURATION: Duration = Duration::from_secs(30);

/// The state held by each individual query.
struct QueryInner {
    request: QueryRequest,
    response: Option<QueryResponse>,
}

/// An individual query that can be asynchronously resolved and waited on.
#[derive(Clone)]
pub struct Query {
    inner: Arc<Mutex<QueryInner>>,
    condvar: Arc<Condvar>,
}

impl Query {
    pub fn new(request: QueryRequest) -> Self {
        Self {
            inner: Arc::new(Mutex::new(QueryInner {
                request,
                response: None,
            })),
            condvar: Arc::new(Condvar::new()),
        }
    }

    pub fn request(&self) -> QueryRequest {
        self.inner.lock().expect("mutex poisoned").request.clone()
    }

    pub fn resolve(&self, response: QueryResponse) {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        inner.response = Some(response);
        self.condvar.notify_one();
    }

    pub fn wait(self) -> Result<QueryResponse, String> {
        let (mut inner, wait_result) = self
            .condvar
            .wait_timeout_while(
                self.inner.lock().expect("muted poisoned"),
                QUERY_MAX_DURATION,
                |inner| inner.response.is_none(),
            )
            .expect("waiting on condvar failed");

        if wait_result.timed_out() {
            return Err("timeout".into());
        }

        assert!(inner.response.is_some());

        Ok(inner
            .response
            .take()
            .expect("response should've had something in it"))
    }
}

struct QueryManagerInner {
    /// Map of query id -> query of queries that need to get sent to the private side of the
    /// mirror.
    pending_requests: HashMap<String, Query>,

    /// Map of query id -> query of queries that were resolved by the mirror.
    pending_responses: HashMap<String, Query>,
}

impl QueryManagerInner {
    pub fn generate_query_id(&self) -> String {
        let mut rng = rand::thread_rng();

        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";

        loop {
            let query_id: String = (0..QUERY_ID_LEN)
                .map(|_| {
                    let idx = (rng.next_u64() % CHARSET.len() as u64) as usize;
                    char::from(CHARSET[idx])
                })
                .collect();

            if !self.pending_requests.contains_key(&query_id)
                && !self.pending_responses.contains_key(&query_id)
            {
                return query_id;
            }
        }
    }
}

#[derive(Clone)]
pub struct QueryManager {
    inner: Arc<Mutex<QueryManagerInner>>,
}

impl Default for QueryManager {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(QueryManagerInner {
                pending_requests: HashMap::new(),
                pending_responses: HashMap::new(),
            })),
        }
    }
}

impl QueryManager {
    pub fn enqueue_query(&self, request: QueryRequest) -> Query {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        let query_id = inner.generate_query_id();
        let query = Query::new(request);
        inner.pending_requests.insert(query_id, query.clone());
        query
    }

    pub fn get_pending_requests(&self) -> HashMap<String, QueryRequest> {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        let mut pending_requests = HashMap::new();
        let mut pending_responses = HashMap::new();

        for (query_id, query) in inner.pending_requests.drain() {
            pending_requests.insert(query_id.clone(), query.request());
            pending_responses.insert(query_id, query);
        }

        for (query_id, query) in pending_responses.drain() {
            inner.pending_responses.insert(query_id, query);
        }

        pending_requests
    }

    pub fn resolve_query(&self, query_id: &str, response: &QueryResponse) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("mutex poisoned");
        let query = inner
            .pending_responses
            .remove(query_id)
            .ok_or_else(|| format!("Unknown query id {}", query_id))?;
        query.resolve(response.clone());
        Ok(())
    }
}
