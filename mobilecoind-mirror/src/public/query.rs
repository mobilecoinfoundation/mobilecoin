use mc_mobilecoind_mirror::mobilecoind_mirror_api::{QueryRequest, QueryResponse};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex},
};

struct QueryInner {
    request: QueryRequest,
    response: Option<QueryResponse>,
}

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
        let mut inner = self.inner.lock().map_err(|err| err.to_string())?;
        while inner.response.is_none() {
            inner = self.condvar.wait(inner).map_err(|err| err.to_string())?;
        }
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

#[derive(Clone)]
pub struct QueryManager {
    inner: Arc<Mutex<QueryManagerInner>>,
}

impl QueryManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(QueryManagerInner {
                pending_requests: HashMap::new(),
                pending_responses: HashMap::new(),
            })),
        }
    }

    pub fn enqueue_query(&self, query_id: String, request: QueryRequest) -> Result<Query, String> {
        let query = Query::new(request);
        let mut inner = self.inner.lock().expect("mutex poisoned");
        if inner.pending_requests.contains_key(&query_id) {
            return Err(format!("Query id {} already in pending queue", query_id));
        }
        inner.pending_requests.insert(query_id, query.clone());
        Ok(query)
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
        match inner.pending_responses.remove(query_id) {
            Some(query) => Ok(query.resolve(response.clone())),
            None => Err(format!("Unknown query id {}", query_id)),
        }
    }
}
