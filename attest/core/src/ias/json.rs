//! Basic RJSON DOM, taken from rjson tests.

use crate::error::JsonError;
use alloc::{string::String, vec::Vec};
use core::convert::TryInto;
use mc_common::HashMap;
use rjson::{Array, Null, Object, Value};

pub(crate) enum JsonValue {
    Null,
    Number(f64),
    Bool(bool),
    String(String),
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

impl TryInto<()> for JsonValue {
    type Error = JsonError;

    #[inline]
    fn try_into(self) -> Result<(), JsonError> {
        match self {
            JsonValue::Null => Ok(()),
            _ => Err(JsonError::FieldType),
        }
    }
}

impl TryInto<f64> for JsonValue {
    type Error = JsonError;

    #[inline]
    fn try_into(self) -> Result<f64, JsonError> {
        match self {
            JsonValue::Number(val) => Ok(val),
            _ => Err(JsonError::FieldType),
        }
    }
}

impl TryInto<bool> for JsonValue {
    type Error = JsonError;

    #[inline]
    fn try_into(self) -> Result<bool, JsonError> {
        match self {
            JsonValue::Bool(val) => Ok(val),
            _ => Err(JsonError::FieldType),
        }
    }
}

impl TryInto<String> for JsonValue {
    type Error = JsonError;

    #[inline]
    fn try_into(self) -> Result<String, JsonError> {
        match self {
            JsonValue::String(val) => Ok(val),
            _ => Err(JsonError::FieldType),
        }
    }
}

// We can't legitimately do Vec<T> because JSON allows arrays of heterogenous
// types.
impl TryInto<Vec<JsonValue>> for JsonValue {
    type Error = JsonError;

    #[inline]
    fn try_into(self) -> Result<Vec<JsonValue>, JsonError> {
        match self {
            JsonValue::Array(val) => Ok(val),
            _ => Err(JsonError::FieldType),
        }
    }
}

impl TryInto<HashMap<String, JsonValue>> for JsonValue {
    type Error = JsonError;

    #[inline]
    fn try_into(self) -> Result<HashMap<String, JsonValue>, JsonError> {
        match self {
            JsonValue::Object(val) => Ok(val),
            _ => Err(JsonError::FieldType),
        }
    }
}

pub(crate) struct JsonArray(Vec<JsonValue>);
pub(crate) struct JsonObject(HashMap<String, JsonValue>);

impl Array<JsonValue, JsonObject, JsonValue> for JsonArray {
    #[inline]
    fn push(&mut self, v: JsonValue) {
        self.0.push(v)
    }

    #[inline]
    fn new() -> Self {
        JsonArray(Vec::new())
    }
}

impl Object<JsonValue, JsonArray, JsonValue> for JsonObject {
    fn insert(&mut self, k: String, v: JsonValue) {
        self.0.insert(k, v);
    }

    #[inline]
    fn new() -> Self {
        JsonObject(HashMap::default())
    }
}

impl Null<JsonValue, JsonArray, JsonObject> for JsonValue {
    #[inline]
    fn new() -> Self {
        JsonValue::Null
    }
}

impl Value<JsonArray, JsonObject, JsonValue> for JsonValue {}

impl From<f64> for JsonValue {
    #[inline]
    fn from(v: f64) -> Self {
        JsonValue::Number(v)
    }
}

impl From<bool> for JsonValue {
    #[inline]
    fn from(v: bool) -> Self {
        JsonValue::Bool(v)
    }
}

impl From<String> for JsonValue {
    #[inline]
    fn from(v: String) -> Self {
        JsonValue::String(v)
    }
}

impl From<JsonArray> for JsonValue {
    #[inline]
    fn from(v: JsonArray) -> Self {
        JsonValue::Array(v.0)
    }
}

impl From<JsonObject> for JsonValue {
    #[inline]
    fn from(v: JsonObject) -> Self {
        JsonValue::Object(v.0)
    }
}

#[inline]
pub(crate) fn parse(src: &str) -> (usize, Option<JsonValue>) {
    let data: Vec<char> = src.chars().collect();
    let mut idx = 0;
    let retval = rjson::parse::<JsonValue, JsonArray, JsonObject, JsonValue>(&*data, &mut idx);
    (idx, retval)
}
