//! Basic RJSON DOM, taken from rjson tests.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{convert::TryInto, fmt::Debug};
use displaydoc::Display;
use rjson::{Array as RJsonArray, Null as RJsonNull, Object as RJsonObject, Value as RJsonValue};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An enumeration of errors which can occur while parsing the JSON of a
/// verification report
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// There was no non-whitespace data to parse
    NoData,
    /// Not all data could be read, error at position: {0}
    IncompleteParse(usize),
    /// The root of the JSON is not an object
    RootNotObject,
    /// The '{0}' field was missing from the IAS JSON
    FieldMissing(String),
    /// A field within the JSON contained an unexpected type
    FieldType,
}

pub enum Value {
    Null,
    Number(f64),
    Bool(bool),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl TryInto<()> for Value {
    type Error = Error;

    fn try_into(self) -> Result<(), Error> {
        match self {
            Value::Null => Ok(()),
            _ => Err(Error::FieldType),
        }
    }
}

impl TryInto<f64> for Value {
    type Error = Error;

    fn try_into(self) -> Result<f64, Error> {
        match self {
            Value::Number(val) => Ok(val),
            _ => Err(Error::FieldType),
        }
    }
}

impl TryInto<bool> for Value {
    type Error = Error;

    fn try_into(self) -> Result<bool, Error> {
        match self {
            Value::Bool(val) => Ok(val),
            _ => Err(Error::FieldType),
        }
    }
}

impl TryInto<String> for Value {
    type Error = Error;

    fn try_into(self) -> Result<String, Error> {
        match self {
            Value::String(val) => Ok(val),
            _ => Err(Error::FieldType),
        }
    }
}

// We can't legitimately do Vec<T> because JSON allows "arrays" of heterogeneous
// types.
impl TryInto<Vec<Value>> for Value {
    type Error = Error;

    fn try_into(self) -> Result<Vec<Value>, Error> {
        match self {
            Value::Array(val) => Ok(val),
            _ => Err(Error::FieldType),
        }
    }
}

impl TryInto<BTreeMap<String, Value>> for Value {
    type Error = Error;

    fn try_into(self) -> Result<BTreeMap<String, Value>, Error> {
        match self {
            Value::Object(val) => Ok(val),
            _ => Err(Error::FieldType),
        }
    }
}

pub struct Array(Vec<Value>);

pub struct Object(BTreeMap<String, Value>);

impl RJsonArray<Value, Object, Value> for Array {
    fn push(&mut self, v: Value) {
        self.0.push(v)
    }

    fn new() -> Self {
        Array(Vec::new())
    }
}

impl RJsonObject<Value, Array, Value> for Object {
    fn insert(&mut self, k: String, v: Value) {
        self.0.insert(k, v);
    }

    fn new() -> Self {
        Object(BTreeMap::default())
    }
}

impl RJsonNull<Value, Array, Object> for Value {
    fn new() -> Self {
        Value::Null
    }
}

impl RJsonValue<Array, Object, Value> for Value {}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Number(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}

impl From<Array> for Value {
    fn from(v: Array) -> Self {
        Value::Array(v.0)
    }
}

impl From<Object> for Value {
    fn from(v: Object) -> Self {
        Value::Object(v.0)
    }
}

pub fn parse(src: &str) -> (usize, Option<Value>) {
    let data: Vec<char> = src.chars().collect();
    let mut idx = 0;
    let retval = rjson::parse::<Value, Array, Object, Value>(&*data, &mut idx);
    (idx, retval)
}
