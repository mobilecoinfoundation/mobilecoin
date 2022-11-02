// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Marker types for generic key objects

/// Root address marker type
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Root;

/// Subaddress marker type
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Subaddress;

/// View key marker type
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct View;

/// Spend key marker type
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Spend;
