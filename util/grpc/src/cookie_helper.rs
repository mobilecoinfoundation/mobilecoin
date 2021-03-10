// Copyright (c) 2018-2021 The MobileCoin Foundation

use cookie::{Cookie, CookieJar, ParseError};
use displaydoc::Display;
use grpcio::{Error as GrpcioError, Metadata, MetadataBuilder};
use std::string::FromUtf8Error;

/// Errors which can occur while parsing or printing cookies.
#[derive(Debug, Display, Eq, PartialEq)]
pub enum Error {
    /// The value given by a Set-Cookie header was not valid UTF-8: {0}
    Utf8(FromUtf8Error),
    /// The value given by a Set-Cookie was not in the proper format: {0}
    Parse(ParseError),
    /// There was an error building metadata from cookie storage: {0}
    Builder(String),
}

impl From<ParseError> for Error {
    fn from(src: ParseError) -> Error {
        Error::Parse(src)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(src: FromUtf8Error) -> Error {
        Error::Utf8(src)
    }
}

impl From<GrpcioError> for Error {
    fn from(src: GrpcioError) -> Error {
        Error::Builder(src.to_string())
    }
}

/// A trait used to monkey-patch helper methods onto the `cookie::CookieJar`
/// type.
pub trait GrpcCookieStore {
    /// Search metadata received from a server and treat any `Set-Cookie` values
    /// appropriately.
    fn update_from_server_metadata(
        &mut self,
        headers: Option<&Metadata>,
        trailers: Option<&Metadata>,
    ) -> Result<(), Error>;

    /// Copy the contents of this CookieJar into a Metadata structure containing
    /// any `Cookie` headers to send to a server.
    fn to_client_metadata(&self) -> Result<MetadataBuilder, Error>;
}

fn append_to_cookies(dest: &mut Vec<Cookie>, src: Option<&Metadata>) -> Result<(), Error> {
    if let Some(metadata) = src {
        for (name, value) in metadata {
            if name.eq_ignore_ascii_case("set-cookie") {
                let stringvalue = String::from_utf8(value.to_vec())?;
                dest.push(Cookie::parse(stringvalue)?);
            }
        }
    }
    Ok(())
}

impl GrpcCookieStore for CookieJar {
    fn update_from_server_metadata(
        &mut self,
        header: Option<&Metadata>,
        trailer: Option<&Metadata>,
    ) -> Result<(), Error> {
        let mut cookies = Vec::new();
        append_to_cookies(&mut cookies, header)?;
        append_to_cookies(&mut cookies, trailer)?;

        for cookie in cookies {
            self.add(cookie);
        }
        Ok(())
    }

    fn to_client_metadata(&self) -> Result<MetadataBuilder, Error> {
        let mut builder = MetadataBuilder::new();

        for cookie in self.iter() {
            builder.add_str("Cookie", cookie.to_string().as_str())?;
        }

        Ok(builder)
    }
}
