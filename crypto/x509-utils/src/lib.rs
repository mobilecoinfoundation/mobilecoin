// Copyright (c) 2018-2020 MobileCoin Inc.

use x509_parser::{error::PEMError, pem::Pem};

/// An iterator of [`Pem`] structures created over a string slice.
pub struct PemStringIter<'a> {
    string: &'a str,
    offset: usize,
}

impl PemStringIter {
    /// Create a new iterator based on the given string.
    fn new(string: &str) -> PemStringIter {
        PemStringIter { string, offset: 0 }
    }
}

impl Iterator for PemStringIter {
    type Item = Pem;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes: &[u8] = self.string.as_ref();

        Pem::read(&bytes[self.offset..])
            .map(|(pem, new_offset)| {
                self.offset = new_offset;
                pem
            })
            .ok()
    }
}

/// A trait used to monkey-patch a pem parsing iterator over a string.
pub trait PemStringIterable {
    /// Create an iterator over a string which contains one or many Pem objects
    fn iter_pem(&self) -> PemStringIter;
}

impl PemStringIterable for str {
    fn iter_pem(&self) -> PemStringIter {
        PemStringIter::new(self)
    }
}

/// An iterator of [`X509Certificate`] objects over a slice of [`Pem`] objects.
pub struct X509CertificateIter<'a> {
    pem_slice: &'a [Pem],
    offset: usize,
}

impl X509CertificateIter {
    fn new(pem_slice: &[Pem]) -> X509CeritificateIter {
        X509CertificateIter {
            pem_slice,
            offset: 0,
        }
    }
}

/// A trait used to monkey-patch an X509Certificate parsing iterator over a
/// slice of [`Pem`] objects.
pub trait X509CertificateIterable {
    fn iter_x509(&self) -> X509CertificateIter;
}

impl X509CertificateIterable for &[Pem] {
    fn iter_x509(&self) -> X509CertificateIter {
        X509CertificateIter::new(self)
    }
}
