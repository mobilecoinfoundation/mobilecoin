// Copyright (c) 2018-2021 The MobileCoin Foundation

use std::{env, ffi::OsString, fs, io::Read, path::PathBuf};

const SSL_CERT_FILES: &[&str] = &[
    "/etc/ssl/certs/ca-bundle.crt",       // OpenSSL, Fedora, RHEL7+
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL6-
    "/etc/ssl/ca-bundle.pem",             // OpenSUSE
    "/etc/pki/tls/cacert.pem",            // OpenELEC
    "/etc/ssl/cert.pem",                  // MacOS
];

const SSL_CERT_DIRS: &[&str] = &[
    "/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
    "/system/etc/security/cacerts", // Android
    "/usr/local/share/certs",       // FreeBSD
    "/etc/pki/tls/certs",           // Fedora/RHEL
    "/etc/openssl/certs",           // NetBSD
];

const INITIAL_BUNDLE_CAPACITY: usize = 8192;

const SSL_CERT_EXTENSIONS: &[&str] = &["pem", "crt"];

/// Read the files in a directory that end with .crt or .pem, and put all their
/// results into a byte vector. When a path is encountered that matches a known
/// bundle file, that file will not be read unless it's the only file in the
/// directory.
///
/// For example, given an /etc/ssl/certs directory containing
///
/// /etc/ssl/certs/ca-certificates.crt
/// /etc/ssl/certs/SomeCA.pem
/// /etc/ssl/certs/OtherCA.crt
///
/// Only SomeCA and OtherCA will be included in the result. However, if that
/// directory only contained ca-certificates.crt, the contents of that file
/// would be used.
fn read_cert_dir_contents(dirname: OsString) -> Result<Vec<u8>, String> {
    let entries = fs::read_dir(&dirname)
        .map_err(|e| format!("Failed reading directory {:?}: {:?}", dirname, e))?;

    let mut retval = Vec::<u8>::with_capacity(INITIAL_BUNDLE_CAPACITY);
    let mut errors = Vec::<String>::new();
    // First, get a count of files that end in crt or pem
    for entry in entries.flatten() {
        if let Ok(metadata) = entry.metadata() {
            if metadata.is_file() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    for desired in SSL_CERT_EXTENSIONS {
                        if *desired == ext {
                            // Double capacity until we have enough space to cover this cert
                            // We *assume* that metadata is not doing a stat() on each call.
                            while retval.capacity() - retval.len() < metadata.len() as usize {
                                let capacity = retval.capacity();
                                retval.reserve(capacity);
                            }

                            if let Ok(mut f) = fs::File::open(&path) {
                                if let Err(e) = f.read_to_end(&mut retval) {
                                    errors.push(format!(
                                        "Could not read {}: {}",
                                        path.display(),
                                        e
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if retval.is_empty() {
        Err(format!(
            "No certificates found in {:?}: {}",
            dirname,
            errors.join(", ")
        ))
    } else {
        Ok(retval)
    }
}

/// This function tries it's best to provide a safe, legitimate PEM-encoded CA
/// bundle as bytes.
///
/// If ca_bundle is a directory, it will read all the PEM-encoded certificates
/// using read_cert_dir_contents(). If the given bundle is a file, it will try
/// to read it as a PEM bundle. If either of these read operations fails, it
/// will return an error, on the assumption that it should not silently attempt
/// to fall-back to the generic system bundle.
///
/// If the given bundle is neither a file nor a directory (e.g. the path doesn't
/// exist, it's a named pipe, unix socket, etc.), it will return an error.
///
/// If no bundle is provided via the parameter, this function will try to read
/// the well-known SSL_CERT_FILE and SSL_CERT_DIR environment variables in the
/// same fashion. As before, if these variables exist, but the file or directory
/// cannot be read, then it will return an error, on the assumption that you
/// wouldn't attempt to manually configure a CA bundle if the auto-detected
/// system bundle was the one you wanted.
///
/// If either of these variables is set, then this function will attempt to
/// auto-detect the system certificates, by first trying to read well-known
/// system-bundle files, and then attempting to read well-known
/// system-collection directories. The first bundle or directory which contains
/// actual data will be returned.
///
/// If, after all that, this function still can't find anything, it will return
/// an error.
pub fn read_ca_bundle(ca_bundle: Option<PathBuf>) -> Result<Vec<u8>, String> {
    ca_bundle.map_or_else(
        || {
            env::var_os("SSL_CERT_FILE").map_or_else(
                || {
                    env::var_os("SSL_CERT_DIR").map_or_else(
                        || {
                            for p in SSL_CERT_FILES {
                                match fs::read(OsString::from(p)) {
                                    Ok(retval) => return Ok(retval),
                                    Err(_e) => continue,
                                }
                            }

                            for p in SSL_CERT_DIRS {
                                match read_cert_dir_contents(OsString::from(p)) {
                                    Ok(retval) => return Ok(retval),
                                    Err(_e) => continue,
                                }
                            }

                            Err(format!(
                                "No certificate found in {:?} or {:?}",
                                SSL_CERT_FILES, SSL_CERT_DIRS
                            ))
                        },
                        read_cert_dir_contents,
                    )
                },
                |path| {
                    fs::read(path.clone()).map_err(|e| format!("Error reading {:?}: {:?}", path, e))
                },
            )
        },
        |path| {
            if path.is_dir() {
                read_cert_dir_contents(OsString::from(path))
            } else if path.is_file() {
                fs::read(path.clone()).map_err(|e| format!("Error reading {:?}: {:?}", path, e))
            } else {
                Err(format!("{:?} is not a file or directory", path))
            }
        },
    )
}
