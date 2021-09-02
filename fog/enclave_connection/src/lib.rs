// Copyright (c) 2018-2021 The MobileCoin Foundation

use aes_gcm::Aes256Gcm;
use cookie::CookieJar;
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use grpcio::{CallOption, Metadata, MetadataBuilder};
use mc_attest_ake::{AuthResponseInput, ClientInitiate, Ready, Start, Transition};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_attest_core::{VerificationReport, Verifier};
use mc_common::{
    logger::{log, Logger},
    trace_time,
};
use mc_connection::{AttestedConnection, Connection};
use mc_crypto_keys::X25519;
use mc_crypto_rand::McRng;
use mc_util_grpc::{BasicCredentials, GrpcCookieStore};
use mc_util_uri::ConnectionUri;
use sha2::Sha512;

mod error;
pub use error::Error;

/// Abstracts the auth and enclave_request aspects of a grpc channel used for
/// attested connections
///
/// These calls:
/// - Take a message type appropriate to the service
/// - Take a CallOption object containing credentials info and cookies
/// - Return a message type appropriate to the service, as well as two metadata
///   objects, the first one containing grpc headers, and second one containing
///   grpc trailers.
pub trait EnclaveGrpcChannel: Send + Sync {
    fn auth(
        &mut self,
        msg: &AuthMessage,
        call_option: CallOption,
    ) -> Result<(Option<Metadata>, AuthMessage, Option<Metadata>), grpcio::Error>;
    fn enclave_request(
        &mut self,
        ciphertext: &Message,
        call_option: CallOption,
    ) -> Result<(Option<Metadata>, Message, Option<Metadata>), grpcio::Error>;
}

/// A generic object representing an attested connection to a remote enclave
pub struct EnclaveConnection<U: ConnectionUri, G: EnclaveGrpcChannel> {
    /// The URI we are connecting to, and which provides the ResponderId
    uri: U,
    /// Abstraction of one or more grpc connections
    grpc: G,
    /// The AKE state machine object, if one is available.
    attest_cipher: Option<Ready<Aes256Gcm>>,
    /// An object which can verify a fog node's provided IAS report
    verifier: Verifier,
    /// Credentials to use for all GRPC calls (this allows authentication
    /// username/password to go through, if provided).
    creds: BasicCredentials,
    /// A hash map of metadata to set on outbound requests, filled by inbound
    /// `Set-Cookie` metadata
    cookies: CookieJar,
    /// Logger
    logger: Logger,
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Connection for EnclaveConnection<U, G> {
    type Uri = U;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> AttestedConnection for EnclaveConnection<U, G> {
    type Error = Error;

    fn is_attested(&self) -> bool {
        self.attest_cipher.is_some()
    }

    fn attest(&mut self) -> Result<VerificationReport, Self::Error> {
        trace_time!(self.logger, "FogClient::attest");
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng::default();

        let initiator = Start::new(self.uri.responder_id()?.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        // Make the auth request with the server
        let call_opt = self.call_option();
        let (header, auth_response_msg, trailer) =
            self.grpc.auth(&auth_request_output.into(), call_opt)?;

        // Update cookies from server-sent metadata
        if let Err(e) = self
            .cookies
            .update_from_server_metadata(header.as_ref(), trailer.as_ref())
        {
            log::warn!(
                self.logger,
                "Could not update cookies from gRPC metadata: {}",
                e
            )
        }

        // Process server response, check if key exchange is successful
        let auth_response_event =
            AuthResponseInput::new(auth_response_msg.into(), self.verifier.clone());
        let (initiator, verification_report) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        self.attest_cipher = Some(initiator);

        Ok(verification_report)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(
                self.logger,
                "Tearing down existing attested connection and clearing cookies."
            );
            self.attest_cipher = None;
            self.cookies = CookieJar::default();
        }
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> EnclaveConnection<U, G> {
    pub fn new(uri: U, grpc: G, verifier: Verifier, logger: Logger) -> Self {
        let creds = BasicCredentials::new(&uri.username(), &uri.password());
        let cookies = CookieJar::default();

        Self {
            uri,
            grpc,
            attest_cipher: None,
            verifier,
            creds,
            cookies,
            logger,
        }
    }

    /// Produce a "call option" object appropriate for this grpc connection.
    /// This includes the http headers needed for credentials and cookies.
    pub fn call_option(&mut self) -> CallOption {
        let retval = CallOption::default();

        // Create metadata from cookies and credentials
        let mut metadata_builder = self
            .cookies
            .to_client_metadata()
            .unwrap_or_else(|_| MetadataBuilder::new());
        if !self.creds.username().is_empty() && !self.creds.password().is_empty() {
            metadata_builder
                .add_str("Authorization", &self.creds.authorization_header())
                .expect("Error setting authorization header");
        }
        retval.headers(metadata_builder.build())
    }

    /// Make an attested request to the enclave, given the plaintext to go to
    /// enclave, and any aad data, which will be nonmalleable, but visible
    /// to untrusted. Returns the decrypted and deserialized response
    /// object.
    pub fn encrypted_enclave_request<
        RequestMessage: mc_util_serial::Message,
        ResponseMessage: mc_util_serial::Message + Default,
    >(
        &mut self,
        plaintext_request: &RequestMessage,
        aad: &[u8],
    ) -> Result<ResponseMessage, Error> {
        if !self.is_attested() {
            let _verification_report = self.attest()?;
        }

        // Build encrypted request, scope attest_cipher borrow
        let msg = {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let mut msg = Message::new();
            msg.set_channel_id(Vec::from(attest_cipher.binding()));
            msg.set_aad(aad.to_vec());

            let plaintext_bytes = mc_util_serial::encode(plaintext_request);

            let request_ciphertext = attest_cipher.encrypt(aad, &plaintext_bytes)?;
            msg.set_data(request_ciphertext);
            msg
        };

        // make an attested call to EnclaveGrpcChannel::enclave_request,
        // and handle cookies
        let message = self.attested_call(|this| {
            let call_opt = this.call_option();
            let (header, message, trailer) = this.grpc.enclave_request(&msg, call_opt)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?;

        // Decrypt request, scope attest_cipher borrow
        {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let plaintext_bytes = attest_cipher.decrypt(&message.get_aad(), message.get_data())?;
            let plaintext_response: ResponseMessage = mc_util_serial::decode(&plaintext_bytes)?;
            Ok(plaintext_response)
        }
    }
}

// boilerplate

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Display for EnclaveConnection<U, G> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Eq for EnclaveConnection<U, G> {}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Hash for EnclaveConnection<U, G> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> PartialEq for EnclaveConnection<U, G> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Ord for EnclaveConnection<U, G> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> PartialOrd for EnclaveConnection<U, G> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}
