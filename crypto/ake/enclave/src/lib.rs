// Copyright (c) 2018-2023 The MobileCoin Foundation

#![no_std]
#![allow(clippy::result_large_err)]
extern crate alloc;

use aes_gcm::Aes256Gcm;
use alloc::{borrow::ToOwned, string::ToString, vec::Vec};
use mc_attest_ake::{
    AuthPending, AuthRequestOutput, AuthResponseInput, AuthResponseOutput, ClientAuthRequestInput,
    ClientInitiate, NodeAuthRequestInput, NodeInitiate, Ready, Start, Transition,
};
use mc_attest_core::{
    DcapEvidence, EnclaveReportDataContents, IntelSealed, Nonce, QuoteNonce, Report, ReportData,
    TargetInfo,
};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, Error, NonceAuthRequest,
    NonceAuthResponse, NonceSession, PeerAuthRequest, PeerAuthResponse, PeerSession,
    PlaintextClientRequest, Result, SealedClientMessage,
};
use mc_attest_trusted::{EnclaveReport, SealAlgo};
use mc_attest_verifier::{DcapVerifier, Error as VerifierError};
use mc_attestation_verifier::{
    Evidence, TrustedIdentity, TrustedMrEnclaveIdentity, VerificationTreeDisplay,
};
use mc_common::{LruCache, ResponderId};
use mc_crypto_keys::{X25519Private, X25519Public, X25519};
use mc_rand::McRng;
use mc_sgx_compat::sync::Mutex;
use mc_util_from_random::FromRandom;
use sha2::Sha512;
use alloc::format;

/// Max number of pending quotes.
const MAX_PENDING_QUOTES: usize = 64;

/// Max number of pending authentication requests.
const MAX_AUTH_PENDING_REQUESTS: usize = 64;

/// Max number of peer sessions.
const MAX_PEER_SESSIONS: usize = 64;

/// Maximum number of concurrent sessions to this enclave from router enclaves.
const MAX_FRONTEND_SESSIONS: usize = 500;

/// Max number of backends that this enclave can connect to as a client.
const MAX_BACKEND_SESSIONS: usize = 10_000;

/// Max number of client sessions.
const MAX_CLIENT_SESSIONS: usize = 10_000;

/// Max number of auth requests for enclave backends.
const MAX_BACKEND_AUTH_PENDING_REQUESTS: usize = 10_000;

/// Any additional "identities" (e.g. key material) for a given enclave that
/// needs to become a part of the report. We provide some simple identities, and
/// a trait to allow extensions
mod identity;

pub use identity::{EnclaveIdentity, NullIdentity};

/// State associated to Attested Authenticated Key Exchange held by an enclave,
/// including for peers and for clients.
/// This also includes cached attestation evidence, and data that goes in the
/// attestation evidence
pub struct AkeEnclaveState<EI: EnclaveIdentity> {
    /// ResponderId used for peer connections
    peer_self_id: Mutex<Option<ResponderId>>,

    /// ResponderId used for client connections
    client_self_id: Mutex<Option<ResponderId>>,

    /// The static identity used for key exchange, generated on startup
    /// Initialized once, read only after that, so doesn't need to be behind a
    /// mutex
    kex_identity: X25519Private,

    /// Any additional (customized) identity
    custom_identity: EI,

    /// A map of generated EREPORTs awaiting confirmation by the quoting
    /// enclave.
    quote_pending: Mutex<LruCache<QuoteNonce, Report>>,

    /// The cached attestation evidence, if any.
    current_attestation_evidence: Mutex<Option<DcapEvidence>>,

    /// A map of responder-ID to incomplete, outbound, AKE state.
    initiator_auth_pending: Mutex<LruCache<ResponderId, AuthPending<X25519, Aes256Gcm, Sha512>>>,

    /// A map of responder-ID to incomplete, outbound AKE state for connections
    /// to enclaves that serve as backends to the current enclave.
    backend_auth_pending: Mutex<LruCache<ResponderId, AuthPending<X25519, Aes256Gcm, Sha512>>>,

    /// A map of channel ID outbound connection state.
    peer_outbound: Mutex<LruCache<PeerSession, Ready<Aes256Gcm>>>,

    /// A map of channel ID to inbound connection state.
    peer_inbound: Mutex<LruCache<PeerSession, Ready<Aes256Gcm>>>,

    /// A map of channel ID to connection state
    clients: Mutex<LruCache<ClientSession, Ready<Aes256Gcm>>>,

    /// A map of inbound session IDs to connection states, for use by a
    /// store/router backend
    frontends: Mutex<LruCache<NonceSession, Ready<Aes256Gcm>>>,

    /// A map of ResponderIds for each enclave that serves as a backend to the
    /// current enclave.
    backends: Mutex<LruCache<ResponderId, Ready<Aes256Gcm>>>,
}

impl<EI: EnclaveIdentity + Default> Default for AkeEnclaveState<EI> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<EI: EnclaveIdentity> AkeEnclaveState<EI> {
    /// Initialize, injecting a custom identity
    pub fn new(custom_identity: EI) -> Self {
        Self {
            peer_self_id: Mutex::new(None),
            client_self_id: Mutex::new(None),
            kex_identity: X25519Private::from_random(&mut McRng::default()),
            custom_identity,
            quote_pending: Mutex::new(LruCache::new(MAX_PENDING_QUOTES)),
            current_attestation_evidence: Mutex::new(None),
            initiator_auth_pending: Mutex::new(LruCache::new(MAX_AUTH_PENDING_REQUESTS)),
            backend_auth_pending: Mutex::new(LruCache::new(MAX_BACKEND_AUTH_PENDING_REQUESTS)),
            peer_outbound: Mutex::new(LruCache::new(MAX_PEER_SESSIONS)),
            peer_inbound: Mutex::new(LruCache::new(MAX_PEER_SESSIONS)),
            clients: Mutex::new(LruCache::new(MAX_CLIENT_SESSIONS)),
            frontends: Mutex::new(LruCache::new(MAX_FRONTEND_SESSIONS)),
            backends: Mutex::new(LruCache::new(MAX_BACKEND_SESSIONS)),
        }
    }

    /// Get the Kex public identity
    pub fn get_kex_identity(&self) -> X25519Public {
        X25519Public::from(&self.kex_identity)
    }

    /// Get the (user-injected) custom identity
    pub fn get_identity(&self) -> &EI {
        &self.custom_identity
    }

    //
    // Kex related
    //

    /// Get identity which ensures MRENCLAVE matches
    fn trusted_identity(&self) -> Result<TrustedIdentity> {
        let report_body = Report::new(None, None)?.body();

        let mr_enclave = report_body.mr_enclave();

        // INTEL-SA-00334: LVI hardening is handled via rustc arguments set in
        // mc-util-build-enclave
        //
        // INTEL-SA-00615: MMIO Stale Data is handled by using [out] parameters
        // in our ECALL/OCALL definitions (EDLs), and only performing direct
        // writes aligned to quadword (8B) boundaries (e.g. in ORAMStorage)
        //
        // INTEL-SA-00657: xAPIC Stale Data is handled by ensuring reads in/out of the
        // enclave are aligned to an 8-byte boundary, and performed in multiples
        // of 8 bytes. In our codebase, this happens within the sgx_edger8r code-gen, so
        // building against SGX 2.17.1 is sufficient hardening for now.
        Ok(TrustedMrEnclaveIdentity::new(
            mr_enclave,
            [] as [&str; 0],
            ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"],
        )
        .into())
    }

    /// Construct a new verifier which ensures MRENCLAVE and debug settings
    /// match.
    fn get_verifier(&self, report_data: EnclaveReportDataContents) -> Result<DcapVerifier> {
        Ok(DcapVerifier::new(
            [self.trusted_identity()?],
            None,
            report_data,
        ))
    }

    /// Get the peer ResponderId for ourself
    pub fn get_peer_self_id(&self) -> Result<ResponderId> {
        (self.peer_self_id.lock()?).clone().ok_or(Error::NotInit)
    }

    /// Get the client ResponderId for ourself
    pub fn get_client_self_id(&self) -> Result<ResponderId> {
        (self.client_self_id.lock()?).clone().ok_or(Error::NotInit)
    }

    /// Init responder ids
    pub fn init(&self, peer_self_id: ResponderId, client_self_id: ResponderId) -> Result<()> {
        let mut peer_lock = self.peer_self_id.lock()?;
        let mut client_lock = self.client_self_id.lock()?;
        if peer_lock.is_none() && client_lock.is_none() {
            *peer_lock = Some(peer_self_id);
            *client_lock = Some(client_self_id);
            Ok(())
        } else {
            Err(Error::AlreadyInit)
        }
    }

    pub fn frontend_encrypt(
        &self,
        session_id: &NonceSession,
        aad: &[u8],
        data: &[u8],
    ) -> Result<EnclaveMessage<NonceSession>> {
        let mut frontends = self.frontends.lock()?;
        let session = frontends.get_mut(session_id).ok_or(Error::NotFound)?;
        let (data, nonce) = session.encrypt_with_nonce(aad, data)?;
        let channel_id = NonceSession::new(session.binding().to_owned(), nonce);

        // Return message
        Ok(EnclaveMessage {
            aad: aad.to_vec(),
            channel_id,
            data,
        })
    }

    pub fn frontend_decrypt(&self, msg: EnclaveMessage<NonceSession>) -> Result<Vec<u8>> {
        let mut frontends = self.frontends.lock()?;
        frontends
            .get_mut(&msg.channel_id)
            .ok_or(Error::NotFound)
            .and_then(|session| {
                Ok(session.decrypt_with_nonce(&msg.aad, &msg.data, msg.channel_id.nonce())?)
            })
    }

    /// Accept an explicit-nonce session from a frontend service (router) to
    /// ourselves (acting as a store).
    pub fn frontend_accept(
        &self,
        req: NonceAuthRequest,
    ) -> Result<(NonceAuthResponse, NonceSession)> {
        let local_identity = self.kex_identity.clone();
        let attestation_evidence = self.get_attestation_evidence()?;

        // Create the state machine
        let responder = Start::new(self.get_client_self_id()?.to_string());

        // Massage the request message into state machine input
        let auth_request = {
            let req: Vec<u8> = req.into();
            ClientAuthRequestInput::<X25519, Aes256Gcm, Sha512>::new(
                AuthRequestOutput::from(req),
                local_identity,
                attestation_evidence,
            )
        };

        // Advance the state machine
        let mut csprng = McRng::default();
        let (responder, auth_response) = responder.try_next(&mut csprng, auth_request)?;
        // For the first message, nonce is a zero
        let session_id = NonceSession::new(responder.binding().to_owned(), 0);

        // This session is established as far as we are concerned.
        self.frontends.lock()?.put(session_id.clone(), responder);

        // Massage the state machine output into the response message
        let auth_response: Vec<u8> = auth_response.into();

        Ok((NonceAuthResponse::from(auth_response), session_id))
    }

    /// Drop the given session from the list of known frontend router sessions.
    pub fn frontend_close(&self, channel_id: NonceSession) -> Result<()> {
        self.frontends.lock()?.pop(&channel_id);
        Ok(())
    }

    /// Constructs a NonceAuthRequest to be sent to an enclave backend.
    ///
    /// Differs from peer_init in that this enclave does not establish a peer
    /// connection to the enclave described by `backend_id`. Rather, this
    /// enclave serves as a client to this other backend enclave.
    pub fn backend_init(&self, backend_id: ResponderId) -> Result<NonceAuthRequest> {
        let mut csprng = McRng::default();

        let initiator = Start::new(backend_id.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;
        self.backend_auth_pending.lock()?.put(backend_id, initiator);
        let client_auth_request_data: Vec<u8> = auth_request_output.into();
        Ok(client_auth_request_data.into())
    }

    /// Connect to an enclave backend as a client.
    ///
    /// This establishes the client to backend enclave connection, see
    /// `backend_init` for more details on how this differs from a peer
    /// connection.
    pub fn backend_connect(
        &self,
        backend_id: ResponderId,
        backend_auth_response: NonceAuthResponse,
    ) -> Result<()> {
        let initiator = self
            .backend_auth_pending
            .lock()?
            .pop(&backend_id)
            .ok_or(Error::NotFound)?;

        let mut csprng = McRng::default();

        let auth_response_output_bytes: Vec<u8> = backend_auth_response.into();
        let auth_response_event = AuthResponseInput::new(
            auth_response_output_bytes.into(),
            [self.trusted_identity()?],
        );
        let (initiator, _verification_report) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        let mut backends = self.backends.lock()?;
        backends.put(backend_id, initiator);

        Ok(())
    }

    /// Accept a client connection
    pub fn client_accept(
        &self,
        req: ClientAuthRequest,
    ) -> Result<(ClientAuthResponse, ClientSession)> {
        let local_identity = self.kex_identity.clone();
        let attestation_evidence = self.get_attestation_evidence()?;

        // Create the state machine
        let responder = Start::new(self.get_client_self_id()?.to_string());

        // Massage the request message into state machine input
        let auth_request = {
            let req: Vec<u8> = req.into();
            ClientAuthRequestInput::<X25519, Aes256Gcm, Sha512>::new(
                AuthRequestOutput::from(req),
                local_identity,
                attestation_evidence,
            )
        };

        // Advance the state machine
        let mut csprng = McRng::default();
        let (responder, auth_response) = responder.try_next(&mut csprng, auth_request)?;
        let session_id = ClientSession::from(responder.binding());

        // This session is established as far as we are concerned.
        self.clients.lock()?.put(session_id.clone(), responder);

        // Massage the state machine output into the response message
        let auth_response: Vec<u8> = auth_response.into();

        Ok((ClientAuthResponse::from(auth_response), session_id))
    }

    /// Close a client session
    pub fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        self.clients.lock()?.pop(&channel_id);
        Ok(())
    }

    /// Begin a peer connection
    pub fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest> {
        let local_identity = self.kex_identity.clone();
        let attestation_evidence = self.get_attestation_evidence()?;

        // Fire up the state machine.
        let mut csprng = McRng::default();
        let initiator = Start::new(peer_id.to_string());

        // Construct the initializer input.
        let node_init = {
            NodeInitiate::<X25519, Aes256Gcm, Sha512>::new(local_identity, attestation_evidence)
        };

        // Initialize
        let (initiator, msg) = initiator.try_next(&mut csprng, node_init)?;

        // Store the current state
        self.initiator_auth_pending
            .lock()?
            .put(peer_id.clone(), initiator);

        // Return the output.
        let msg_vec: Vec<u8> = msg.into();
        Ok(PeerAuthRequest::from(msg_vec))
    }

    /// Accept a peer connection
    pub fn peer_accept(&self, req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession)> {
        let local_identity = self.kex_identity.clone();
        let attestation_evidence = self.get_attestation_evidence()?;

        // Create the state machine
        let responder = Start::new(self.get_peer_self_id()?.to_string());

        // Massage the request message into state machine input
        let auth_request = {
            let req: Vec<u8> = req.into();
            NodeAuthRequestInput::<X25519, Aes256Gcm, Sha512>::new(
                AuthRequestOutput::from(req),
                local_identity,
                attestation_evidence,
                [self.trusted_identity()?],
            )
        };

        // Advance the state machine
        let mut csprng = McRng::default();
        let (responder, auth_response) = responder.try_next(&mut csprng, auth_request)?;
        let session_id = PeerSession::from(responder.binding());

        // This session is established as far as we are concerned.
        self.peer_inbound.lock()?.put(session_id.clone(), responder);

        // Massage the state machine output into the response message
        let auth_response: Vec<u8> = auth_response.into();

        Ok((PeerAuthResponse::from(auth_response), session_id))
    }

    /// Complete the connection to a peer that our accepted our PeerAuthRequest
    pub fn peer_connect(
        &self,
        peer_id: &ResponderId,
        msg: PeerAuthResponse,
    ) -> Result<(PeerSession, DcapEvidence)> {
        // Find our state machine
        let initiator = self
            .initiator_auth_pending
            .lock()?
            .pop(peer_id)
            .ok_or(Error::NotFound)?;

        let msg: Vec<u8> = msg.into();
        let auth_response_output = AuthResponseOutput::from(msg);
        let identities = [self.trusted_identity()?];
        let auth_response_input = AuthResponseInput::new(auth_response_output, identities);

        // Advance the state machine to ready (or failure)
        let mut csprng = McRng::default();
        let (initiator, attestation_evidence) =
            initiator.try_next(&mut csprng, auth_response_input)?;

        let peer_session = PeerSession::from(initiator.binding());

        self.peer_outbound
            .lock()?
            .put(peer_session.clone(), initiator);

        Ok((peer_session, attestation_evidence))
    }

    /// Close a peer connection
    pub fn peer_close(&self, session_id: &PeerSession) -> Result<()> {
        self.peer_inbound.lock()?.pop(session_id);
        self.peer_outbound.lock()?.pop(session_id);
        Ok(())
    }

    /// Check if a peer is known, return Error::NotFound if not
    pub fn is_peer_known(&self, session_id: &PeerSession) -> Result<bool> {
        match self.get_peer_map_by_session(session_id) {
            Ok(_) => Ok(true),
            Err(Error::NotFound) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Decrypt a message from a peer
    pub fn peer_decrypt(&self, msg: EnclaveMessage<PeerSession>) -> Result<Vec<u8>> {
        // Ensure lock gets released as soon as we're done decrypting.
        let mut map = self.get_peer_map_by_session(&msg.channel_id)?.lock()?;
        map.get_mut(&msg.channel_id)
            .ok_or(Error::NotFound)
            .and_then(|session| Ok(session.decrypt(&msg.aad, &msg.data)?))
    }

    /// Encrypt a message for a peer
    pub fn peer_encrypt(
        &self,
        peer: &PeerSession,
        aad: &[u8],
        data: &[u8],
    ) -> Result<EnclaveMessage<PeerSession>> {
        // Get the peer_map (inbound or outbound)
        let peer_map = self.get_peer_map_by_session(peer)?;

        // Encrypt for the peer.
        let mut peers = peer_map.lock()?;
        let session = peers.get_mut(peer).ok_or(Error::NotFound)?;
        let data = session.encrypt(aad, data)?;

        // Return message
        Ok(EnclaveMessage {
            aad: aad.to_vec(),
            channel_id: peer.clone(),
            data,
        })
    }

    /// Decrypt a message from a client
    pub fn client_decrypt(&self, msg: EnclaveMessage<ClientSession>) -> Result<Vec<u8>> {
        // Ensure lock gets released as soon as we're done decrypting.
        let mut clients = self.clients.lock()?;
        clients
            .get_mut(&msg.channel_id)
            .ok_or(Error::NotFound)
            .and_then(|session| Ok(session.decrypt(&msg.aad, &msg.data)?))
    }

    /// Encrypt a message for a client
    pub fn client_encrypt(
        &self,
        session_id: &ClientSession,
        aad: &[u8],
        data: &[u8],
    ) -> Result<EnclaveMessage<ClientSession>> {
        let mut clients = self.clients.lock()?;
        let session = clients.get_mut(session_id).ok_or(Error::NotFound)?;
        let data = session.encrypt(aad, data)?;

        // Return message
        Ok(EnclaveMessage {
            aad: aad.to_vec(),
            channel_id: session_id.clone(),
            data,
        })
    }

    /// Transforms an incoming client message, i.e. a message sent from a client
    /// to the current enclave, into a sealed message which can be decrypted
    /// later for use by this enclave without advancing the Noise nonce.
    pub fn decrypt_client_message_for_enclave(
        &self,
        incoming_client_message: EnclaveMessage<ClientSession>,
    ) -> Result<SealedClientMessage> {
        let aad = incoming_client_message.aad.clone();
        let channel_id = incoming_client_message.channel_id.clone();
        let client_query_bytes = self.client_decrypt(incoming_client_message)?;
        let sealed_client_query = PlaintextClientRequest {
            client_request_bytes: client_query_bytes,
            channel_id: channel_id.clone(),
        };
        let sealed_client_query_bytes = mc_util_serial::serialize(&sealed_client_query)?;
        let sealed_data = IntelSealed::seal_raw(&sealed_client_query_bytes, &[])?;

        Ok(SealedClientMessage {
            channel_id,
            aad,
            data: sealed_data,
        })
    }

    /// Unseals the data component of a sealed client message and returns the
    /// plaintext
    pub fn unseal(&self, sealed_message: &SealedClientMessage) -> Result<Vec<u8>> {
        let (sealed_client_request_bytes, _) = sealed_message.data.unseal_raw()?;
        let sealed_client_request: PlaintextClientRequest =
            mc_util_serial::deserialize(&sealed_client_request_bytes)?;

        Ok(sealed_client_request.client_request_bytes)
    }

    /// Transforms a sealed client message, i.e. a message sent from a client
    /// to the current enclave which has been sealed for this enclave, into a
    /// list of outbound messages for other enclaves that serve as backends to
    /// the current enclave.
    ///                              / --> Backend Enclave 1
    ///   Client -> Current Enclave ---> Backend Enclave 2
    ///                              \ --> Backend Enclave N
    pub fn reencrypt_sealed_message_for_backends(
        &self,
        sealed_client_message: &SealedClientMessage,
    ) -> Result<Vec<EnclaveMessage<NonceSession>>> {
        let client_request_bytes = self.unseal(sealed_client_message)?;
        let mut backends = self.backends.lock()?;
        let backend_messages = backends
            .iter_mut()
            .map(|(_, encryptor)| {
                let aad = sealed_client_message.aad.clone();
                let (data, nonce) = encryptor.encrypt_with_nonce(&aad, &client_request_bytes)?;
                let channel_id = NonceSession::new(encryptor.binding().into(), nonce);
                Ok(EnclaveMessage {
                    aad,
                    channel_id,
                    data,
                })
            })
            .collect::<Result<_>>()?;

        Ok(backend_messages)
    }

    pub fn backend_decrypt(
        &self,
        responder_id: &ResponderId,
        msg: &EnclaveMessage<NonceSession>,
    ) -> Result<Vec<u8>> {
        // Ensure lock gets released as soon as we're done decrypting.
        let mut backends = self.backends.lock()?;
        backends
            .get_mut(responder_id)
            .ok_or(Error::NotFound)
            .and_then(|session| {
                Ok(session.decrypt_with_nonce(&msg.aad, &msg.data, msg.channel_id.nonce())?)
            })
    }

    //
    // Quote attestation related
    //

    /// Get the cached attestation evidence if available
    pub fn get_attestation_evidence(&self) -> Result<DcapEvidence> {
        (*self.current_attestation_evidence.lock()?)
            .clone()
            .ok_or(Error::NoAttestationEvidenceAvailable)
    }

    /// Build a new Report and EnclaveReportDataContents object for ourself
    pub fn new_ereport(&self, qe_info: TargetInfo) -> Result<(Report, EnclaveReportDataContents)> {
        let mut quote_pending = self.quote_pending.lock()?;

        let quote_nonce = loop {
            let mut csprng = McRng::default();
            let quote_nonce = QuoteNonce::new(&mut csprng)?;
            if quote_pending.contains(&quote_nonce) {
                continue;
            } else {
                break quote_nonce;
            }
        };

        let report_contents = EnclaveReportDataContents::new(
            quote_nonce.clone(),
            self.get_kex_identity(),
            self.custom_identity.get_bytes_for_report(),
        );

        let mut report_data = ReportData::default();
        let report_data_bytes: &mut [u8] = report_data.as_mut();
        let identity_bytes = report_contents.sha256();
        report_data_bytes[..identity_bytes.len()].copy_from_slice(&identity_bytes);

        // Actually get the EREPORT
        let report = Report::new(Some(&qe_info), Some(&report_data))?;
        quote_pending.put(quote_nonce, report.clone());

        Ok((report, report_contents))
    }

    /// Verify an enclave's attestation evidence
    pub fn verify_attestation_evidence(&self, attestation_evidence: DcapEvidence) -> Result<()> {
        let DcapEvidence {
            quote,
            collateral,
            report_data,
        } = attestation_evidence.clone();

        let nonce = report_data.nonce();

        let mut quote_pending = self.quote_pending.lock()?;

        let report = quote_pending.pop(nonce).ok_or(Error::InvalidState)?;

        // Ensure the quote contains our report, and is sane.
        let quote_report_body = quote.app_report_body();
        let report_body = report.body();

        if &report_body != quote_report_body {
            return Err(VerifierError::Verification("Report mismatch".to_string()).into());
        }

        let verifier = self.get_verifier(report_data)?;

        // Verify signature, MRENCLAVE, report value, etc.
        let evidence = Evidence::new(quote, collateral.clone()).map_err(|e| 
            Error::Encode(format!("Failed to build the evidence {e}. The collateral was {collateral:?}."))
        )?;
        let verification = verifier.verify(&evidence);

        if verification.is_failure().into() {
            let display_tree = VerificationTreeDisplay::new(&verifier, verification);
            return Err(mc_attest_verifier::Error::Verification(display_tree.to_string()).into());
        }

        *(self.current_attestation_evidence.lock()?) = Some(attestation_evidence);
        Ok(())
    }

    //
    // Details
    //

    /// Helper: Find peer connection among either the inbound set or outbound
    /// set
    fn get_peer_map_by_session(
        &self,
        session: &PeerSession,
    ) -> Result<&Mutex<LruCache<PeerSession, Ready<Aes256Gcm>>>> {
        let map = self.peer_inbound.lock()?;
        if map.contains(session) {
            return Ok(&self.peer_inbound);
        }

        let map = self.peer_outbound.lock()?;
        if map.contains(session) {
            return Ok(&self.peer_outbound);
        }

        Err(Error::NotFound)
    }
}
