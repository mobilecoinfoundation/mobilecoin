// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
extern crate alloc;

use aes_gcm::Aes256Gcm;
use alloc::{string::ToString, vec::Vec};
use core::convert::TryFrom;
use digest::Digest;
use mc_attest_ake::{
    AuthPending, AuthRequestInput, AuthRequestOutput, AuthResponse, NodeInitiate, Ready, Start,
    Transition,
};
use mc_attest_core::{
    IasNonce, Measurement, Nonce, NonceError, Quote, QuoteNonce, Report, ReportData, TargetInfo,
    VerificationReport, VerificationReportData, VerifyError, DEBUG_ENCLAVE, IAS_VERSION,
};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, Error, PeerAuthRequest,
    PeerAuthResponse, PeerSession, Result, Session,
};
use mc_attest_trusted::EnclaveReport;
use mc_common::{LruCache, ResponderId};
use mc_crypto_keys::{X25519Private, X25519Public, X25519};
use mc_crypto_rand::McRng;
use mc_sgx_compat::sync::Mutex;
use mc_util_from_random::FromRandom;
use sha2::{Sha256, Sha512};

/// Max number of pending quotes.
const MAX_PENDING_QUOTES: usize = 64;

// Max number of auth pending requests.
const MAX_AUTH_PENDING_REQUESTS: usize = 64;

/// Max number of peer sessions.
const MAX_PEER_SESSIONS: usize = 64;

/// Max number of client sessions.
const MAX_CLIENT_SESSIONS: usize = 10000;

/// Any additional "identities" (e.g. key material) for a given enclave that needs to become
/// a part of the report. We provide some simple identities, and a trait to allow extensions
mod identity;
pub use identity::{EnclaveIdentity, NullIdentity};

/// State associated to Attested Authenticated Key Exchange held by an enclave,
/// including for peers and for clients.
/// This also includes cached IAS reports, and data that goes in those reports
pub struct AkeEnclaveState<EI: EnclaveIdentity> {
    /// ResponderId used for peer connections
    peer_self_id: Mutex<Option<ResponderId>>,
    /// ResponderId used for client connections
    client_self_id: Mutex<Option<ResponderId>>,

    /// The static identity used for key exchange, generated on startup
    /// Initialized once, read only after that, so doesn't need to be behind a mutex
    kex_identity: X25519Private,

    /// Any additional (customized) identity
    custom_identity: EI,

    /// A map of generated EREPORTs awaiting confirmation by the quoting enclave.
    quote_pending: Mutex<LruCache<QuoteNonce, Report>>,

    /// A map of generated quotes, awaiting reporting and signature by IAS.
    ias_pending: Mutex<LruCache<IasNonce, Quote>>,

    /// The cached IAS report, if any.
    current_ias_report: Mutex<Option<VerificationReport>>,

    /// A map of responder-ID to incomplete, outbound, AKE state.
    initiator_auth_pending: Mutex<LruCache<ResponderId, AuthPending<X25519, Aes256Gcm, Sha512>>>,

    /// A map of channel ID outbound connection state.
    peer_outbound: Mutex<LruCache<PeerSession, Ready<Aes256Gcm>>>,

    /// A map of channel ID to inbound connection state.
    peer_inbound: Mutex<LruCache<PeerSession, Ready<Aes256Gcm>>>,

    /// A map of channel ID to connection state
    clients: Mutex<LruCache<ClientSession, Ready<Aes256Gcm>>>,
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
            ias_pending: Mutex::new(LruCache::new(MAX_PENDING_QUOTES)),
            current_ias_report: Mutex::new(None),
            initiator_auth_pending: Mutex::new(LruCache::new(MAX_AUTH_PENDING_REQUESTS)),
            peer_outbound: Mutex::new(LruCache::new(MAX_PEER_SESSIONS)),
            peer_inbound: Mutex::new(LruCache::new(MAX_PEER_SESSIONS)),
            clients: Mutex::new(LruCache::new(MAX_CLIENT_SESSIONS)),
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

    /// Accept a client connection
    pub fn client_accept(
        &self,
        req: ClientAuthRequest,
    ) -> Result<(ClientAuthResponse, ClientSession)> {
        self.accept(self.get_client_self_id()?, &self.clients, req)
    }

    /// Close a client session
    pub fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        self.clients.lock()?.pop(&channel_id);
        Ok(())
    }

    /// Begin a peer connection
    pub fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest> {
        let local_identity = self.kex_identity.clone();
        let ias_report = self.get_ias_report()?;

        // Fire up the state machine.
        let mut csprng = McRng::default();
        // TODO: Cache expected values rather than creating a new report each time.
        let report_body = Report::new(None, None)?.body();
        let expected_measurements: [Measurement; 1] = [report_body.mr_enclave().into()];
        let initiator = Start::new(
            peer_id.to_string(),
            expected_measurements.to_vec(),
            report_body.product_id(),
            report_body.security_version(),
            DEBUG_ENCLAVE,
        );

        // Construct the initializer input.
        let node_init =
            { NodeInitiate::<X25519, Aes256Gcm, Sha512>::new(local_identity, ias_report) };

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
        self.accept(self.get_peer_self_id()?, &self.peer_inbound, req)
    }

    /// Connect to a peer that our accepted our PeerAuthRequest
    pub fn peer_connect(
        &self,
        peer_id: &ResponderId,
        msg: PeerAuthResponse,
    ) -> Result<PeerSession> {
        // Find our state machine
        let initiator = self
            .initiator_auth_pending
            .lock()?
            .pop(peer_id)
            .ok_or(Error::NotFound)?;

        let msg: Vec<u8> = msg.into();
        let auth_response_event = AuthResponse::from(msg);

        // Advance the state machine to ready (or failure)
        let mut csprng = McRng::default();
        let (initiator, _) = initiator.try_next(&mut csprng, auth_response_event)?;

        let retval = PeerSession::from(initiator.binding());

        self.peer_outbound.lock()?.put(retval.clone(), initiator);

        Ok(retval)
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
        let data = session.encrypt(aad, &data)?;

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

    //
    // IAS related
    //

    /// Get the cached IAS report if available
    pub fn get_ias_report(&self) -> Result<VerificationReport> {
        (*self.current_ias_report.lock()?)
            .clone()
            .ok_or(Error::NoReportAvailable)
    }

    /// Build a new Report and QuoteNonce object for ourself
    pub fn new_ereport(&self, qe_info: TargetInfo) -> Result<(Report, QuoteNonce)> {
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

        // Copy the public key into the report data.
        let mut report_data = ReportData::default();
        let report_data_bytes: &mut [u8] = report_data.as_mut();
        let identity = self.get_kex_identity();
        let identity_bytes: &[u8] = identity.as_ref();
        let custom_identity_bytes = self.custom_identity.get_bytes_for_report();
        report_data_bytes[..identity_bytes.len()].copy_from_slice(identity_bytes);
        report_data_bytes[identity_bytes.len()..].copy_from_slice(custom_identity_bytes.as_ref());

        // Actually get the EREPORT
        let report = Report::new(Some(&qe_info), Some(&report_data))?;
        quote_pending.put(quote_nonce, report);

        Ok((report, quote_nonce))
    }

    /// Verify a quote
    pub fn verify_quote(&self, quote: Quote, qe_report: Report) -> Result<IasNonce> {
        // Is the qe_report for our enclave?
        qe_report.verify()?;

        // The qe_report contains SHA256(quote || quote_nonce) as the lower
        // 32 bytes of the report data.
        //
        // Unfortunately, this means we cannot do anything but hash each
        // potential in-flight quote with each nonce in our state cache.
        let qe_report_data = qe_report.body().report_data();
        let qe_report_bytes: &[u8] = qe_report_data.as_ref();

        let mut target_nonce: Option<QuoteNonce> = None;
        let mut hasher = Sha256::new();

        let mut quote_pending = self.quote_pending.lock()?;

        // We iterate each nonce in our cache, and save the key of the one
        // we want to work on
        for (nonce, _) in quote_pending.iter() {
            hasher.input(<QuoteNonce as AsRef<[u8]>>::as_ref(nonce));
            hasher.input(quote.as_ref());
            let output_arr = hasher.result_reset();
            let output = output_arr.as_slice();
            debug_assert!(output.len() < qe_report_bytes.len());
            if output == &qe_report_bytes[..output.len()] {
                target_nonce = Some(*nonce);
                break;
            }
        }

        // If we found a matching entry in our cache, then we remove the
        // old state from the phase-one cache, upgrade it to the IasPending
        // state object, and insert it into the IAS pending cache. If the
        // upgrade fails, it's because the quote and qe_report don't match,
        // in which case we should simply abort the attempt because there's
        // nothing we can do to fix it, and leaving it around is probably
        // wrong.
        if let Some(target_nonce) = target_nonce {
            let mut ias_pending = self.ias_pending.lock()?;
            let mut csprng = McRng::default();
            // this should never fail...
            if let Some(report) = quote_pending.pop(&target_nonce) {
                let ias_nonce = loop {
                    let ias_nonce = IasNonce::new(&mut csprng)?;
                    if !ias_pending.contains(&ias_nonce) {
                        break ias_nonce;
                    }
                };
                // Ensure the quote contains our report, and is sane.
                quote.verify_report(&qe_report, &report)?;
                ias_pending.put(ias_nonce.clone(), quote);
                return Ok(ias_nonce);
            }
        }

        Err(Error::InvalidState)
    }

    /// Verify an ias report
    pub fn verify_ias_report(&self, ias_report: VerificationReport) -> Result<()> {
        // Check report signature first
        ias_report.verify_signature(None)?;

        // Parse the data, extract the nonce
        let ias_data = VerificationReportData::try_from(&ias_report)?;
        let nonce = ias_data
            .nonce
            .as_ref()
            .ok_or(Error::Verify(VerifyError::Nonce(NonceError::Missing)))?;

        // Find the quote we cached earlier, if any
        let cached_quote = self
            .ias_pending
            .lock()?
            .pop(nonce)
            .ok_or(Error::InvalidState)?;

        // Double-check that what we cached matches what IAS signed
        if !cached_quote.contents_eq(&ias_data.quote) {
            return Err(Error::Verify(VerifyError::IasQuoteMismatch));
        }

        // Verify the report data.
        ias_data.verify_data(IAS_VERSION, Some(nonce), None)?;

        // Save the result
        *(self.current_ias_report.lock()?) = Some(ias_report);
        Ok(())
    }

    //
    // Details
    //

    /// Helper: Find peer connection among either the inbound set or outbound set
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

    /// Helper: Accept a session, which might be either a peer or client session
    fn accept<S: Session>(
        &self,
        self_id: ResponderId,
        session_db: &Mutex<LruCache<S, Ready<Aes256Gcm>>>,
        req: S::Request,
    ) -> Result<(S::Response, S)>
    where
        Start: Transition<
            Ready<Aes256Gcm>,
            AuthRequestInput<S::Handshake, X25519, Aes256Gcm, Sha512>,
            AuthResponse,
        >,
        Error: From<
            <Start as Transition<
                Ready<Aes256Gcm>,
                AuthRequestInput<S::Handshake, X25519, Aes256Gcm, Sha512>,
                AuthResponse,
            >>::Error,
        >,
    {
        let local_identity = self.kex_identity.clone();
        let ias_report = self.get_ias_report()?;

        // Create the state machine
        let mut csprng = McRng::default();
        // TODO: Cache expected values rather than creating a new report each time.
        let report_body = Report::new(None, None)?.body();
        let expected_measurements: [Measurement; 1] = [report_body.mr_enclave().into()];
        let responder = Start::new(
            self_id.to_string(),
            expected_measurements.to_vec(),
            report_body.product_id(),
            report_body.security_version(),
            DEBUG_ENCLAVE,
        );

        // Massage our input into the state machine input
        let auth_request = {
            let req: Vec<u8> = req.into();
            AuthRequestInput::<S::Handshake, X25519, Aes256Gcm, Sha512>::new(
                AuthRequestOutput::from(req),
                local_identity,
                ias_report,
            )
        };

        let (responder, auth_response) = responder.try_next(&mut csprng, auth_request)?;
        let session_id = S::from(responder.binding());
        // This session is established as far as we are concerned.
        session_db.lock()?.put(session_id.clone(), responder);

        let auth_response: Vec<u8> = auth_response.into();
        Ok((S::Response::from(auth_response), session_id))
    }
}
