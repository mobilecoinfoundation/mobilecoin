// Copyright (c) 2018-2022 The MobileCoin Foundation

//! JNI wrappers for our various objects.

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

use crate::{
    error::McError,
    ffi::{jni_big_int_to_u64, jni_ffi_call, jni_ffi_call_or, RUST_OBJ_FIELD},
};
use aes_gcm::Aes256Gcm;
use bip39::{Language, Mnemonic};
use generic_array::{typenum::U66, GenericArray};
use jni::{
    objects::{JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobject, jobjectArray, jshort, jstring, JNI_FALSE},
    JNIEnv,
};
use mc_account_keys::{
    AccountKey, PublicAddress, RootEntropy, RootIdentity, ShortAddressHash,
    CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX, INVALID_SUBADDRESS_INDEX,
};
use mc_account_keys_slip10::Slip10KeyGenerator;
use mc_api::printable::PrintableWrapper;
use mc_attest_ake::{
    AuthPending, AuthResponseInput, AuthResponseOutput, ClientInitiate, Ready, Start, Transition,
};
use mc_attest_core::{
    MrEnclave, MrSigner, ReportData, VerificationReport, VerificationReportData,
    VerificationSignature,
};
use mc_attest_verifier::{MrEnclaveVerifier, MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_common::ResponderId;
use mc_crypto_box::{CryptoBox, VersionedCryptoBox};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic, X25519};
use mc_crypto_rand::McRng;
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_kex_rng::{BufferedRng, KexRngPubkey, NewFromKex, StoredRng, VersionedKexRng};
use mc_fog_report_types::{Report, ReportResponse};
use mc_fog_report_validation::{FogReportResponses, FogResolver};
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::{
        create_shared_secret, recover_onetime_private_key, recover_public_subaddress_spend_key,
    },
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{Tx, TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
    Amount, BlockVersion, CompressedCommitment, MaskedAmount, Token,
};
use mc_transaction_std::{
    AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, DestinationMemo,
    GiftCodeCancellationMemo, GiftCodeCancellationMemoBuilder, GiftCodeFundingMemo,
    GiftCodeFundingMemoBuilder, GiftCodeSenderMemo, GiftCodeSenderMemoBuilder, InputCredentials,
    MemoBuilder, MemoPayload, RTHMemoBuilder, ReservedSubaddresses, SenderMemoCredential,
    TransactionBuilder,
};

use mc_util_from_random::FromRandom;
use mc_util_uri::FogUri;
use protobuf::Message;
use rand::{rngs::StdRng, SeedableRng};
use sha2::Sha512;
use std::{
    collections::BTreeMap,
    ops::DerefMut,
    str::FromStr,
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroize;

/****************************************************************
 * RistrettoPrivate
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPrivate_init_1jni(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let key_bytes = env.convert_byte_array(bytes)?;
        let key = RistrettoPrivate::try_from(&key_bytes[..])?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, key)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPrivate_init_1jni_1seed(
    env: JNIEnv,
    obj: JObject,
    seed: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let seed_bytes = env.convert_byte_array(seed)?;
        let seed_bytes32 = <[u8; 32]>::try_from(&seed_bytes[..])?;
        let mut rng: StdRng = SeedableRng::from_seed(seed_bytes32);
        let key = RistrettoPrivate::from_random(&mut rng);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, key)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPrivate_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, RistrettoPrivate>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPrivate_get_1bytes(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let pkey: MutexGuard<RistrettoPrivate> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            Ok(env.byte_array_from_slice(&pkey.to_bytes())?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPrivate_get_1public(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let private_key: MutexGuard<RistrettoPrivate> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let public_key = RistrettoPublic::from(&*private_key);
            let mbox = Box::new(Mutex::new(public_key));
            let ptr: *mut Mutex<RistrettoPublic> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

/****************************************************************
 * AttestedClient
 */

enum AttestedClientState {
    Pending(AuthPending<X25519, Aes256Gcm, Sha512>),
    Ready(Ready<Aes256Gcm>),
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AttestedClient_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: AttestedClientState = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AttestedClient_attest_1start(
    env: JNIEnv,
    obj: JObject,
    responder_id: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let responder_id: MutexGuard<ResponderId> =
                env.get_rust_field(responder_id, RUST_OBJ_FIELD)?;
            let mut csprng = McRng::default();

            let start = Start::new(responder_id.to_string());
            let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
            let (auth_pending, auth_request_output) = start.try_next(&mut csprng, init_input)?;

            env.set_rust_field(
                obj,
                RUST_OBJ_FIELD,
                AttestedClientState::Pending(auth_pending),
            )?;
            Ok(env.byte_array_from_slice(auth_request_output.as_ref())?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AttestedClient_get_1binding(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let state: MutexGuard<AttestedClientState> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let binding = match &*state {
                AttestedClientState::Pending(_) => Err(McError::Other("Not ready".to_owned())),
                AttestedClientState::Ready(ready) => Ok(ready.binding()),
            }?;

            Ok(env.byte_array_from_slice(binding)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AttestedClient_attest_1finish(
    env: JNIEnv,
    obj: JObject,
    auth_response: jbyteArray,
    verifier: JObject,
) {
    jni_ffi_call(&env, |env| {
        let mut csprng = McRng::default();
        let state: AttestedClientState = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        let auth_response_msg = {
            let rust_bytes = env.convert_byte_array(auth_response)?;
            AuthResponseOutput::from(rust_bytes)
        };

        let verifier: MutexGuard<Verifier> = env.get_rust_field(verifier, RUST_OBJ_FIELD)?;
        match state {
            AttestedClientState::Pending(pending) => {
                let auth_response_input =
                    AuthResponseInput::new(auth_response_msg, verifier.clone());
                let (ready, _) = pending.try_next(&mut csprng, auth_response_input)?;
                Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, AttestedClientState::Ready(ready))?)
            }

            AttestedClientState::Ready(ready) => {
                env.set_rust_field(obj, RUST_OBJ_FIELD, AttestedClientState::Ready(ready))?;
                Err(McError::Other("Already ready".to_owned()))
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AttestedClient_encrypt_1payload(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
    aad: jbyteArray,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let mut state: MutexGuard<AttestedClientState> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let payload = env.convert_byte_array(bytes)?;
            let aad = env.convert_byte_array(aad)?;

            match state.deref_mut() {
                AttestedClientState::Pending(_) => Err(McError::Other("Not ready".to_owned())),
                AttestedClientState::Ready(ref mut ready) => {
                    let encrypted = ready.encrypt(&aad, &payload)?;
                    Ok(env.byte_array_from_slice(&encrypted)?)
                }
            }
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AttestedClient_decrypt_1payload(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
    aad: jbyteArray,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let mut state: MutexGuard<AttestedClientState> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let payload = env.convert_byte_array(bytes)?;
            let aad = env.convert_byte_array(aad)?;

            match state.deref_mut() {
                AttestedClientState::Pending(_) => Err(McError::Other("Not ready".to_owned())),
                AttestedClientState::Ready(ref mut ready) => {
                    let decrypted = ready.decrypt(&aad, &payload)?;

                    Ok(env.byte_array_from_slice(&decrypted)?)
                }
            }
        },
    )
}

/*****************************************************************
 * Amount
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Amount_init_1jni(
    env: JNIEnv,
    obj: JObject,
    commitment: jbyteArray,
    masked_value: jlong,
) {
    jni_ffi_call(&env, |env| {
        let commitment_bytes = env.convert_byte_array(commitment)?;

        // FIXME #1595: We should get a masked token id also, here we default to
        // 0 bytes, which is backwards compatible
        let masked_amount = MaskedAmount {
            commitment: CompressedCommitment::try_from(&commitment_bytes[..])?,
            masked_value: masked_value as u64,
            masked_token_id: Default::default(),
        };
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, masked_amount)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Amount_init_1jni_1with_1secret(
    env: JNIEnv,
    obj: JObject,
    tx_out_shared_secret: JObject,
    masked_value: jlong,
) {
    jni_ffi_call(&env, |env| {
        let tx_out_shared_secret: MutexGuard<RistrettoPublic> =
            env.get_rust_field(tx_out_shared_secret, RUST_OBJ_FIELD)?;
        // FIXME #1595: the masked token id should be 0 or 4 bytes.
        // To avoid breaking changes, it is hard coded to 0 bytes here
        let masked_amount =
            MaskedAmount::reconstruct(masked_value as u64, &[], &tx_out_shared_secret)?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, masked_amount)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Amount_get_1bytes(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let amount_key: MutexGuard<MaskedAmount> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let bytes = mc_util_serial::encode(&*amount_key);
            Ok(env.byte_array_from_slice(&bytes)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Amount_finalize_1jni(env: JNIEnv, obj: JObject) {
    jni_ffi_call(&env, |env| {
        let _: MaskedAmount = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Amount_unmask_1value(
    env: JNIEnv,
    obj: JObject,
    view_key: JObject,
    tx_pub_key: JObject,
) -> jobject {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let masked_amount: MutexGuard<MaskedAmount> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let view_key: MutexGuard<RistrettoPrivate> =
                env.get_rust_field(view_key, RUST_OBJ_FIELD)?;
            let tx_pub_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_pub_key, RUST_OBJ_FIELD)?;
            let shared_secret = create_shared_secret(&tx_pub_key, &view_key);
            let (amount, _) = masked_amount.get_value(&shared_secret)?;
            Ok(env
                .new_object(
                    "java/math/BigInteger",
                    "(I[B)V", // public BigInteger(int signum, byte[] magnitude)
                    &[
                        1.into(),
                        env.byte_array_from_slice(&amount.value.to_be_bytes())?
                            .into(),
                    ],
                )?
                .into_inner())
        },
    )
}

/******************************************************************
 * RistrettoPublic
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPublic_init_1jni(
    env: JNIEnv,
    obj: JObject,
    raw_key_bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let key_bytes = env.convert_byte_array(raw_key_bytes)?;
        let pub_key = RistrettoPublic::try_from(&key_bytes[..])?;
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, pub_key)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPublic_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: RistrettoPublic = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_RistrettoPublic_get_1bytes(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let pkey: MutexGuard<RistrettoPublic> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            Ok(env.byte_array_from_slice(&pkey.to_bytes())?)
        },
    )
}

/*******************************************************************
 * PrintableWrapper
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PrintableWrapper_b58_1decode(
    env: JNIEnv,
    _obj: JObject,
    b58_string: JString,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let b58_string: String = env.get_string(b58_string)?.into();
            let printable_wrapper = PrintableWrapper::b58_decode(b58_string)
                .map_err(|err| McError::Other(format!("{}", err)))?;
            let wrapper_bytes = printable_wrapper
                .write_to_bytes()
                .map_err(|err| McError::Other(format!("{}", err)))?;
            Ok(env.byte_array_from_slice(&wrapper_bytes)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PrintableWrapper_b58_1encode(
    env: JNIEnv,
    _obj: JObject,
    wrapper_bytes: jbyteArray,
) -> jstring {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let wrapper_bytes = env.convert_byte_array(wrapper_bytes)?;
            let printable_wrapper = PrintableWrapper::parse_from_bytes(&wrapper_bytes)
                .map_err(|err| McError::Other(format!("{}", err)))?;
            let b58_string = printable_wrapper
                .b58_encode()
                .map_err(|err| McError::Other(format!("{}", err)))?;
            Ok(env.new_string(b58_string)?.into_inner())
        },
    )
}

/********************************************************************
 * PublicAddress
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_get_1view_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let address: MutexGuard<PublicAddress> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let mbox = Box::new(Mutex::new(*address.view_public_key()));
            let ptr: *mut Mutex<RistrettoPublic> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_get_1fog_1authority_1sig(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let address: MutexGuard<PublicAddress> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            match address.fog_authority_sig() {
                None => Ok(JObject::null().into_inner()),
                Some(out) => Ok(env.byte_array_from_slice(out)?),
            }
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_get_1report_1id(
    env: JNIEnv,
    obj: JObject,
) -> jstring {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let address: MutexGuard<PublicAddress> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            match address.fog_report_id() {
                None => Ok(JObject::null().into_inner()),
                Some(out) => Ok(env.new_string(out)?.into_inner()),
            }
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_get_1spend_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let address: MutexGuard<PublicAddress> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let mbox = Box::new(Mutex::new(*address.spend_public_key()));
            let ptr: *mut Mutex<RistrettoPublic> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_get_1fog_1uri(
    env: JNIEnv,
    obj: JObject,
) -> jstring {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let address: MutexGuard<PublicAddress> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            match address.fog_report_url() {
                None => Ok(JObject::null().into_inner()),
                Some(out) => Ok(env.new_string(out)?.into_inner()),
            }
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_init_1jni_1with_1fog(
    env: JNIEnv,
    obj: JObject,
    view_key: JObject,
    spend_key: JObject,
    fog_report_url: JString,
    fog_authority_sig: jbyteArray,
    fog_report_id: JString,
) {
    jni_ffi_call(&env, |env| {
        let view_public_key: MutexGuard<RistrettoPublic> =
            env.get_rust_field(view_key, RUST_OBJ_FIELD)?;
        let spend_public_key: MutexGuard<RistrettoPublic> =
            env.get_rust_field(spend_key, RUST_OBJ_FIELD)?;
        let fog_report_url: String = env.get_string(fog_report_url)?.into();
        let fog_authority_sig = env.convert_byte_array(fog_authority_sig)?;
        let fog_report_id: String = env.get_string(fog_report_id)?.into();
        let public_address = PublicAddress::new_with_fog(
            &spend_public_key,
            &view_public_key,
            fog_report_url,
            fog_report_id,
            fog_authority_sig,
        );
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, public_address)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_init_1jni(
    env: JNIEnv,
    obj: JObject,
    view_key: JObject,
    spend_key: JObject,
) {
    jni_ffi_call(&env, |env| {
        let view_public_key: MutexGuard<RistrettoPublic> =
            env.get_rust_field(view_key, RUST_OBJ_FIELD)?;
        let spend_public_key: MutexGuard<RistrettoPublic> =
            env.get_rust_field(spend_key, RUST_OBJ_FIELD)?;
        let public_address = PublicAddress::new(&spend_public_key, &view_public_key);
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, public_address)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_PublicAddress_calculate_1address_1hash_1data(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let public_address: MutexGuard<PublicAddress> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let short_address_hash: ShortAddressHash = ShortAddressHash::from(&*public_address);
            let hash_data: [u8; 16] = short_address_hash.into();

            Ok(env.byte_array_from_slice(&hash_data)?)
        },
    )
}

/********************************************************************
 * ClientKexRng
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_init_1jni(
    env: JNIEnv,
    obj: JObject,
    view_key: JObject,
    pubkey: jbyteArray,
    version: jint,
) {
    jni_ffi_call(&env, |env| {
        let view_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(view_key, RUST_OBJ_FIELD)?;

        let pubkey_bytes = env.convert_byte_array(pubkey)?;

        let assembled_pubkey = KexRngPubkey {
            public_key: pubkey_bytes,
            version: version as u32,
        };

        let kexrng = VersionedKexRng::try_from_kex_pubkey(&assembled_pubkey, &view_key)?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, kexrng)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_init_1from_1stored_1rng_1protobuf_1bytes(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let protobuf_bytes = env.convert_byte_array(bytes)?;
        let stored_rng: StoredRng = mc_util_serial::decode(&protobuf_bytes)?;

        let versioned_kex_rng: VersionedKexRng = VersionedKexRng::try_from(stored_rng)?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, versioned_kex_rng)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_get_1stored_1rng_1protobuf_1bytes(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let versioned_kex_rng: MutexGuard<VersionedKexRng> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let stored_rng: StoredRng = versioned_kex_rng.clone().into();
            let bytes = mc_util_serial::encode(&stored_rng);

            Ok(env.byte_array_from_slice(&bytes)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_rng_1advance(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let mut kexrng: MutexGuard<VersionedKexRng> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
        kexrng.advance();
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_get_1output(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let kexrng: MutexGuard<VersionedKexRng> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            Ok(env.byte_array_from_slice(kexrng.peek())?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_get_1next_1n(
    env: JNIEnv,
    obj: JObject,
    n: jlong,
) -> jobjectArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let kexrng: MutexGuard<VersionedKexRng> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let next_vals: Vec<_> = kexrng.clone().take(n as usize).collect();

            // Create a byte[][] array
            let arr = env.new_object_array(
                next_vals.len() as i32,
                "[B",
                env.byte_array_from_slice(&[])?,
            )?;
            for (i, val) in next_vals.iter().enumerate() {
                env.set_object_array_element(arr, i as i32, env.byte_array_from_slice(val)?)?;
            }

            Ok(arr)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ClientKexRng_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: VersionedKexRng = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * Account
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_init_1jni(
    env: JNIEnv,
    obj: JObject,
    view_key: JObject,
    spend_key: JObject,
    fog_report_url: JString,
    fog_authority_spki: jbyteArray,
    fog_report_id: JString,
) {
    jni_ffi_call(&env, |env| {
        let view_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(view_key, RUST_OBJ_FIELD)?;
        let spend_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(spend_key, RUST_OBJ_FIELD)?;
        let fog_report_url: String = env.get_string(fog_report_url)?.into();
        let fog_authority_spki = env.convert_byte_array(fog_authority_spki)?;
        let fog_report_id: String = env.get_string(fog_report_id)?.into();

        let account_key = AccountKey::new_with_fog(
            &spend_key,
            &view_key,
            fog_report_url,
            fog_report_id,
            fog_authority_spki,
        );

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, account_key)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_init_1jni_1non_1fog(
    env: JNIEnv,
    obj: JObject,
    view_key: JObject,
    spend_key: JObject,
) {
    jni_ffi_call(&env, |env| {
        let view_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(view_key, RUST_OBJ_FIELD)?;
        let spend_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(spend_key, RUST_OBJ_FIELD)?;

        let account_key = AccountKey::new(&spend_key, &view_key);
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, account_key)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_init_1jni_1from_1root_1entropy(
    env: JNIEnv,
    obj: JObject,
    root_entropy: jbyteArray,
    fqdn: JString,
    fog_authority_spki: jbyteArray,
    fog_report_id: JString,
) {
    jni_ffi_call(&env, |env| {
        let root_entropy = <[u8; 32]>::try_from(&env.convert_byte_array(root_entropy)?[..])?;
        let fqdn: String = env.get_string(fqdn)?.into();

        let fog_url = if fqdn.is_empty() { None } else { Some(fqdn) };

        let fog_authority_spki = env.convert_byte_array(fog_authority_spki)?;
        let fog_report_id: String = env.get_string(fog_report_id)?.into();

        let root_identity = RootIdentity {
            root_entropy: RootEntropy::from(&root_entropy),
            fog_report_url: fog_url.unwrap_or_default(),
            fog_report_id,
            fog_authority_spki,
        };

        let account_key = AccountKey::from(&root_identity);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, account_key)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1default_1subaddress_1spend_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let spend_key = account_key.default_subaddress_spend_private();

            let mbox = Box::new(Mutex::new(spend_key));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1default_1subaddress_1view_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let view_key = account_key.default_subaddress_view_private();

            let mbox = Box::new(Mutex::new(view_key));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1change_1subaddress_1spend_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let spend_key = account_key.change_subaddress_spend_private();

            let mbox = Box::new(Mutex::new(spend_key));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1change_1subaddress_1view_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let view_key = account_key.change_subaddress_view_private();

            let mbox = Box::new(Mutex::new(view_key));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: AccountKey = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1view_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let mbox = Box::new(Mutex::new(*account_key.view_private_key()));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1spend_1key(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let mbox = Box::new(Mutex::new(*account_key.spend_private_key()));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_getFogUriString(
    env: JNIEnv,
    obj: JObject,
) -> jobject {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(env
                .new_string(account_key.fog_report_url().unwrap_or(""))?
                .into_inner())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1fog_1authority_1spki(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            match account_key.fog_authority_spki() {
                None => Ok(JObject::null().into_inner()),
                Some(out) => Ok(env.byte_array_from_slice(out)?),
            }
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1report_1id(
    env: JNIEnv,
    obj: JObject,
) -> jstring {
    jni_ffi_call_or(
        || Ok(env.new_string("")?.into_inner()),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(env
                .new_string(account_key.fog_report_id().unwrap_or(""))?
                .into_inner())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKey_get_1public_1address(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let mbox = Box::new(Mutex::new(account_key.default_subaddress()));
            let ptr: *mut Mutex<PublicAddress> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

/********************************************************************
 * AuthenticatedSenderMemo
 */
#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderMemo_init_1jni_1from_1memo_1data(
    env: JNIEnv,
    obj: JObject,
    memo_data: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        let authenticated_sender_memo: AuthenticatedSenderMemo =
            AuthenticatedSenderMemo::from(&memo_data);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, authenticated_sender_memo)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderMemo_is_1valid(
    env: JNIEnv,
    obj: JObject,
    sender_public_address: JObject,
    receiving_subaddress_view_private_key: JObject,
    tx_out_public_key: JObject,
) -> jboolean {
    jni_ffi_call_or(
        || Ok(JNI_FALSE),
        &env,
        |env| {
            let authenticated_sender_memo: MutexGuard<AuthenticatedSenderMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let sender_public_address: MutexGuard<PublicAddress> =
                env.get_rust_field(sender_public_address, RUST_OBJ_FIELD)?;
            let receiving_subaddress_view_private_key: MutexGuard<RistrettoPrivate> =
                env.get_rust_field(receiving_subaddress_view_private_key, RUST_OBJ_FIELD)?;
            let tx_out_public_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_out_public_key, RUST_OBJ_FIELD)?;

            let tx_out_public_key_compressed = CompressedRistrettoPublic::from(&*tx_out_public_key);

            let is_memo_valid = authenticated_sender_memo
                .validate(
                    &*sender_public_address,
                    &*receiving_subaddress_view_private_key,
                    &tx_out_public_key_compressed,
                )
                .unwrap_u8();

            Ok(is_memo_valid)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderMemo_get_1address_1hash_1data(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let authenticated_sender_memo: MutexGuard<AuthenticatedSenderMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let short_address_hash: ShortAddressHash =
                authenticated_sender_memo.sender_address_hash();
            let hash_data: [u8; 16] = short_address_hash.into();
            Ok(env.byte_array_from_slice(&hash_data)?)
        },
    )
}

/********************************************************************
 * SenderWithPaymentRequestMemo
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderWithPaymentRequestMemo_init_1jni_1from_1memo_1data(
    env: JNIEnv,
    obj: JObject,
    memo_data: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        let authenticated_sender_with_payment_request_id_memo: AuthenticatedSenderWithPaymentRequestIdMemo =
            AuthenticatedSenderWithPaymentRequestIdMemo::from(&memo_data);

        Ok(env.set_rust_field(
            obj,
            RUST_OBJ_FIELD,
            authenticated_sender_with_payment_request_id_memo,
        )?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderWithPaymentRequestMemo_is_1valid(
    env: JNIEnv,
    obj: JObject,
    sender_public_addresss: JObject,
    receiving_subaddress_view_private_key: JObject,
    tx_out_public_key: JObject,
) -> jboolean {
    jni_ffi_call_or(
        || Ok(JNI_FALSE),
        &env,
        |env| {
            let authenticated_sender_with_payment_request_id_memo: MutexGuard<
                AuthenticatedSenderWithPaymentRequestIdMemo,
            > = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let sender_public_address: MutexGuard<PublicAddress> =
                env.get_rust_field(sender_public_addresss, RUST_OBJ_FIELD)?;
            let receiving_subaddress_view_private_key: MutexGuard<RistrettoPrivate> =
                env.get_rust_field(receiving_subaddress_view_private_key, RUST_OBJ_FIELD)?;
            let tx_out_public_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_out_public_key, RUST_OBJ_FIELD)?;

            let tx_out_public_key_compressed = CompressedRistrettoPublic::from(&*tx_out_public_key);

            Ok(authenticated_sender_with_payment_request_id_memo
                .validate(
                    &*sender_public_address,
                    &*receiving_subaddress_view_private_key,
                    &tx_out_public_key_compressed,
                )
                .unwrap_u8())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderWithPaymentRequestMemo_get_1address_1hash_1data(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let authenticated_sender_with_payment_request_id_memo: MutexGuard<
                AuthenticatedSenderWithPaymentRequestIdMemo,
            > = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let short_address_hash: ShortAddressHash =
                authenticated_sender_with_payment_request_id_memo.sender_address_hash();
            let hash_data: [u8; 16] = short_address_hash.into();
            Ok(env.byte_array_from_slice(&hash_data)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_SenderWithPaymentRequestMemo_get_1payment_1request_1id(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let authenticated_sender_with_payment_request_id_memo: MutexGuard<
                AuthenticatedSenderWithPaymentRequestIdMemo,
            > = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(authenticated_sender_with_payment_request_id_memo.payment_request_id() as jlong)
        },
    )
}

/********************************************************************
 * DestinationMemo
 */
#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_init_1jni_1from_1memo_1data(
    env: JNIEnv,
    obj: JObject,
    memo_data: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        let destination_memo: DestinationMemo = DestinationMemo::from(&memo_data);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, destination_memo)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_is_1valid(
    env: JNIEnv,
    _obj: JObject,
    account_key: JObject,
    tx_out: JObject,
) -> jboolean {
    jni_ffi_call_or(
        || Ok(JNI_FALSE),
        &env,
        |env| {
            let account_key: MutexGuard<AccountKey> =
                env.get_rust_field(account_key, RUST_OBJ_FIELD)?;
            let tx_out: MutexGuard<TxOut> = env.get_rust_field(tx_out, RUST_OBJ_FIELD)?;

            Ok(mc_transaction_core::subaddress_matches_tx_out(
                &*account_key,
                CHANGE_SUBADDRESS_INDEX,
                &*tx_out,
            )? as u8)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1address_1hash_1data(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let destination_memo: MutexGuard<DestinationMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let short_address_hash: &ShortAddressHash = destination_memo.get_address_hash();
            let hash_data: [u8; 16] = <[u8; 16]>::from(short_address_hash.clone());
            Ok(env.byte_array_from_slice(&hash_data)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1number_1of_1recipients(
    env: JNIEnv,
    obj: JObject,
) -> jshort {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let destination_memo: MutexGuard<DestinationMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            // number_of_recipients is a u8 and jshort is an i16. This is fine
            // because number_of_recipients will never be negative.
            Ok(destination_memo.get_num_recipients() as jshort)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1fee(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let destination_memo: MutexGuard<DestinationMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(destination_memo.get_fee() as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DestinationMemo_get_1total_1outlay(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let destination_memo: MutexGuard<DestinationMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(destination_memo.get_total_outlay() as jlong)
        },
    )
}

/********************************************************************
 * GiftCodeFundingMemo
 */
#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeFundingMemo_init_1jni_1from_1memo_1data(
    env: JNIEnv,
    obj: JObject,
    memo_data: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        let memo: GiftCodeFundingMemo = GiftCodeFundingMemo::from(&memo_data);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeFundingMemo_validate_1gift_1code_1funding_1tx_1out(
    env: JNIEnv,
    obj: JObject,
    tx_out_public_key: JObject,
) -> jboolean {
    jni_ffi_call_or(
        || Ok(JNI_FALSE),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeFundingMemo> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_out_public_key, RUST_OBJ_FIELD)?;

            let key_matches = memo.public_key_matches(&key);

            Ok(key_matches as u8)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeFundingMemo_get_1note(
    env: JNIEnv,
    obj: JObject,
) -> jstring {
    jni_ffi_call_or(
        || Ok(env.new_string("")?.into_inner()),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeFundingMemo> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let funding_note = memo.funding_note()?;

            Ok(env.new_string(funding_note)?.into_inner())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeFundingMemo_get_1fee(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeFundingMemo> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(memo.get_fee() as jlong)
        },
    )
}

/********************************************************************
 * GiftCodeSenderMemo
 */
#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeSenderMemo_init_1jni_1from_1memo_1data(
    env: JNIEnv,
    obj: JObject,
    memo_data: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        let memo: GiftCodeSenderMemo = GiftCodeSenderMemo::from(&memo_data);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeSenderMemo_get_1note(
    env: JNIEnv,
    obj: JObject,
) -> jstring {
    jni_ffi_call_or(
        || Ok(env.new_string("")?.into_inner()),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeSenderMemo> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let sender_note = memo.sender_note()?;

            Ok(env.new_string(sender_note)?.into_inner())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeSenderMemo_get_1fee(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeSenderMemo> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(memo.get_fee() as jlong)
        },
    )
}

/********************************************************************
 * GiftCodeCancellationMemo
 */
#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeCancellationMemo_init_1jni_1from_1memo_1data(
    env: JNIEnv,
    obj: JObject,
    memo_data: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let memo_data = <[u8; 64]>::try_from(&env.convert_byte_array(memo_data)?[..])?;
        let memo: GiftCodeCancellationMemo = GiftCodeCancellationMemo::from(&memo_data);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeCancellationMemo_get_1global_1index(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeCancellationMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(memo.cancelled_gift_code_index() as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeCancellationMemo_get_1fee(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let memo: MutexGuard<GiftCodeCancellationMemo> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            Ok(memo.get_fee() as jlong)
        },
    )
}

/********************************************************************
 * TxOut
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOut_init_1from_1protobuf_1bytes(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let protobuf_bytes = env.convert_byte_array(bytes)?;
        let tx_out: TxOut = mc_util_serial::decode(&protobuf_bytes)?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, tx_out)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOut_finalize_1jni(env: JNIEnv, obj: JObject) {
    jni_ffi_call(&env, |env| {
        let _: TxOut = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOut_compute_1key_1image(
    env: JNIEnv,
    obj: JObject,
    account_key: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let tx_out: MutexGuard<TxOut> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let account_key: MutexGuard<AccountKey> =
                env.get_rust_field(account_key, RUST_OBJ_FIELD)?;
            let tx_pub_key = RistrettoPublic::try_from(&tx_out.public_key)?;
            let tx_out_target_key = RistrettoPublic::try_from(&tx_out.target_key)?;

            let subaddress_spk = recover_public_subaddress_spend_key(
                account_key.view_private_key(),
                &tx_out_target_key,
                &tx_pub_key,
            );
            let spsk_to_index: BTreeMap<RistrettoPublic, u64> = (0..=DEFAULT_SUBADDRESS_INDEX)
                .chain(CHANGE_SUBADDRESS_INDEX..INVALID_SUBADDRESS_INDEX)
                .map(|index| (*account_key.subaddress(index).spend_public_key(), index))
                .collect();
            let subaddress_index = spsk_to_index
                .get(&subaddress_spk)
                .ok_or_else(|| McError::Other("Subaddress match error".to_owned()))?;

            let onetime_private_key = recover_onetime_private_key(
                &tx_pub_key,
                account_key.view_private_key(),
                &account_key.subaddress_spend_private(*subaddress_index),
            );

            let key_image = KeyImage::from(&onetime_private_key);

            Ok(env.byte_array_from_slice(&key_image.as_bytes()[..])?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOut_encode(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let tx_out: MutexGuard<TxOut> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let bytes = mc_util_serial::encode(&*tx_out);
            Ok(env.byte_array_from_slice(&bytes)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOut_decrypt_1memo_1payload(
    env: JNIEnv,
    obj: JObject,
    account_key: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let tx_out: MutexGuard<TxOut> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let account_key: MutexGuard<AccountKey> =
                env.get_rust_field(account_key, RUST_OBJ_FIELD)?;

            let tx_out_public_key: RistrettoPublic = RistrettoPublic::try_from(&tx_out.public_key)?;

            let shared_secret =
                get_tx_out_shared_secret(&*account_key.view_private_key(), &tx_out_public_key);

            let memo_payload: MemoPayload = tx_out.decrypt_memo(&shared_secret);
            let memo_payload_generic_array: GenericArray<u8, U66> = memo_payload.into();
            let memo_payload_bytes: &[u8] = memo_payload_generic_array.as_slice();

            Ok(env.byte_array_from_slice(memo_payload_bytes)?)
        },
    )
}

/********************************************************************
 * TxOutMembershipProof
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOutMembershipProof_init_1from_1protobuf_1bytes(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let protobuf_bytes = env.convert_byte_array(bytes)?;
        let tx_out: TxOutMembershipProof = mc_util_serial::decode(&protobuf_bytes)?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, tx_out)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOutMembershipProof_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: TxOutMembershipProof = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * Transaction
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Transaction_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: Tx = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Transaction_encode(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let tx: MutexGuard<Tx> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let bytes = mc_util_serial::encode(&*tx);
            Ok(env.byte_array_from_slice(&bytes)?)
        },
    )
}

/********************************************************************
 * TxOutMemoBuilder
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOutMemoBuilder_init_1jni_1with_1sender_1and_1destination_1rth_1memo(
    env: JNIEnv,
    obj: JObject,
    account_key: JObject,
) {
    jni_ffi_call(&env, |env| {
        let account_key: MutexGuard<AccountKey> =
            env.get_rust_field(account_key, RUST_OBJ_FIELD)?;

        let mut rth_memo_builder: RTHMemoBuilder = RTHMemoBuilder::default();
        rth_memo_builder.set_sender_credential(SenderMemoCredential::from(&*account_key));
        rth_memo_builder.enable_destination_memo();

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(rth_memo_builder);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo_builder_box)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOutMemoBuilder_init_1jni_1with_1sender_1payment_1request_1and_1destination_1rth_1memo(
    env: JNIEnv,
    obj: JObject,
    account_key: JObject,
    payment_request_id: jlong,
) {
    jni_ffi_call(&env, |env| {
        let account_key: MutexGuard<AccountKey> =
            env.get_rust_field(account_key, RUST_OBJ_FIELD)?;

        let mut rth_memo_builder: RTHMemoBuilder = RTHMemoBuilder::default();
        rth_memo_builder.set_sender_credential(SenderMemoCredential::from(&*account_key));
        rth_memo_builder.set_payment_request_id(payment_request_id as u64);
        rth_memo_builder.enable_destination_memo();

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(rth_memo_builder);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo_builder_box)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TxOutMemoBuilder_init_1jni_1with_1default_1rth_1memo(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> =
            Box::new(RTHMemoBuilder::default());
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo_builder_box)?)
    })
}

/********************************************************************
 * GiftCodeMemoBuilders
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeFundingMemoBuiler_init(
    env: JNIEnv,
    obj: JObject,
    note: JString,
) {
    jni_ffi_call(&env, |env| {
        let note: String = env.get_string(note)?.into();
        let memo_builder = GiftCodeFundingMemoBuilder::new(note.as_str())?;

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(memo_builder);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo_builder_box)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeSenderMemoBuiler_init(
    env: JNIEnv,
    obj: JObject,
    note: JString,
) {
    jni_ffi_call(&env, |env| {
        let note: String = env.get_string(note)?.into();
        let memo_builder = GiftCodeSenderMemoBuilder::new(note.as_str())?;

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(memo_builder);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo_builder_box)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_GiftCodeCancellationMemoBuiler_init(
    env: JNIEnv,
    obj: JObject,
    global_index: JObject,
) {
    jni_ffi_call(&env, |env| {
        let index = jni_big_int_to_u64(env, global_index)?;
        let memo_builder = GiftCodeCancellationMemoBuilder::new(index);

        let memo_builder_box: Box<dyn MemoBuilder + Sync + Send> = Box::new(memo_builder);

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, memo_builder_box)?)
    })
}

/********************************************************************
 * TransactionBuilder
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_init_1jni(
    env: JNIEnv,
    obj: JObject,
    fog_resolver: JObject,
    memo_builder_box: JObject,
    block_version: jint,
) {
    jni_ffi_call(&env, |env| {
        let fog_resolver: MutexGuard<FogResolver> =
            env.get_rust_field(fog_resolver, RUST_OBJ_FIELD)?;
        let block_version = BlockVersion::try_from(block_version as u32).unwrap();
        // Note: RTHMemoBuilder can be selected here, but we will only actually
        // write memos if block_version is large enough that memos are supported.
        // If block version is < 2, then transaction builder will filter out memos.
        let memo_builder_box: Box<dyn MemoBuilder + Send + Sync> =
            env.take_rust_field(memo_builder_box, RUST_OBJ_FIELD)?;
        // FIXME #1595: The token id should be a parameter and not hard coded to Mob
        // here
        let token_id = Mob::ID;
        let fee_amount = Amount::new(Mob::MINIMUM_FEE, token_id);
        let tx_builder = TransactionBuilder::new_with_box(
            block_version,
            fee_amount,
            fog_resolver.clone(),
            memo_builder_box,
        )?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, tx_builder)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _: TransactionBuilder<FogResolver> = env.take_rust_field(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_add_1input(
    env: JNIEnv,
    obj: JObject,
    ring: jobjectArray,
    membership_proofs: jobjectArray,
    real_index: jshort,
    onetime_private_key: JObject,
    view_private_key: JObject,
) {
    jni_ffi_call(&env, |env| {
        let mut tx_builder: MutexGuard<TransactionBuilder<FogResolver>> =
            env.get_rust_field(obj, RUST_OBJ_FIELD)?;
        let ring: Vec<TxOut> = (0..env.get_array_length(ring)?)
            .map(|index| {
                let obj = env.get_object_array_element(ring, index)?;
                let tx_out: MutexGuard<TxOut> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
                Ok(tx_out.clone())
            })
            .collect::<Result<_, jni::errors::Error>>()?;

        let membership_proofs: Vec<TxOutMembershipProof> = (0..env
            .get_array_length(membership_proofs)?)
            .map(|index| {
                let obj = env.get_object_array_element(membership_proofs, index)?;
                let membership_proof: MutexGuard<TxOutMembershipProof> =
                    env.get_rust_field(obj, RUST_OBJ_FIELD)?;
                Ok(membership_proof.clone())
            })
            .collect::<Result<_, jni::errors::Error>>()?;

        let onetime_private_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(onetime_private_key, RUST_OBJ_FIELD)?;

        let view_private_key: MutexGuard<RistrettoPrivate> =
            env.get_rust_field(view_private_key, RUST_OBJ_FIELD)?;

        let input_credentials_result = InputCredentials::new(
            ring,
            membership_proofs,
            real_index as usize,
            *onetime_private_key,
            *view_private_key,
        );
        tx_builder.add_input(input_credentials_result?);

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_add_1output(
    env: JNIEnv,
    obj: JObject,
    value: JObject,
    recipient: JObject,
    confirmation_number_out: jbyteArray,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let mut tx_builder: MutexGuard<TransactionBuilder<FogResolver>> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;

            let value = jni_big_int_to_u64(env, value)?;

            // TODO (GH #1867): If you want to do mixed transactions, use something other
            // than fee_token_id here.
            let amount = Amount {
                value: value as u64,
                token_id: tx_builder.get_fee_token_id(),
            };

            let recipient: MutexGuard<PublicAddress> =
                env.get_rust_field(recipient, RUST_OBJ_FIELD)?;

            let mut rng = McRng::default();
            let (tx_out, confirmation_number) =
                tx_builder.add_output(amount, &recipient, &mut rng)?;
            if !confirmation_number_out.is_null() {
                let len = env.get_array_length(confirmation_number_out)?;
                if len as usize >= confirmation_number.to_vec().len() {
                    env.set_byte_array_region(
                        confirmation_number_out,
                        0,
                        confirmation_number
                            .to_vec()
                            .into_iter()
                            .map(|u| u as i8)
                            .collect::<Vec<_>>()
                            .as_slice(),
                    )?;
                }
            }

            let mbox = Box::new(Mutex::new(tx_out));
            let ptr: *mut Mutex<TxOut> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_add_1change_1output(
    env: JNIEnv,
    obj: JObject,
    value: JObject,
    source_account_key: JObject,
    confirmation_number_out: jbyteArray,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let mut tx_builder: MutexGuard<TransactionBuilder<FogResolver>> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let source_account_key: MutexGuard<AccountKey> =
                env.get_rust_field(source_account_key, RUST_OBJ_FIELD)?;

            let value = jni_big_int_to_u64(env, value)?;
            let change_destination = ReservedSubaddresses::from(&*source_account_key);
            let mut rng = McRng::default();

            // TODO (GH #1867): If you want to do mixed transactions, use something other
            // than fee_token_id here.
            let amount = Amount {
                value: value as u64,
                token_id: tx_builder.get_fee_token_id(),
            };

            let (tx_out, confirmation_number) =
                tx_builder.add_change_output(amount, &change_destination, &mut rng)?;
            if !confirmation_number_out.is_null() {
                let len = env.get_array_length(confirmation_number_out)?;
                if len as usize >= confirmation_number.to_vec().len() {
                    env.set_byte_array_region(
                        confirmation_number_out,
                        0,
                        confirmation_number
                            .to_vec()
                            .into_iter()
                            .map(|u| u as i8)
                            .collect::<Vec<_>>()
                            .as_slice(),
                    )?;
                }
            }

            let mbox = Box::new(Mutex::new(tx_out));
            let ptr: *mut Mutex<TxOut> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_add_1gift_1code_1output(
    env: JNIEnv,
    obj: JObject,
    value: JObject,
    source_account_key: JObject,
    confirmation_number_out: jbyteArray,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let mut tx_builder: MutexGuard<TransactionBuilder<FogResolver>> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let source_account_key: MutexGuard<AccountKey> =
                env.get_rust_field(source_account_key, RUST_OBJ_FIELD)?;

            let value = jni_big_int_to_u64(env, value)?;
            let reserved_subaddresses = ReservedSubaddresses::from(&*source_account_key);
            let mut rng = McRng::default();

            // TODO (GH #1867): If you want to do mixed transactions, use something other
            // than fee_token_id here.
            let amount = Amount {
                value: value as u64,
                token_id: tx_builder.get_fee_token_id(),
            };

            let (tx_out, confirmation_number) =
                tx_builder.add_gift_code_output(amount, &reserved_subaddresses, &mut rng)?;
            if !confirmation_number_out.is_null() {
                let len = env.get_array_length(confirmation_number_out)?;
                if len as usize >= confirmation_number.to_vec().len() {
                    env.set_byte_array_region(
                        confirmation_number_out,
                        0,
                        confirmation_number
                            .to_vec()
                            .into_iter()
                            .map(|u| u as i8)
                            .collect::<Vec<_>>()
                            .as_slice(),
                    )?;
                }
            }

            let mbox = Box::new(Mutex::new(tx_out));
            let ptr: *mut Mutex<TxOut> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_set_1tombstone_1block(
    env: JNIEnv,
    obj: JObject,
    value: jlong,
) {
    jni_ffi_call(&env, |env| {
        let mut tx_builder: MutexGuard<TransactionBuilder<FogResolver>> =
            env.get_rust_field(obj, RUST_OBJ_FIELD)?;

        tx_builder.set_tombstone_block(value as u64);

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_set_1fee(
    env: JNIEnv,
    obj: JObject,
    value: jlong,
) {
    jni_ffi_call(&env, |env| {
        let mut tx_builder: MutexGuard<TransactionBuilder<FogResolver>> =
            env.get_rust_field(obj, RUST_OBJ_FIELD)?;

        tx_builder.set_fee(value as u64)?;

        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_TransactionBuilder_build_1tx(
    env: JNIEnv,
    obj: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let tx_builder: TransactionBuilder<FogResolver> =
                env.take_rust_field(obj, RUST_OBJ_FIELD)?;

            let mut rng = McRng::default();
            let tx = tx_builder.build(&NoKeysRingSigner {}, &mut rng)?;

            let mbox = Box::new(Mutex::new(tx));
            let ptr: *mut Mutex<Tx> = Box::into_raw(mbox);

            Ok(ptr as jlong)
        },
    )
}

/********************************************************************
 * Util
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Util_recover_1onetime_1private_1key(
    env: JNIEnv,
    _obj: JObject,
    tx_pub_key: JObject,
    tx_target_key: JObject,
    account_key: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let tx_pub_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_pub_key, RUST_OBJ_FIELD)?;
            let tx_target_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_target_key, RUST_OBJ_FIELD)?;
            let account_key: MutexGuard<AccountKey> =
                env.get_rust_field(account_key, RUST_OBJ_FIELD)?;

            let subaddress_spk = recover_public_subaddress_spend_key(
                account_key.view_private_key(),
                &tx_target_key,
                &tx_pub_key,
            );
            let spsk_to_index: BTreeMap<RistrettoPublic, u64> = (0..=DEFAULT_SUBADDRESS_INDEX)
                .chain(CHANGE_SUBADDRESS_INDEX..INVALID_SUBADDRESS_INDEX)
                .map(|index| (*account_key.subaddress(index).spend_public_key(), index))
                .collect();
            let subaddress_index = spsk_to_index
                .get(&subaddress_spk)
                .ok_or_else(|| McError::Other("Subaddress match error".to_owned()))?;

            let key = recover_onetime_private_key(
                &tx_pub_key,
                account_key.view_private_key(),
                &account_key.subaddress_spend_private(*subaddress_index),
            );

            let mbox = Box::new(Mutex::new(key));
            let ptr: *mut Mutex<RistrettoPrivate> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Util_attest_1verify_1report(
    env: JNIEnv,
    _obj: JObject,
    report_bytes: jbyteArray,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let report_bytes = env.convert_byte_array(report_bytes)?;
            let remote_report: VerificationReport = mc_util_serial::deserialize(&report_bytes)?;
            let verification_report_data = VerificationReportData::try_from(&remote_report)?;
            let report_data: ReportData =
                verification_report_data.quote.report_body()?.report_data();
            let report_data_bytes: &[u8] = report_data.as_ref();

            Ok(env.byte_array_from_slice(report_data_bytes)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_DefaultVersionedCryptoBox_versioned_1crypto_1box_1decrypt(
    env: JNIEnv,
    _obj: JObject,
    key: JObject,
    encrypted: jbyteArray,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let view_key: MutexGuard<RistrettoPrivate> = env.get_rust_field(key, RUST_OBJ_FIELD)?;
            let encrypted = env.convert_byte_array(encrypted)?;

            let (success, mut plaintext) =
                VersionedCryptoBox::default().decrypt(&view_key, &encrypted)?;

            if !bool::from(success) {
                plaintext.zeroize();
                return Err(McError::Other("Mac check failed".to_owned()));
            }

            Ok(env.byte_array_from_slice(&plaintext)?)
        },
    )
}

/// A method that converts a BigInteger value to string, used for testing
/// jni_big_int_to_u64.
#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Util_bigint2string(
    env: JNIEnv,
    _obj: JObject,
    value: JObject,
) -> jstring {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let val = jni_big_int_to_u64(env, value)?;
            Ok(env.new_string(val.to_string())?.into_inner())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Util_get_1shared_1secret(
    env: JNIEnv,
    _obj: JObject,
    view_private_key: JObject,
    tx_out_public_key: JObject,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let view_private_key: MutexGuard<RistrettoPrivate> =
                env.get_rust_field(view_private_key, RUST_OBJ_FIELD)?;
            let tx_out_public_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_out_public_key, RUST_OBJ_FIELD)?;

            let key = get_tx_out_shared_secret(&view_private_key, &tx_out_public_key);

            let mbox = Box::new(Mutex::new(key));
            let ptr: *mut Mutex<RistrettoPublic> = Box::into_raw(mbox);

            Ok(ptr as jlong)
        },
    )
}

/********************************************************************
 * Receipt
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Receipt_is_1confirmation_1valid(
    env: JNIEnv,
    _obj: JObject,
    confirmation_number: jbyteArray,
    tx_pub_key: JObject,
    view_key: JObject,
) -> jboolean {
    jni_ffi_call_or(
        || Ok(JNI_FALSE),
        &env,
        |env| {
            let tx_pub_key: MutexGuard<RistrettoPublic> =
                env.get_rust_field(tx_pub_key, RUST_OBJ_FIELD)?;
            let view_key: MutexGuard<RistrettoPrivate> =
                env.get_rust_field(view_key, RUST_OBJ_FIELD)?;

            let confirmation_number =
                <[u8; 32]>::try_from(&env.convert_byte_array(confirmation_number)?[..])?;
            let confirmation = TxOutConfirmationNumber::from(confirmation_number);
            // jboolean is a u8 type with JNI_FALSE and JNI_TRUE defined as 0 and 1
            Ok(confirmation.validate(&tx_pub_key, &view_key) as u8)
        },
    )
}

/********************************************************************
 * ResponderId
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ResponderId_init_1jni(
    env: JNIEnv,
    obj: JObject,
    address: JString,
) {
    jni_ffi_call(&env, |env| {
        let address: String = env.get_string(address)?.into();
        let responder_id = ResponderId::from_str(address.as_str())
            .map_err(|err| McError::Other(format!("Unable to construct ResponderId: {}", err)))?;
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, responder_id)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ResponderId_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, ResponderId>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * Attestation Verifier
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Verifier_init_1jni(env: JNIEnv, obj: JObject) {
    jni_ffi_call(&env, |env| {
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, verifier)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Verifier_add_1mr_1signer(
    env: JNIEnv,
    obj: JObject,
    mr_signer: jbyteArray,
    product_id: jshort,
    security_version: jshort,
    config_advisories: jobjectArray,
    hardening_advisories: jobjectArray,
) {
    jni_ffi_call(&env, |env| {
        let mr_signer_bytes = <[u8; 32]>::try_from(&env.convert_byte_array(mr_signer)?[..])?;
        let mr_signer = MrSigner::from(mr_signer_bytes);
        let mut mr_signer_verifier =
            MrSignerVerifier::new(mr_signer, product_id as u16, security_version as u16);

        let config_advisories_num = env.get_array_length(config_advisories)?;
        for i in 0..config_advisories_num {
            let config_advisory: JString = env
                .get_object_array_element(config_advisories, i as i32)?
                .into();
            let config_advisory_string: String = env.get_string(config_advisory)?.into();
            mr_signer_verifier.allow_config_advisory(&config_advisory_string);
        }

        let hardening_advisories_num = env.get_array_length(hardening_advisories)?;
        for i in 0..hardening_advisories_num {
            let hardening_advisory: JString = env
                .get_object_array_element(hardening_advisories, i as i32)?
                .into();
            let hardening_advisory_string: String = env.get_string(hardening_advisory)?.into();
            mr_signer_verifier.allow_hardening_advisory(&hardening_advisory_string);
        }

        let mut verifier: MutexGuard<Verifier> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
        verifier.mr_signer(mr_signer_verifier);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Verifier_add_1mr_1enclave(
    env: JNIEnv,
    obj: JObject,
    mr_enclave: jbyteArray,
    config_advisories: jobjectArray,
    hardening_advisories: jobjectArray,
) {
    jni_ffi_call(&env, |env| {
        let mr_enclave_bytes = <[u8; 32]>::try_from(&env.convert_byte_array(mr_enclave)?[..])?;
        let mr_enclave = MrEnclave::from(mr_enclave_bytes);
        let mut mr_enclave_verifier = MrEnclaveVerifier::new(mr_enclave);

        let config_advisories_num = env.get_array_length(config_advisories)?;
        for i in 0..config_advisories_num {
            let config_advisory: JString = env
                .get_object_array_element(config_advisories, i as i32)?
                .into();
            let config_advisory_string: String = env.get_string(config_advisory)?.into();
            mr_enclave_verifier.allow_config_advisory(&config_advisory_string);
        }

        let hardening_advisories_num = env.get_array_length(hardening_advisories)?;
        for i in 0..hardening_advisories_num {
            let hardening_advisory: JString = env
                .get_object_array_element(hardening_advisories, i as i32)?
                .into();
            let hardening_advisory_string: String = env.get_string(hardening_advisory)?.into();
            mr_enclave_verifier.allow_hardening_advisory(&hardening_advisory_string);
        }

        let mut verifier: MutexGuard<Verifier> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
        verifier.mr_enclave(mr_enclave_verifier);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Verifier_finalize_1jni(env: JNIEnv, obj: JObject) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, Verifier>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * FogResolver
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_FogResolver_init_1jni(
    env: JNIEnv,
    obj: JObject,
    report_responses: JObject,
    verifier: JObject,
) {
    jni_ffi_call(&env, |env| {
        let report_responses: MutexGuard<FogReportResponses> =
            env.get_rust_field(report_responses, RUST_OBJ_FIELD)?;
        let verifier: MutexGuard<Verifier> = env.get_rust_field(verifier, RUST_OBJ_FIELD)?;
        let fog_resolver = FogResolver::new(report_responses.clone(), &verifier)?;
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, fog_resolver)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_FogResolver_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, FogResolver>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * FogReportResponses
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_FogReportResponses_init_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let fog_report_responses = FogReportResponses::default();
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, fog_report_responses)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_FogReportResponses_add_1response(
    env: JNIEnv,
    obj: JObject,
    report_uri: JString,
    report_response: JObject,
) {
    jni_ffi_call(&env, |env| {
        let report_uri: String = env.get_string(report_uri)?.into();
        let report_uri = FogUri::from_str(&report_uri)?;
        let report_uri = report_uri.to_string();
        let report_response: MutexGuard<ReportResponse> =
            env.get_rust_field(report_response, RUST_OBJ_FIELD)?;
        let mut report_responses: MutexGuard<FogReportResponses> =
            env.get_rust_field(obj, RUST_OBJ_FIELD)?;
        report_responses.insert(report_uri, report_response.clone());
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_FogReportResponses_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, FogReportResponses>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * ReportResponse
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ReportResponse_init_1jni(
    env: JNIEnv,
    obj: JObject,
    reports: jobjectArray,
    chain: jobjectArray,
    signature: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let reports: Vec<Report> = (0..env.get_array_length(reports)?)
            .map(|index| {
                let obj = env.get_object_array_element(reports, index)?;
                let report: MutexGuard<Report> = env.get_rust_field(obj, RUST_OBJ_FIELD)?;
                Ok(report.clone())
            })
            .collect::<Result<_, jni::errors::Error>>()?;
        let chain = (0..env.get_array_length(chain)?)
            .map(|index| {
                let obj = env.get_object_array_element(chain, index)?;
                env.convert_byte_array(obj.into_inner()) // FIXME: into_inner()
                                                         // sane here?
            })
            .collect::<Result<Vec<Vec<u8>>, jni::errors::Error>>()?;
        let signature = env.convert_byte_array(signature)?;
        let report_response = ReportResponse {
            reports,
            chain,
            signature,
        };
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, report_response)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ReportResponse_init_1jni_1from_1protobuf_1bytes(
    env: JNIEnv,
    obj: JObject,
    bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let protobuf_bytes = env.convert_byte_array(bytes)?;
        let report_response: ReportResponse = mc_util_serial::decode(&protobuf_bytes)?;

        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, report_response)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ReportResponse_get_1bytes(
    env: JNIEnv,
    obj: JObject,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let report_response: MutexGuard<ReportResponse> =
                env.get_rust_field(obj, RUST_OBJ_FIELD)?;
            let bytes = mc_util_serial::encode(&*report_response);
            Ok(env.byte_array_from_slice(&bytes)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_ReportResponse_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, ReportResponse>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * VerificationSignature
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_VerificationSignature_init_1jni(
    env: JNIEnv,
    obj: JObject,
    contents_bytes: jbyteArray,
) {
    jni_ffi_call(&env, |env| {
        let contents_bytes = env.convert_byte_array(contents_bytes)?;
        let verification_signature = VerificationSignature::from(contents_bytes);
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, verification_signature)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_VerificationSignature_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, VerificationSignature>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * VerificationReport
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_VerificationReport_init_1jni(
    env: JNIEnv,
    obj: JObject,
    verification_signature: JObject,
    chain: jobjectArray,
    http_body: JString,
) {
    jni_ffi_call(&env, |env| {
        let verification_signature: MutexGuard<VerificationSignature> =
            env.get_rust_field(verification_signature, RUST_OBJ_FIELD)?;

        let chain = (0..env.get_array_length(chain)?)
            .map(|index| {
                let obj = env.get_object_array_element(chain, index)?;
                env.convert_byte_array(obj.into_inner())
            })
            .collect::<Result<Vec<Vec<u8>>, jni::errors::Error>>()?;
        let http_body: String = env.get_string(http_body)?.into();
        let verification_report = VerificationReport {
            sig: verification_signature.clone(),
            chain,
            http_body,
        };
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, verification_report)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_VerificationReport_finalize_1jni(
    env: JNIEnv,
    obj: JObject,
) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, VerificationReport>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * Report
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Report_init_1jni(
    env: JNIEnv,
    obj: JObject,
    report_id: JString,
    verification_report: JObject,
    pubkey_expiry: jlong,
) {
    jni_ffi_call(&env, |env| {
        let verification_report: MutexGuard<VerificationReport> =
            env.get_rust_field(verification_report, RUST_OBJ_FIELD)?;
        let report_id: String = env.get_string(report_id)?.into();
        let report = Report {
            fog_report_id: report_id,
            report: verification_report.clone(),
            pubkey_expiry: pubkey_expiry as u64,
        };
        Ok(env.set_rust_field(obj, RUST_OBJ_FIELD, report)?)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Report_finalize_1jni(env: JNIEnv, obj: JObject) {
    jni_ffi_call(&env, |env| {
        let _ = env.take_rust_field::<_, _, Report>(obj, RUST_OBJ_FIELD)?;
        Ok(())
    })
}

/********************************************************************
 * Mnemonic (BIP39)
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Mnemonics_entropy_1from_1mnemonic(
    env: JNIEnv,
    _obj: JObject,
    mnemonic: JString,
) -> jbyteArray {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let mnemonic: String = env.get_string(mnemonic)?.into();

            let mnemonic = Mnemonic::from_phrase(&mnemonic, Language::English)?;

            let entropy = mnemonic.entropy();

            Ok(env.byte_array_from_slice(entropy)?)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Mnemonics_entropy_1to_1mnemonic(
    env: JNIEnv,
    _obj: JObject,
    entropy: jbyteArray,
) -> jstring {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let bytes = env.convert_byte_array(entropy)?;
            let mnemonic = Mnemonic::from_entropy(&bytes, Language::English)?;
            Ok(env.new_string(mnemonic.to_string())?.into_inner())
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_Mnemonics_words_1by_1prefix(
    env: JNIEnv,
    _obj: JObject,
    prefix: JString,
) -> jstring {
    jni_ffi_call_or(
        || Ok(JObject::null().into_inner()),
        &env,
        |env| {
            let prefix: String = env.get_string(prefix)?.into();
            let words = bip39::Language::English
                .wordlist()
                .get_words_by_prefix(&prefix);
            let joined_words = words.join(",");
            Ok(env.new_string(joined_words)?.into_inner())
        },
    )
}

/********************************************************************
 * SLIP-0010
 */

#[no_mangle]
pub unsafe extern "C" fn Java_com_mobilecoin_lib_AccountKeyDeriver_accountKey_1from_1mnemonic(
    env: JNIEnv,
    _obj: JObject,
    mnemonic_phrase: JString,
    account_index: jint,
) -> jlong {
    jni_ffi_call_or(
        || Ok(0),
        &env,
        |env| {
            let mnemonic_phrase: String = env.get_string(mnemonic_phrase)?.into();
            let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English)?;
            let key = mnemonic.derive_slip10_key(account_index as u32);
            let account_key = AccountKey::from(key);
            let mbox = Box::new(Mutex::new(account_key));
            let ptr: *mut Mutex<AccountKey> = Box::into_raw(mbox);
            Ok(ptr as jlong)
        },
    )
}
