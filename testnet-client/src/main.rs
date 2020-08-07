// Copyright (c) 2018-2020 MobileCoin Inc.

//! A demo client for interacting with the MobileCoin test network using mobilecoind.

use chrono::Local;
use dialoguer::{theme::ColorfulTheme, Input, Select, Validator};
use grpcio::ChannelBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use mc_common::logger::{create_app_logger, o, Logger};
use mc_mobilecoind_api::{mobilecoind_api_grpc::MobilecoindApiClient, MobilecoindUri};
use mc_util_b58_payloads::payloads::RequestPayload;
use mc_util_grpc::{build_info_grpc::BuildInfoApiClient, ConnectionUriGrpcioChannel};
use protobuf::RepeatedField;
use rust_decimal::{prelude::ToPrimitive, Decimal};
use std::{convert::TryInto, fmt, str::FromStr, sync::Arc, thread, time::Duration};
use structopt::StructOpt;

/// Command lien config.
#[derive(Clone, StructOpt)]
struct Config {
    /// The host:port of the mobilecoind instance to connect to.
    #[structopt(short = "m", long, default_value = "insecure-mobilecoind://127.0.0.1/")]
    pub mobilecoind_uri: MobilecoindUri,
}

/// The main entry point.
fn main() {
    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());

    match TestnetClient::new(&config, &logger) {
        Ok(mut client) => client.run(),
        Err(_) => std::process::exit(1),
    }
}

/// Commands in the main menu.
enum Command {
    Send,
    Receive,
    CheckBalance,
    Quit,
}
impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Send => write!(f, "Send a payment"),
            Command::Receive => write!(f, "Request a payment"),
            Command::CheckBalance => write!(f, "Check balance"),
            Command::Quit => write!(f, "Quit"),
        }
    }
}

/// The actual test-net client implementation.
struct TestnetClient {
    config: Config,
    client: MobilecoindApiClient,
    monitor_id: Vec<u8>,
}

impl TestnetClient {
    pub fn new(config: &Config, logger: &Logger) -> Result<Self, String> {
        // Construct GRPC connection to mobilecoind.
        let env = Arc::new(grpcio::EnvBuilder::new().build());
        let ch = ChannelBuilder::new(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(&config.mobilecoind_uri, logger);

        // Connect to mobilecoind and get some information from it. Log that to ease with potential debugging.
        let build_info_client = BuildInfoApiClient::new(ch.clone());
        let build_info = match build_info_client.get_build_info(&mc_mobilecoind_api::Empty::new()) {
            Ok(resp) => resp,
            Err(err) => {
                println!(
                    "Unable to connect to mobilecoind on {}.",
                    config.mobilecoind_uri,
                );
                println!("Are you sure it is running and accepting connections?");
                println!();
                println!("The error was: {}", err);
                return Err(format!(
                    "unable to get build info from mobilecoind - {}",
                    err
                ));
            }
        };
        println!("Connected to mobilecoind on {}.", config.mobilecoind_uri);
        println!("commit = {}", build_info.git_commit);
        println!("profile = {}", build_info.profile);
        println!("target_arch = {}", build_info.target_arch);
        println!("target_feature = {}", build_info.target_feature);
        println!("rustflags = {}", build_info.rustflags);
        println!("sgx_mode = {}", build_info.sgx_mode);
        println!("ias_mode = {}", build_info.ias_mode);
        println!();

        let client = MobilecoindApiClient::new(ch);

        let testnet_client = TestnetClient {
            config: config.clone(),
            client,
            monitor_id: Vec::new(),
        };

        let network_status = match testnet_client.get_network_status() {
            Ok(resp) => resp,
            Err(err) => {
                println!(
                    "Unable to query network status using mobilecoind on {}.",
                    config.mobilecoind_uri
                );
                println!("Are you sure it is running and accepting connections?");
                println!();
                println!("The error was: {}", err);
                return Err(format!(
                    "unable to query network status from mobilecoind - {}",
                    err
                ));
            }
        };
        println!(
            "The local ledger is at block #{}. The MobileCoin Network is at block #{}.",
            network_status.local_block_index, network_status.network_highest_block_index,
        );

        // Return.
        Ok(testnet_client)
    }

    /// The main UI loop.
    pub fn run(&mut self) {
        self.print_intro();

        loop {
            let root_entropy = Self::get_root_entropy();
            match self.add_monitor_and_wait_for_sync(&root_entropy) {
                Ok(_) => {
                    break;
                }
                Err(err) => {
                    println!("{}", err);
                }
            }
        }

        loop {
            if let Err(err) = self.print_balance() {
                println!("{}", err);
            }

            let commands = [
                Command::Send,
                Command::Receive,
                Command::CheckBalance,
                Command::Quit,
            ];
            let selection = Select::with_theme(&ColorfulTheme::default())
                .default(0)
                .items(&commands)
                .interact()
                .unwrap();
            match commands[selection] {
                Command::Send => self.send(),
                Command::Receive => self.receive(),
                Command::CheckBalance => {
                    // Balance updates every loop iteration
                }
                Command::Quit => {
                    println!("Thanks for using the MobileCoin TestNet!");
                    thread::sleep(Duration::from_secs(1));
                    break;
                }
            }
        }
    }

    /// Print a short introductory message.
    fn print_intro(&self) {
        println!(
            r#"
**********************************************************************

                  Welcome to the MobileCoin TestNet

**********************************************************************

You are now connected to: {}

Please enter the 32 byte master key for an account. If you received an
email with an allocation of TestNet mobilecoins, this is the master
key that we sent to you. It should look something like:

dc74edf1d8842dfdf49d6db5d3d4e873665c2dd400c0955dd9729571826a26be
"#,
            self.config.mobilecoind_uri,
        );
    }

    /// Get root entropy from user.
    fn get_root_entropy() -> [u8; 32] {
        #[derive(Clone)]
        struct EntropyBytes(pub [u8; 32]);
        impl FromStr for EntropyBytes {
            type Err = String;
            fn from_str(src: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode(src).map_err(|err| format!("Invalid input: {}", err))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "Invalid input length, got {} bytes while expecting 32",
                        bytes.len()
                    ));
                }

                let mut output = [0; 32];
                output.copy_from_slice(&bytes[..]);
                Ok(Self(output))
            }
        }
        impl fmt::Display for EntropyBytes {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        Input::<EntropyBytes>::new()
            .with_prompt("Enter your master key")
            .interact_text()
            .expect("failed getting master key")
            .0
    }

    /// Contact the MobileCoin network to collect the latest ledger size information
    fn get_network_status(&self) -> Result<mc_mobilecoind_api::GetNetworkStatusResponse, String> {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(120);
        pb.set_message("Checking the MobileCoin public ledger...");

        // Get the network status.
        let network_status = self
            .client
            .get_network_status(&mc_mobilecoind_api::Empty::new())
            .map_err(|err| format!("Failed getting network status: {}", err))?;

        pb.finish_and_clear();
        Ok(network_status)
    }

    /// Add a monitor and wait for it to catch up.
    fn add_monitor_and_wait_for_sync(&mut self, entropy: &[u8; 32]) -> Result<(), String> {
        // Get account key from entropy
        let mut req = mc_mobilecoind_api::GetAccountKeyRequest::new();
        req.set_entropy(entropy.to_vec());

        let mut resp = self
            .client
            .get_account_key(&req)
            .map_err(|err| format!("Failed getting account key for entropy: {}", err))?;

        let account_key = resp.take_account_key();

        // Add monitor for this account.
        let mut req = mc_mobilecoind_api::AddMonitorRequest::new();
        req.set_account_key(account_key);
        req.set_first_subaddress(0);
        req.set_num_subaddresses(1);
        req.set_first_block(0);

        let resp = self
            .client
            .add_monitor(&req)
            .map_err(|err| format!("Failed adding monitor: {}", err))?;
        self.monitor_id = resp.get_monitor_id().to_vec();

        let network_status = self.get_network_status()?;

        self.wait_for_monitor_sync(Some(network_status.network_highest_block_index + 1))?;

        // Done!
        Ok(())
    }

    /// Print the current balance.
    fn print_balance(&mut self) -> Result<(), String> {
        let network_status = self.get_network_status()?;

        if network_status.network_highest_block_index > network_status.local_block_index {
            let blocks_behind =
                network_status.network_highest_block_index - network_status.local_block_index;

            // If we're behind by too many blocks (arbitrarily chosen for now), then display an error.
            if blocks_behind > 10 {
                println!(
                    r#"
**********************************************************************

          The ledger must be current to check your balance.

          Waiting for {} more blocks.

**********************************************************************
"#,
                    blocks_behind
                );
                return Ok(());
            }

            // Syncing is not going to take very long, so wait until that happens.
            self.wait_for_monitor_sync(Some(network_status.network_highest_block_index + 1))?;
        }

        let mut req = mc_mobilecoind_api::GetBalanceRequest::new();
        req.set_monitor_id(self.monitor_id.clone());
        req.set_subaddress_index(0);

        let resp = self
            .client
            .get_balance(&req)
            .map_err(|err| format!("Failed getting balance: {}", err))?;
        let balance = resp.get_balance();
        let date = Local::now();
        println!(
            r#"
**********************************************************************

                     Your balance was {}
                             at {}

**********************************************************************
"#,
            u64_to_mob_display(balance),
            date.format("%H:%M:%S"),
        );

        Ok(())
    }

    /// Send coins flow.
    fn send(&mut self) {
        // Print intro text.
        println!(
            r#"
**********************************************************************

                          Sending a Payment

**********************************************************************

Please enter a payment request code. If you received an email with an
allocation of TestNet mobilecoins, this is the longer alphanumeric
string that we send you. It should look something like:

3CioMy13rUrFWRCcXMjz4GayaVgRcqpRpz6JXzmryaN2NJjSv2YaKED33iYnUyAMa9vi1XLRoW8xVuzzJTsc6MArq5NBDHMZXDtYRSrA9AjFdfv6QzLF21AWc36yXcsiqGZkgLKk
"#
        );

        // Read and parse B58 request code.
        #[derive(Clone)]
        struct WrappedRequestPayload(pub Option<RequestPayload>);
        impl FromStr for WrappedRequestPayload {
            type Err = String;
            fn from_str(src: &str) -> Result<Self, Self::Err> {
                if src.is_empty() {
                    return Ok(Self(None));
                }

                Ok(Self(Some(RequestPayload::decode(src).map_err(|err| {
                    format!("Invalid request code: {}", err)
                })?)))
            }
        }
        impl fmt::Display for WrappedRequestPayload {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if let Some(inner) = &self.0 {
                    write!(f, "{}", inner.encode())?;
                }
                Ok(())
            }
        }

        let opt_request_code = Input::<WrappedRequestPayload>::new()
            .with_prompt("Enter the request code to fulfill, or leave blank to cancel")
            .allow_empty(true)
            .interact_text()
            .expect("failed getting request code")
            .0;
        if opt_request_code.is_none() {
            return;
        }
        let mut request_code = opt_request_code.unwrap();

        // Allow user to confirm, change amount or cancel.
        let tx_proposal = loop {
            println!();
            if request_code.memo.is_empty() {
                println!(
                    "This is a payment request for {}.",
                    u64_to_mob_display(request_code.value),
                );
            } else {
                println!(
                    "This is a payment request for {}. It includes a memo:",
                    u64_to_mob_display(request_code.value),
                );
                println!();
                println!("{}", request_code.memo);
                println!();
            }

            // Construct TX to figure out the fee and whether we have enough funds.
            let tx_proposal = match self.generate_tx(&request_code) {
                Ok((tx_proposal, balance)) => {
                    let fee = tx_proposal.get_fee();
                    let remaining_balance = balance - fee - request_code.value;
                    println!(
                        "You will be charged a fee of {} to send this payment. Your remaining",
                        u64_to_mob_display(fee),
                    );
                    println!(
                        "balance after sending this payment will be {}.",
                        u64_to_mob_display(remaining_balance),
                    );
                    println!();

                    tx_proposal
                }

                Err(err) => {
                    println!("Error generating transaction: {}", err);
                    println!(
                        "You will not be able to send this payment. It is possible you do not"
                    );
                    println!("have enough funds, in which case you can edit the payment amount.");
                    println!();

                    println!("Please select from the following available options:");
                    let selection = Select::with_theme(&ColorfulTheme::default())
                        .default(0)
                        .items(&[
                            "Change payment amount".to_owned(),
                            "Cancel payment".to_owned(),
                        ])
                        .interact()
                        .unwrap();
                    match selection {
                        0 => {
                            request_code.value = Self::input_mob(
                                "Enter new amount in MOB, or leave blank to cancel",
                                request_code.value,
                            );
                            continue;
                        }
                        1 => {
                            return;
                        }
                        _ => unreachable!(),
                    };
                }
            };

            println!("Please select from the following available options:");
            let selection = Select::with_theme(&ColorfulTheme::default())
                .default(0)
                .items(&[
                    format!("Send payment of {}", u64_to_mob_display(request_code.value)),
                    "Change payment amount".to_owned(),
                    "Cancel payment".to_owned(),
                ])
                .interact()
                .unwrap();
            match selection {
                0 => {
                    break tx_proposal;
                }
                1 => {
                    request_code.value = Self::input_mob(
                        "Enter new amount in MOB, or leave blank to cancel",
                        request_code.value,
                    );
                }
                2 => {
                    return;
                }
                _ => unreachable!(),
            }
        };

        // Send payment
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(120);
        pb.set_message("Sending payment...");

        let mut req = mc_mobilecoind_api::SubmitTxRequest::new();
        req.set_tx_proposal(tx_proposal);

        let mut resp = match self.client.submit_tx(&req) {
            Ok(resp) => resp,
            Err(err) => {
                println!("Error submitting transaction: {}", err);
                return;
            }
        };

        let sender_tx_receipt = resp.take_sender_tx_receipt();

        pb.set_message("Waiting for payment to complete...");
        let mut req = mc_mobilecoind_api::GetTxStatusAsSenderRequest::new();
        req.set_receipt(sender_tx_receipt);

        loop {
            let resp = match self.client.get_tx_status_as_sender(&req) {
                Ok(resp) => resp,
                Err(err) => {
                    println!("Failed checking tx status: {}", err);
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            match resp.get_status() {
                mc_mobilecoind_api::TxStatus::Unknown => {
                    thread::sleep(Duration::from_millis(250));
                }
                mc_mobilecoind_api::TxStatus::Verified => {
                    // Wait for monitor to sync so that we show the updated balance - this is a
                    // best effort attempt, if it fails we just skip it.
                    pb.set_message("Waiting for sync to complete...");
                    let _ = self.wait_for_monitor_sync(None);

                    pb.finish_with_message("Payment was successful!");
                    break;
                }
                mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => {
                    pb.finish_with_message(
                        "Tombstone block exceeded - transaction did not go through!",
                    );
                    println!();
                    break;
                }
                mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber => {
                    pb.finish_with_message(
                        "Invalid Confirmation - transaction was successful, cannot confirm sender",
                    );
                    println!();
                    break;
                }
            }
        }

        println!();
    }

    /// Receive coins flow.
    fn receive(&self) {
        // Print intro text.
        println!(
            r#"
**********************************************************************

                         Receiving a Payment

**********************************************************************

You can create a request code to share with another MobileCoin user
to receive a payment. You can meet other TestNet users online at the
MobileCoin forums. Visit http://community.mobilecoin.com

"#
        );

        let amount = Self::input_mob(
            "How many mobilecoins would you like to request (in MOB)?",
            0,
        );

        println!();
        println!("Would you like to add a memo?");
        let selection = Select::with_theme(&ColorfulTheme::default())
            .default(0)
            .items(&["Yes", "No"])
            .interact()
            .unwrap();
        let memo = match selection {
            0 => Input::<String>::new()
                .with_prompt("Please enter your memo, or leave blank to cancel")
                .allow_empty(true)
                .interact_text()
                .expect("failed getting memo"),
            1 => String::from(""),
            _ => unreachable!(),
        };
        println!();

        // Get our public address.
        let mut req = mc_mobilecoind_api::GetPublicAddressRequest::new();
        req.set_monitor_id(self.monitor_id.clone());
        req.set_subaddress_index(0);

        let mut resp = match self.client.get_public_address(&req) {
            Ok(resp) => resp,
            Err(err) => {
                println!("Failed getting our public address: {}", err);
                return;
            }
        };

        let public_address = resp.take_public_address();

        // Generate b58 code
        let mut req = mc_mobilecoind_api::GetRequestCodeRequest::new();
        req.set_receiver(public_address);
        req.set_value(amount);
        req.set_memo(memo);

        let resp = match self.client.get_request_code(&req) {
            Ok(resp) => resp,
            Err(err) => {
                println!("Failed generating request code: {}", err);
                return;
            }
        };

        println!("Your request code is:");
        println!();
        println!("  {}", resp.get_b58_code());
        println!();
    }

    /// Read an amount in MOB from the user.
    fn input_mob(prompt: &str, default: u64) -> u64 {
        // default is in picoMOB but we need it in MOB
        let mob_default = Decimal::from(default) / Decimal::from_scientific("1e12").unwrap();

        struct CanConvertToMOB;
        impl Validator for CanConvertToMOB {
            type Err = String;
            fn validate(&self, text: &str) -> Result<(), Self::Err> {
                let dec = Decimal::from_str(text).map_err(|err| format!("{}", err))?;
                (dec * Decimal::from_scientific("1e12").unwrap())
                    .to_u64()
                    .ok_or_else(|| "Value too big".to_owned())?;
                Ok(())
            }
        }

        let mob = Input::<Decimal>::new()
            .with_prompt(prompt)
            .default(mob_default)
            .validate_with(CanConvertToMOB)
            .interact_text()
            .expect("failed getting request code");

        // Convert MOB back to pMOB
        (mob * Decimal::from_scientific("1e12").unwrap())
            .to_u64()
            .expect("failed converting to u64")
    }

    /// Helper method for generating a transaction from a B58 request code.
    fn generate_tx(
        &self,
        request_payload: &RequestPayload,
    ) -> Result<(mc_mobilecoind_api::TxProposal, u64), String> {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(120);
        pb.set_message("Preparing transaction...");

        // Get our UnspentTxOuts.
        let mut req = mc_mobilecoind_api::GetUnspentTxOutListRequest::new();
        req.set_monitor_id(self.monitor_id.clone());
        req.set_subaddress_index(0);

        let resp = self
            .client
            .get_unspent_tx_out_list(&req)
            .map_err(|err| format!("Unable to get unspent txouts: {}", err))?;
        let utxos = resp.output_list;
        let balance = utxos.iter().map(|utxo| utxo.get_value()).sum::<u64>();

        // Create the outlay
        let mut outlay = mc_mobilecoind_api::Outlay::new();
        outlay.set_value(request_payload.value);
        outlay.set_receiver(mc_api::external::PublicAddress::from(
            &(request_payload
                .try_into()
                .map_err(|err| format!("Bad request payload: {}", err))?),
        ));

        // Construct the tx
        let mut req = mc_mobilecoind_api::GenerateTxRequest::new();
        req.set_sender_monitor_id(self.monitor_id.clone());
        req.set_change_subaddress(0);
        req.set_input_list(utxos);
        req.set_outlay_list(RepeatedField::from_vec(vec![outlay]));

        let mut resp = self
            .client
            .generate_tx(&req)
            .map_err(|err| format!("Unable to generate transaction: {}", err))?;
        Ok((resp.take_tx_proposal(), balance))
    }

    // Display a progress bar and wait until the local monitor has synced to a given block height
    // (if provided), or to the current ledger height if not.
    fn wait_for_monitor_sync(&mut self, block_height: Option<u64>) -> Result<(), String> {
        let resp = self
            .client
            .get_ledger_info(&mc_mobilecoind_api::Empty::new())
            .map_err(|err| format!("Failed getting number of blocks in ledger: {}", err))?;
        let num_blocks = block_height.unwrap_or(resp.block_count);

        let pb = ProgressBar::new(num_blocks);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "Syncing account... {spinner:.green} [{elapsed_precise}] [{bar:20.cyan/blue}] {pos}/{len} ({eta})",
                )
                .progress_chars("#>-"),
        );

        let mut blocks_synced = 0;
        while blocks_synced < num_blocks {
            // Get current number of blocks synced.
            let mut req = mc_mobilecoind_api::GetMonitorStatusRequest::new();
            req.set_monitor_id(self.monitor_id.clone());

            let resp = self
                .client
                .get_monitor_status(&req)
                .map_err(|err| format!("Failed getting monitor status: {}", err))?;

            pb.set_position(blocks_synced);
            blocks_synced = resp.get_status().next_block;
        }

        Ok(())
    }
}

/// Helper method for converting a u64 picomob value into human-readable form.
/// For values > 999.999 MOB, display as ({:.3} kMOB)
/// Prefer MOB units whenever we can display in the form ({:.3} MOB)
/// For values < 0.001 MOB, we display as ({:.3} µMOB)
/// For values < 0.001 µMOB, we display as ({} pMOB)
fn u64_to_mob_display(val: u64) -> String {
    let mut decimal_val: Decimal = val.into();

    let kilo_mob = Decimal::from_scientific("1e15").unwrap();
    let mob = Decimal::from_scientific("1e12").unwrap();
    let micro_mob = Decimal::from_scientific("1e6").unwrap();
    let thousand = Decimal::from_scientific("1e3").unwrap();

    if val == 0 {
        "0 MOB".to_owned()
    } else if decimal_val >= kilo_mob {
        decimal_val /= kilo_mob;
        format!("{:.3} kMOB", decimal_val)
    } else if decimal_val >= mob / thousand {
        decimal_val /= mob;
        format!("{:.3} MOB", decimal_val)
    } else if decimal_val >= micro_mob / thousand {
        decimal_val /= micro_mob;
        format!("{:.3} µMOB", decimal_val)
    } else {
        format!("{} pMOB", decimal_val)
    }
}

/// Tests.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_to_mob_display() {
        const MOB: u64 = 1_000_000_000_000;

        assert_eq!(u64_to_mob_display(0), "0 MOB");
        assert_eq!(u64_to_mob_display(99), "99 pMOB");
        assert_eq!(u64_to_mob_display(999), "999 pMOB");

        assert_eq!(u64_to_mob_display(100_000), "0.100 µMOB");
        assert_eq!(u64_to_mob_display(999_999), "0.999 µMOB");
        assert_eq!(u64_to_mob_display(1_000_000), "1.000 µMOB");
        assert_eq!(u64_to_mob_display(9_999_999), "9.999 µMOB");
        assert_eq!(u64_to_mob_display(999_999_999), "999.999 µMOB");

        assert_eq!(u64_to_mob_display(1_000_000_000), "0.001 MOB");
        assert_eq!(u64_to_mob_display(1_000_000_001), "0.001 MOB");
        assert_eq!(u64_to_mob_display(9_999_999_999), "0.009 MOB");
        assert_eq!(u64_to_mob_display(10_000_000_000), "0.010 MOB");
        assert_eq!(u64_to_mob_display(100_000_000_000), "0.100 MOB");
        assert_eq!(u64_to_mob_display(999_999_999_999), "0.999 MOB");
        assert_eq!(u64_to_mob_display(1_000_000_000_000), "1.000 MOB");
        assert_eq!(u64_to_mob_display(1_000_000_000_001), "1.000 MOB");
        assert_eq!(u64_to_mob_display(99_999_999_999_999), "99.999 MOB");
        assert_eq!(u64_to_mob_display(MOB - 100_000_000_000), "0.900 MOB");
        assert_eq!(u64_to_mob_display(MOB - 910_000_000_000), "0.090 MOB");
        assert_eq!(u64_to_mob_display(MOB - 991_000_000_000), "0.009 MOB");
        assert_eq!(u64_to_mob_display(999_999_999_999), "0.999 MOB");
        assert_eq!(u64_to_mob_display(1_000_000_000_000), "1.000 MOB");
        assert_eq!(u64_to_mob_display(1_000_000_000_001), "1.000 MOB");
        assert_eq!(u64_to_mob_display(MOB + 100_000_000), "1.000 MOB");
        assert_eq!(u64_to_mob_display(MOB + 1_000_000_000), "1.001 MOB");
        assert_eq!(u64_to_mob_display(MOB + 10_000_000_000), "1.010 MOB");
        assert_eq!(u64_to_mob_display(MOB + 100_000_000_000), "1.100 MOB");
        assert_eq!(u64_to_mob_display(MOB * 999), "999.000 MOB");
        assert_eq!(u64_to_mob_display(999_999_999_999_999), "999.999 MOB");

        assert_eq!(u64_to_mob_display(MOB * 1000), "1.000 kMOB");
        assert_eq!(u64_to_mob_display(MOB * 1000 + 1), "1.000 kMOB");
        assert_eq!(u64_to_mob_display(MOB * 1001), "1.001 kMOB");
    }
}
