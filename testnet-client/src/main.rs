// Copyright (c) 2018-2020 MobileCoin Inc.

//! A demo client for interacting with the MobileCoin test network using mobilecoind.

use dialoguer::{theme::ColorfulTheme, Input, Select, Validator};
use grpc_util::build_info_grpc::BuildInfoApiClient;
use grpcio::{ChannelBuilder, ChannelCredentialsBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use mc_b58_payloads::payloads::RequestPayload;
use mobilecoind_api::mobilecoind_api_grpc::MobilecoindApiClient;
use protobuf::RepeatedField;
use rust_decimal::{prelude::ToPrimitive, Decimal};
use std::{fmt, str::FromStr, sync::Arc, thread, time::Duration};
use structopt::StructOpt;

/// Command lien config.
#[derive(Clone, StructOpt)]
struct Config {
    /// The host:port of the mobilecoind instance to connect to.
    #[structopt(short = "s", long = "server", default_value = "127.0.0.1:4444")]
    pub mobilecoind_host: String,

    /// Use SSL when connecting to mobilecoind.
    #[structopt(long)]
    pub use_ssl: bool,
}

/// The main entry point.
fn main() {
    let config = Config::from_args();

    match TestnetClient::new(&config) {
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
    pub fn new(config: &Config) -> Result<Self, String> {
        // Construct GRPC connection to mobilecoind.
        let env = Arc::new(grpcio::EnvBuilder::new().build());
        let ch_builder = ChannelBuilder::new(env)
            .keepalive_permit_without_calls(true)
            .keepalive_time(Duration::from_secs(1))
            .keepalive_timeout(Duration::from_secs(20))
            .max_reconnect_backoff(Duration::from_millis(2000))
            .initial_reconnect_backoff(Duration::from_millis(1000))
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX);

        let ch = if config.use_ssl {
            let creds = ChannelCredentialsBuilder::new().build();
            ch_builder.secure_connect(&config.mobilecoind_host, creds)
        } else {
            ch_builder.connect(&config.mobilecoind_host)
        };

        // Connect to mobilecoind and get some information from it. Log that to ease with potential debugging.
        let build_info_client = BuildInfoApiClient::new(ch.clone());
        let build_info = match build_info_client.get_build_info(&mobilecoind_api::Empty::new()) {
            Ok(resp) => resp,
            Err(err) => {
                println!(
                    "Unable to connect to mobilecoind on {}.",
                    config.mobilecoind_host
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
        println!("Connected to mobilecoind on {}.", config.mobilecoind_host);
        println!("commit = {}", build_info.git_commit);
        println!("profile = {}", build_info.profile);
        println!("target_arch = {}", build_info.target_arch);
        println!("target_feature = {}", build_info.target_feature);
        println!("rustflags = {}", build_info.rustflags);
        println!("sgx_mode = {}", build_info.sgx_mode);
        println!("ias_mode = {}", build_info.ias_mode);

        let client = MobilecoindApiClient::new(ch);
        let ledger_info = match client.get_ledger_info(&mobilecoind_api::Empty::new()) {
            Ok(resp) => resp,
            Err(err) => {
                println!(
                    "Unable to query ledger using mobilecoind on {}.",
                    config.mobilecoind_host
                );
                println!("Are you sure it is running and accepting connections?");
                println!();
                println!("The error was: {}", err);
                return Err(format!("unable to query ledger from mobilecoind - {}", err));
            }
        };
        println!(
            "mobilecoind currently has {} blocks in ledger.",
            ledger_info.block_count
        );

        // Return.
        Ok(TestnetClient {
            config: config.clone(),
            client,
            monitor_id: Vec::new(),
        })
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
            self.print_balance();

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

  dc74edf1d8892dfdf49d6db5d3d4e873665c2dd400c0955dd9729571826a26be

"#,
            self.config.mobilecoind_host,
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
            .interact()
            .expect("failed getting master key")
            .0
    }

    /// Add a monitor and wait for it to catch up.
    fn add_monitor_and_wait_for_sync(&mut self, entropy: &[u8; 32]) -> Result<(), String> {
        // Get account key from entropy
        let mut req = mobilecoind_api::GetAccountKeyRequest::new();
        req.set_entropy(entropy.to_vec());

        let mut resp = self
            .client
            .get_account_key(&req)
            .map_err(|err| format!("Failed getting account key for entropy: {}", err))?;

        let account_key = resp.take_account_key();

        // Add monitor for this account.
        let mut req = mobilecoind_api::AddMonitorRequest::new();
        req.set_account_key(account_key);
        req.set_first_subaddress(0);
        req.set_num_subaddresses(1);
        req.set_first_block(0);

        let resp = self
            .client
            .add_monitor(&req)
            .map_err(|err| format!("Failed adding monitor: {}", err))?;
        self.monitor_id = resp.get_monitor_id().to_vec();

        // Get current number of blocks in ledger.
        let resp = self
            .client
            .get_ledger_info(&mobilecoind_api::Empty::new())
            .map_err(|err| format!("Failed getting number of blocks in ledger: {}", err))?;
        let num_blocks = resp.block_count;

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
            let mut req = mobilecoind_api::GetMonitorStatusRequest::new();
            req.set_monitor_id(self.monitor_id.clone());

            let resp = self
                .client
                .get_monitor_status(&req)
                .map_err(|err| format!("Failed getting monitor status: {}", err))?;

            pb.set_position(blocks_synced);
            blocks_synced = resp.get_status().next_block;
        }

        // Done!
        Ok(())
    }

    /// Print the current balance.
    fn print_balance(&self) {
        let mut req = mobilecoind_api::GetBalanceRequest::new();
        req.set_monitor_id(self.monitor_id.clone());
        req.set_subaddress_index(0);

        match self.client.get_balance(&req) {
            Ok(resp) => {
                let balance = resp.get_balance();

                println!();
                println!(
                    "        >>> Your balance is now {} <<<",
                    u64_to_mob_display(balance)
                );
                println!();
            }
            Err(err) => {
                println!("Error getting balance: {}", err);
            }
        }
    }

    /// Send coins flow.
    fn send(&self) {
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
            .with_prompt("Enter your request code")
            .allow_empty(true)
            .interact()
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
                            request_code.value =
                                Self::input_mob("Enter new amount (in MOB)", request_code.value);
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
                    request_code.value =
                        Self::input_mob("Enter new amount (in MOB)", request_code.value);
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
        let mut req = mobilecoind_api::SubmitTxRequest::new();
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
        let mut req = mobilecoind_api::GetTxStatusAsSenderRequest::new();
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
                mobilecoind_api::TxStatus::Unknown => {
                    thread::sleep(Duration::from_millis(250));
                }
                mobilecoind_api::TxStatus::Verified => {
                    // Wait for monitor to sync so that we show the updated balance - this is a
                    // best effort attempt, if it fails we just skip it.
                    pb.set_message("Waiting for sync to complete...");
                    let _ = self.wait_for_sync();

                    pb.finish_with_message("Payment was successful!");
                    break;
                }
                mobilecoind_api::TxStatus::TombstoneBlockExceeded => {
                    pb.finish_with_message(
                        "Tombstone block exceeded - transaction did not go through!",
                    );
                    println!();
                    break;
                }
            }
        }

        println!();
    }

    /// Wait for mobilecoind to finish syncing our monitor.
    fn wait_for_sync(&self) -> Result<(), String> {
        let resp = self
            .client
            .get_ledger_info(&mobilecoind_api::Empty::new())
            .map_err(|err| format!("Failed getting number of blocks in ledger: {}", err))?;
        let num_blocks = resp.block_count;

        let mut blocks_synced = 0;
        while blocks_synced < num_blocks {
            // Get current number of blocks synced.
            let mut req = mobilecoind_api::GetMonitorStatusRequest::new();
            req.set_monitor_id(self.monitor_id.clone());

            let resp = self
                .client
                .get_monitor_status(&req)
                .map_err(|err| format!("Failed getting monitor status: {}", err))?;

            blocks_synced = resp.get_status().next_block;
        }

        Ok(())
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
                .with_prompt("Please enter your memo")
                .allow_empty(true)
                .interact()
                .expect("failed getting memo"),
            1 => String::from(""),
            _ => unreachable!(),
        };
        println!();

        // Get our public address.
        let mut req = mobilecoind_api::GetPublicAddressRequest::new();
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
        let mut req = mobilecoind_api::GetRequestCodeRequest::new();
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
            .interact()
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
    ) -> Result<(mobilecoind_api::TxProposal, u64), String> {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(120);
        pb.set_message("Preparing transaction...");

        // Get our UnspentTxOuts.
        let mut req = mobilecoind_api::GetUnspentTxOutListRequest::new();
        req.set_monitor_id(self.monitor_id.clone());
        req.set_subaddress_index(0);

        let resp = self
            .client
            .get_unspent_tx_out_list(&req)
            .map_err(|err| format!("Unable to get unspent txouts: {}", err))?;
        let utxos = resp.output_list;
        let balance = utxos.iter().map(|utxo| utxo.get_value()).sum::<u64>();

        // Create the outlay
        let mut outlay = mobilecoind_api::Outlay::new();
        outlay.set_value(request_payload.value);
        outlay.set_receiver(mobilecoind_api::PublicAddress::from(
            &request_payload.into(),
        ));

        // Construct the tx
        let mut req = mobilecoind_api::GenerateTxRequest::new();
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
}

/// Helper method for converting a u64 picomob value into human-readable form.
fn u64_to_mob_display(val: u64) -> String {
    let mut decimal_val: Decimal = val.into();

    let kilo_mob = Decimal::from_scientific("1000e12").unwrap();
    let mob = Decimal::from_scientific("1e12").unwrap();
    let micro_mob = Decimal::from_scientific("1e6").unwrap();

    if val == 0 {
        "0 MOB".to_owned()
    } else if decimal_val >= kilo_mob {
        decimal_val /= kilo_mob;
        format!("{:.3} kMOB", decimal_val)
    } else if decimal_val >= mob {
        decimal_val /= mob;
        format!("{:.3} MOB", decimal_val)
    } else if decimal_val >= micro_mob {
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
        assert_eq!(u64_to_mob_display(1), "1 pMOB");
        assert_eq!(u64_to_mob_display(123), "123 pMOB");

        assert_eq!(u64_to_mob_display(MOB - 1), "999999.999 µMOB");
        assert_eq!(u64_to_mob_display(MOB), "1.000 MOB");
        assert_eq!(u64_to_mob_display(MOB + 1), "1.000 MOB");
        assert_eq!(u64_to_mob_display(MOB + 100_000_000), "1.000 MOB");
        assert_eq!(u64_to_mob_display(MOB + 1_000_000_000), "1.001 MOB");

        assert_eq!(u64_to_mob_display(MOB * 1000), "1.000 kMOB");
        assert_eq!(u64_to_mob_display((MOB * 1000) + 1), "1.000 kMOB");
        assert_eq!(u64_to_mob_display((MOB * 1000) + MOB), "1.001 kMOB");
    }
}
