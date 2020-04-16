use dialoguer::{theme::ColorfulTheme, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use mc_b58_payloads::payloads::RequestPayload;
use rust_decimal::{prelude::ToPrimitive, Decimal};
use std::{fmt, str::FromStr};

fn main() {
    TestnetClient::new().run();
}

enum Command {
    Send,
    Receive,
    CheckBalance,
    Quit,
}
impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Send => write!(f, "Pay a bill"),
            Command::Receive => write!(f, "Create a bill"),
            Command::CheckBalance => write!(f, "Check balance"),
            Command::Quit => write!(f, "Quit"),
        }
    }
}

struct TestnetClient;

impl TestnetClient {
    pub fn new() -> Self {
        TestnetClient {}
    }

    pub fn run(&self) {
        Self::print_intro();

        // let root_entropy = Self::get_root_entropy();
        // self.add_monitor_and_wait_for_sync(&root_entropy);

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
                Command::CheckBalance => todo!(),
                Command::Quit => break,
            }
        }
    }

    fn print_intro() {
        let intro = r#"
**********************************************************************

                 Welcome to the MobileCoin TestNet

**********************************************************************

You are now connected to: testnet-west.mobilecoin.com:444

Please enter the 32 byte root entropy for an account. If you received an email with an allocation of TestNet mobilecoins, this is the hexadecimal string we sent you. It should look something like

        dc74edf1d8892dfdf49d6db5d3d4e873665c2dd400c0955dd9729571826a26be
"#;
        println!("{}", intro);
    }

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
            .with_prompt("Enter your root entropy")
            .interact()
            .expect("failed getting root entropy")
            .0
    }

    fn add_monitor_and_wait_for_sync(&self, entropy: &[u8; 32]) {
        let num_blocks = 5; // TODO get from mobilecoind

        let pb = ProgressBar::new(num_blocks);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "Syncing account... {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .progress_chars("#>-"),
        );

        let mut blocks_synced = 0;
        while blocks_synced < num_blocks {
            pb.set_position(blocks_synced);
            std::thread::sleep(std::time::Duration::from_millis(100));
            blocks_synced += 1;
        }
    }

    fn print_balance(&self) {
        println!();
        println!("        >>> Your balance is now 500.000 MOB <<<"); // TODO
        println!();
    }

    fn send(&self) {
        // Print intro text.
        println!(
            r#"
Please enter a payment request code. If you received an email with an allocation of TestNet mobilecoins, this is the longer alphanumeric string. It should look something like

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
        loop {
            println!();
            if request_code.memo.is_empty() {
                println!(
                    "This request code is a bill for {} MOB.",
                    request_code.value
                ); // TODO mob conversion
            } else {
                println!(
                    "This request code is a bill for {} MOB. It includes the memo:",
                    request_code.value
                ); // TODO mob conversion
                println!();
                println!("{}", request_code.memo);
                println!();
            }

            // TODO construct TX to figure out the fee.
            // TODO mob conversion
            let fee = 12345;
            let remaining_balance = 66666;
            println!("You will be charged a fee of {} mMOB to send this payment. Your remaining balance after paying this bill will be {} MOB.", fee, remaining_balance);
            println!();

            println!("Please select from the following available options:");
            let selection = Select::with_theme(&ColorfulTheme::default())
                .default(0)
                .items(&[
                    format!("Send payment of {} MOB", request_code.value),
                    "Change payment amount".to_owned(),
                    "Cancel payment".to_owned(),
                ])
                .interact()
                .unwrap();
            match selection {
                0 => {
                    break;
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
        }

        // Send payment
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(120);
        pb.set_message("Sending payment...");
        std::thread::sleep(std::time::Duration::from_secs(1));
        pb.set_message("Waiting for payment to complete...");
        std::thread::sleep(std::time::Duration::from_secs(4));
        pb.finish_with_message("Done");

        println!("Payment was successful!");
        println!();
    }

    fn receive(&self) {
        println!("You can create a request code to share with another MobileCoin user as a bill to receive a payment. You can meet other TestNet users and share request codes online at the MobileCoin forum.");
        println!();

        let amount = Self::input_mob(
            "How many mobilecoins would you like to receive (in MOB)?",
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

        // TODO
        let view_key = [0; 32];
        let spend_key = [0; 32];
        match RequestPayload::new_v3(&view_key, &spend_key, "", amount, &memo) {
            Ok(payload) => {
                println!("Your request code is:");
                println!();
                println!("        {}", payload.encode());
                println!();
            }
            Err(err) => {
                println!("Error creating request code: {}", err);
            }
        }
    }

    fn input_mob(prompt: &str, default: u64) -> u64 {
        // TODO mob stuff
        Input::<Decimal>::new()
            .with_prompt(prompt)
            .default(default.into()) // TODO MOB
            .interact()
            .expect("failed getting request code")
            .to_u64()
            .expect("failed converting to u64")
    }
}
