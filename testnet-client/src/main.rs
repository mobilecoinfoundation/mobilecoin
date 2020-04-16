use dialoguer::{theme::ColorfulTheme, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use mc_b58_payloads::payloads::RequestPayload;
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

    pub fn run(&mut self) {
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
                Command::Receive => todo!(),
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

    fn add_monitor_and_wait_for_sync(&mut self, entropy: &[u8; 32]) {
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

    fn print_balance(&mut self) {
        println!();
        println!("        >>> Your balance is now 500.000 MOB <<<"); // TODO
        println!();
    }

    fn send(&mut self) {
        println!(
            r#"
Please enter a payment request code. If you received an email with an allocation of TestNet mobilecoins, this is the longer alphanumeric string. It should look something like

        3CioMy13rUrFWRCcXMjz4GayaVgRcqpRpz6JXzmryaN2NJjSv2YaKED33iYnUyAMa9vi1XLRoW8xVuzzJTsc6MArq5NBDHMZXDtYRSrA9AjFdfv6QzLF21AWc36yXcsiqGZkgLKk
"#
        );

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

        let request_code = Input::<WrappedRequestPayload>::new()
            .with_prompt("Enter your request code")
            .allow_empty(true)
            .interact()
            .expect("failed getting request code")
            .0;
    }
}
