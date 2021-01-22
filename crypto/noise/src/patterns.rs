// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The fundamental pattern names defined in noise framework rev. 34

use alloc::vec;

use alloc::vec::Vec;
use core::fmt::{Display, Formatter, Result as FmtResult};

/// An enumeration of message tokens used in a message.
///
/// These tokens are described in
/// [section 7.1](http://noiseprotocol.org/noise.html#handshake-pattern-basics)
/// of the specification.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum Token {
    /// The "e" token
    Ephemeral,
    /// The "s" token
    Static,
    /// The "ee" token
    KexEphemeralEphemeral,
    /// The "es" token
    KexEphemeralStatic,
    /// The "se" token
    KexStaticEphemeral,
    /// The "ss" token
    KexStaticStatic,
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        match self {
            Token::Ephemeral => "e",
            Token::Static => "s",
            Token::KexEphemeralEphemeral => "ee",
            Token::KexEphemeralStatic => "es",
            Token::KexStaticEphemeral => "se",
            Token::KexStaticStatic => "ss",
        }
    }
}

/// An enumeration of static pre-share tokens for a given pattern.
///
/// These tokens are described in
/// [section 7.1](http://noiseprotocol.org/noise.html#handshake-pattern-basics)
/// of the specification, and used to indicate pre-shared tokens.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum PreMessageToken {
    Ephemeral,
    Static,
    EphemeralStatic,
    None,
}

impl AsRef<str> for PreMessageToken {
    fn as_ref(&self) -> &str {
        match self {
            PreMessageToken::Ephemeral => "e",
            PreMessageToken::Static => "s",
            PreMessageToken::EphemeralStatic => "e, s",
            PreMessageToken::None => "",
        }
    }
}

/// A message pattern lists the tokens within a given message, in order of
/// appearance.
///
/// Message patterns are described as a sequence of message tokens in
/// [section 7.1](http://noiseprotocol.org/noise.html#handshake-pattern-basics)
/// of the specification. It is implied, but not directly stated, that these
/// patterns include directionality.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub enum MessagePattern {
    /// An initiator message, e.g. "-> e, s"
    Initiator(Vec<Token>),
    /// A responder's message, e.g. "<- e, ee, se, s, es"
    Responder(Vec<Token>),
}

/// A message pattern will be printed as a string like "<- e, ee, se, s, es"
impl Display for MessagePattern {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            MessagePattern::Initiator(tokens) => {
                write!(f, "->")?;
                let mut first = true;
                for token in tokens {
                    if !first {
                        write!(f, ",")?;
                    }
                    write!(f, " {}", token.as_ref())?;
                    first = false;
                }
            }
            MessagePattern::Responder(tokens) => {
                write!(f, "<-")?;
                let mut first = true;
                for token in tokens {
                    if !first {
                        write!(f, ",")?;
                    }
                    write!(f, " {}", token.as_ref())?;
                    first = false;
                }
            }
        }
        Ok(())
    }
}

/// An interface used by handshake pattern types.
///
/// Handshake patterns are defined in
/// [section 7.1](http://noiseprotocol.org/noise.html#handshake-pattern-basics)
/// of the specification, and they are what's typically defined as the "noise
/// handshake", e.g., the pattern:
///
/// ```txt
/// XX:
///   -> e
///   <- e, ee, s, es
///   -> s, se
/// ```
///
/// describes an exchange that is similar in feel (and encryption) to
/// [SIGMA-I](http://webee.technion.ac.il/~hugo/sigma-pdf.pdf), albeit with
/// MAC instead of a digital signature.
pub trait HandshakePattern: Display {
    /// Get the pattern name as a static string, e.g. "IX"
    fn name() -> &'static str;
    /// Get the initiator's pre-message pattern
    fn initiator_premsg() -> PreMessageToken;
    /// Get the responder's pre-message pattern
    fn responder_premsg() -> PreMessageToken;
    /// Get the message patterns for handshake, in reverse order.
    fn reverse_messages() -> Vec<MessagePattern>;
}

macro_rules! impl_handshake_patterns {
    ($($name:ident, $strname:literal, $initiator_premsg:expr, $responder_premsg:expr, $reverse_messages:expr;)*) => {$(
        /// The defined handshake pattern has
        #[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl HandshakePattern for $name {
            fn name() -> & 'static str {
                $strname
            }

            fn initiator_premsg() -> PreMessageToken {
                $initiator_premsg
            }

            fn responder_premsg() -> PreMessageToken {
                $responder_premsg
            }

            fn reverse_messages() -> Vec < MessagePattern > {
                $reverse_messages
            }
        }

        /// A handshake pattern is printed as it appears.
        ///
        /// ```txt
        /// IX
        ///   -> e, s
        ///   <- e, ee, se, s, es
        /// ```
        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}:\n", Self::name())?;
                if Self::initiator_premsg() != PreMessageToken::None {
                    write!(f, "  -> {}\n", Self::initiator_premsg().as_ref())?;
                }
                if Self::responder_premsg() != PreMessageToken::None {
                    write!(f, "  <- {}\n", Self::responder_premsg().as_ref())?;
                }
                if Self::responder_premsg() != PreMessageToken::None
                    || Self::initiator_premsg() != PreMessageToken::None
                {
                    write!(f, "  ...\n")?;
                }

                for msg in Self::reverse_messages().iter().rev() {
                    write!(f, "  {}\n", msg)?;
                }

                Ok(())
            }
        }
    )*}
}

// Note: the messages are in reverse order, since they are used as a fifo,
// but the tokens are not, since they are simply iterated for each message.
impl_handshake_patterns! {
    HandshakeIX, "IX", PreMessageToken::None, PreMessageToken::None, vec![
        // msg 2: response
        MessagePattern::Responder(vec![
            // token 1
            Token::Ephemeral,
            // token 2
            Token::KexEphemeralEphemeral,
            // token 3
            Token::KexStaticEphemeral,
            // token 4
            Token::Static,
            // token 5
            Token::KexEphemeralStatic,
        ]),
        // msg 1: request
        MessagePattern::Initiator(vec![Token::Ephemeral, Token::Static]),
    ];
    HandshakeNX, "NX", PreMessageToken::None, PreMessageToken::None, vec![
        // msg 2: response
        MessagePattern::Responder(vec![
            // token 1
            Token::Ephemeral,
            // token 2
            Token::KexEphemeralEphemeral,
            // token 3
            Token::Static,
            // token 4
            Token::KexEphemeralStatic,
        ]),
        // msg 1: request
        MessagePattern::Initiator(vec![Token::Ephemeral]),
    ];
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, string::String};

    #[test]
    fn display() {
        assert_eq!(
            format!("{}", HandshakeIX::default()),
            String::from("IX:\n  -> e, s\n  <- e, ee, se, s, es\n")
        );

        assert_eq!(
            format!("{}", HandshakeNX::default()),
            String::from("NX:\n  -> e\n  <- e, ee, s, es\n")
        );
    }
}
