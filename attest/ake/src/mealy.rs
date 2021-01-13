// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A set of traits used to implement a rusty deterministic finite state
//! transducer

use rand_core::{CryptoRng, RngCore};

/// A marker trait indicating a particular structure is a valid input for a
/// transducer
pub trait Input {}

/// A marker trait indicating a particular structure is a valid output from a
/// transducer
pub trait Output {}

/// A marker trait indicating a particular structure is a valid state for a
/// transducer
pub trait State {}

/// A [Mealy Machine](https://en.wikipedia.org/wiki/Mealy_machine) is a
/// deterministic finite state transducer which operates to translate inputs
/// into outputs utilizing intermediate states.
///
/// The intent here is that each input, state, and output are defined as their
/// own data structure, and implementing this trait on a given state structure
/// for a given input serves to define the combination transition and output
/// functions.
pub trait Transition<NextState: State, InputEvent: Input, OutputEvent: Output>: State {
    type Error: Sized;

    /// Consume this state and an input to produce a new state and output.
    ///
    /// Resulting states may not have transitions defined for them.
    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        input: InputEvent,
    ) -> Result<(NextState, OutputEvent), Self::Error>;
}
