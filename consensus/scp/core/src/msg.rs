// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Message types for the phases of SCP.
use crate::{
    core_types::{Ballot, GenericNodeId, SlotIndex, Value},
    msg::Topic::*,
    quorum_set::QuorumSet,
};

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
};
use core::{
    cmp,
    cmp::Ordering,
    fmt,
    fmt::{Debug, Display, Formatter},
    hash::{BuildHasher, Hash, Hasher},
};
use mc_common::{HashSet, HasherBuilder, NodeID};
use mc_crypto_digestible::Digestible;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// The highest possible ballot counter.
pub const INFINITY: u32 = <u32>::max_value();

/// The contents of a Nominate Message.
#[derive(Clone, Debug, Eq, Hash, Serialize, Deserialize, PartialEq, Digestible)]
pub struct NominatePayload<V: Value> {
    /// Voted values.
    pub X: BTreeSet<V>,

    /// Accepted values.
    pub Y: BTreeSet<V>,
}

impl<V: Value> Ord for NominatePayload<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.Y.len() != other.Y.len() {
            return self.Y.len().cmp(&other.Y.len());
        }
        if self.Y != other.Y {
            return self.Y.cmp(&other.Y);
        }
        if self.X.len() != other.X.len() {
            return self.X.len().cmp(&other.X.len());
        }
        if self.X != other.X {
            return self.X.cmp(&other.X);
        }

        Ordering::Equal
    }
}

impl<V: Value> PartialOrd for NominatePayload<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: Value> NominatePayload<V> {
    /// Create a new NominatePayload.
    ///
    /// # Arguments
    /// * `x` - Values voted nominated.
    /// * `y` - Values accepted nominated.
    pub fn new(x: &HashSet<V>, y: &HashSet<V>) -> Self {
        Self {
            X: x.iter().cloned().collect(),
            Y: y.iter().cloned().collect(),
        }
    }
}

/// The contents of a Prepare Message.
///
/// See [IETF Draft 0](https://tools.ietf.org/html/draft-mazieres-dinrg-scp-00#page-7)
#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Hash, Digestible)]
pub struct PreparePayload<V: Value> {
    /// The ballot, containing the current and highest prepare vote.
    pub B: Ballot<V>,

    /// The highest accepted prepared ballot.
    pub P: Option<Ballot<V>>,

    /// Prepared prime: the highest ballot that satisfies the same criteria as
    /// `prepared`, but has a different value than `prepared`.
    pub PP: Option<Ballot<V>>,

    /// The counter for the lowest ballot the sender is attempting to confirm.
    pub CN: u32,

    /// The counter for the highest ballot in a sender's quorum for which all
    /// members have sent `prepared` with at least this counter, or
    /// `prepared_prime` with at least this counter.
    pub HN: u32,
}

impl<V: Value> Ord for PreparePayload<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        // "All messages sent by a particular node are totally ordered by
        // (Phi, b, p, p', h) with Phi the most significant and h the least
        // significant field."
        // See p.24 of the [Whitepaper](https://www.stellar.org/papers/stellar-consensus-protocol.pdf).

        if self.B != other.B {
            return self.B.cmp(&other.B);
        }
        if self.P != other.P {
            return self.P.cmp(&other.P);
        }
        if self.PP != other.PP {
            return self.PP.cmp(&other.PP);
        }
        self.HN.cmp(&other.HN)
    }
}

impl<V: Value> PartialOrd for PreparePayload<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The contents of a Commit Message.
///
/// See Commit Message in [IETF Draft 05](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-05.pdf)
#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Hash, Digestible)]
pub struct CommitPayload<V: Value> {
    /// The ballot, containing the current and highest commit vote.
    ///
    /// Note: The value can no longer change, only the counter.
    pub B: Ballot<V>,

    /// The counter of the highest accepted prepared ballot.
    pub PN: u32,

    /// The counter of the lowest ballot for which the node has accepted commit.
    pub CN: u32,

    /// The counter of the highest ballot for which the node has accepted
    /// commit.
    pub HN: u32,
}

impl<V: Value> Ord for CommitPayload<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        // "All messages sent by a particular node are totally ordered by
        // (Phi, b, p, p', h) with Phi the most significant and h the least
        // significant field."
        // See p.24 of the [Whitepaper](https://www.stellar.org/papers/stellar-consensus-protocol.pdf).

        if self.B != other.B {
            return self.B.cmp(&other.B);
        }
        if self.PN != other.PN {
            return self.PN.cmp(&other.PN);
        }
        self.HN.cmp(&other.HN)
    }
}

impl<V: Value> PartialOrd for CommitPayload<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The contents of an Externalize Message.
#[derive(Clone, Debug, Eq, Serialize, Deserialize, PartialEq, Hash, Digestible)]
pub struct ExternalizePayload<V: Value> {
    /// The lowest confirmed committed ballot.
    pub C: Ballot<V>,

    /// The counter of the highest confirmed committed ballot.
    pub HN: u32,
}

impl<V: Value> Ord for ExternalizePayload<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        // "All messages sent by a particular node are totally ordered by
        // (Phi, b, p, p', h) with Phi the most significant and h the least
        // significant field."
        // See p.24 of the [Whitepaper](https://www.stellar.org/papers/stellar-consensus-protocol.pdf).

        self.HN.cmp(&other.HN)
    }
}

impl<V: Value> PartialOrd for ExternalizePayload<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Encapsulates phase of SCP, and contains the appropriate payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Digestible)]
pub enum Topic<V: Value> {
    /// Nominate Messages.
    Nominate(NominatePayload<V>),

    /// Messasges acceptable in both the Nominate and Prepare phase.
    NominatePrepare(NominatePayload<V>, PreparePayload<V>),

    /// Prepare Messages.
    Prepare(PreparePayload<V>),

    /// Commit Messages.
    Commit(CommitPayload<V>),

    /// Externalize Messages.
    Externalize(ExternalizePayload<V>),
}

impl<V: Value> Ord for Topic<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            Nominate(ref payload) => {
                match other {
                    Nominate(ref other_payload) => payload.cmp(other_payload),

                    // NOMINATE messages are less than all other messages
                    _ => Ordering::Less,
                }
            }

            NominatePrepare(ref nominate_payload, ref prepare_payload) => match other {
                Nominate(_) => Ordering::Greater,

                NominatePrepare(ref other_nominate_payload, ref other_prepare_payload) => {
                    if prepare_payload != other_prepare_payload {
                        prepare_payload.cmp(other_prepare_payload)
                    } else {
                        nominate_payload.cmp(other_nominate_payload)
                    }
                }

                _ => Ordering::Less,
            },

            Prepare(ref payload) => match other {
                Nominate(_) => Ordering::Greater,
                NominatePrepare(_, _) => Ordering::Greater,

                Prepare(ref other_payload) => payload.cmp(other_payload),

                _ => Ordering::Less,
            },

            Commit(ref payload) => match other {
                Nominate(_) => Ordering::Greater,
                NominatePrepare(_, _) => Ordering::Greater,
                Prepare(_) => Ordering::Greater,

                Commit(ref other_payload) => payload.cmp(other_payload),

                _ => Ordering::Less,
            },

            Externalize(ref payload) => match other {
                Externalize(other_payload) => payload.cmp(other_payload),

                _ => Ordering::Greater,
            },
        }
    }
}

impl<V: Value> PartialOrd for Topic<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The Messsage type for Consensus.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Digestible)]
pub struct Msg<V: Value, ID: GenericNodeId = NodeID> {
    /// ID of the node sending this message.
    pub sender_id: ID,

    /// The slot that this message is about.
    pub slot_index: SlotIndex,

    /// Quorum slices of the sending node.
    pub quorum_set: QuorumSet<ID>,

    /// The "payload" of the message.
    pub topic: Topic<V>,
}

impl<
        V: Value,
        ID: GenericNodeId
            + Clone
            + Debug
            + Display
            + Serialize
            + DeserializeOwned
            + Eq
            + PartialEq
            + Hash,
    > Msg<V, ID>
{
    /// Creates a new Msg.
    pub fn new(
        sender_id: ID,
        quorum_set: QuorumSet<ID>,
        slot_index: SlotIndex,
        topic: Topic<V>,
    ) -> Self {
        Self {
            sender_id,
            slot_index,
            quorum_set,
            topic,
        }
    }

    /// Basic validation of Msg structure.
    pub fn validate(&self) -> Result<(), String> {
        if !self.quorum_set.is_valid() {
            return Err(format!("Invalid quorum set {:?}", self.quorum_set));
        }

        let validate_nominate = |payload: &NominatePayload<V>| -> Result<(), String> {
            if payload.X.intersection(&payload.Y).next().is_some() {
                Err(format!("X intersects Y, msg: {}", self))
            } else {
                Ok(())
            }
        };

        let validate_prepare = |payload: &PreparePayload<V>| -> Result<(), String> {
            if let Some(P) = &payload.P {
                if payload.B < *P {
                    return Err(format!("B < P, msg: {}", self));
                }

                if let Some(PP) = &payload.PP {
                    if *PP >= *P {
                        return Err(format!("PP >= P, msg: {}", self));
                    }
                }
            }

            if payload.CN > payload.HN {
                return Err(format!("CN > HN, msg: {}", self));
            }
            if payload.HN > payload.B.N {
                return Err(format!("HN > BN, msg: {}", self));
            }

            Ok(())
        };

        match self.topic {
            Nominate(ref payload) => {
                validate_nominate(payload)?;
            }

            NominatePrepare(ref nominate_payload, ref prepare_payload) => {
                validate_nominate(nominate_payload)?;
                validate_prepare(prepare_payload)?;
            }

            Prepare(ref payload) => {
                validate_prepare(payload)?;
            }

            Commit(ref payload) => {
                if payload.CN > payload.HN {
                    return Err(format!("CN > HN, msg: {}", self));
                }
            }

            Externalize(_) => {}
        }

        Ok(())
    }

    /// Return the ballot counter (if any) used for checking if this node has
    /// fallen behind other nodes.
    ///
    /// "Note that for the purposes of determining whether a quorum has
    /// a particular "ballot.counter", a node considers "ballot" fields
    /// in "SCPPrepare" and "SCPCommit" messages. It also considers
    /// "SCPExternalize" messages to convey an implicit
    /// "ballot.counter" of "infinity"."
    /// (p.14 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
    ///
    /// "Note that the blocking threshold may include ballots from "SCPCommit"
    /// messages *as well as "SCPExternalize" messages, which implicitly
    /// have an infinite ballot counter." (p.15 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
    pub fn bN(&self) -> u32 {
        match self.topic {
            Nominate(_) => 0,
            NominatePrepare(_, ref payload) => payload.B.N,
            Prepare(ref payload) => payload.B.N,
            Commit(ref payload) => payload.B.N,
            Externalize(_) => INFINITY,
        }
    }

    /// Returns the set of values that `self` votes or accepts as nominated.
    pub fn votes_or_accepts_nominated(&self) -> Option<BTreeSet<V>> {
        match self.topic {
            Nominate(ref payload) | NominatePrepare(ref payload, _) => {
                Some(payload.X.union(&payload.Y).cloned().collect())
            }
            _ => None,
        }
    }

    /// Returns the set of values that e accepts as nominated.
    pub fn accepts_nominated(&self) -> Option<&BTreeSet<V>> {
        match self.topic {
            Nominate(ref payload) | NominatePrepare(ref payload, _) => Some(&payload.Y),
            _ => None,
        }
    }

    /// Returns the set of ballots for which `self` votes or accepts "prepared".
    pub fn votes_or_accepts_prepared(&self) -> HashSet<Ballot<V>> {
        let mut result: HashSet<Ballot<V>> = Default::default();

        match self.topic {
            NominatePrepare(_, ref payload) | Prepare(ref payload) => {
                // "vote-or-accept prepare(ballot)"
                // (p.13 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                result.insert(payload.B.clone());
                // If "prepared != NULL": "accept prepare(prepared)"
                // (p.13 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                if let Some(P) = &payload.P {
                    result.insert(P.clone());

                    // If "preparedPrime != NULL": "accept prepare(preparedPrime)"
                    // (p.13 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                    if let Some(PP) = &payload.PP {
                        result.insert(PP.clone());
                    }
                }
            }
            Commit(ref payload) => {
                // "vote-or-accept prepare(<infinity, ballot.value>)"
                // (p.17 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                result.insert(Ballot::new(INFINITY, &payload.B.X));
            }
            Externalize(ref payload) => {
                // "vote-or-accept prepare(<infinity, ballot.value>)"
                result.insert(Ballot::new(INFINITY, &payload.C.X));
            }
            _ => {}
        }

        result
    }

    /// Returns the set of ballots that `self` accepts as prepared.
    pub fn accepts_prepared(&self) -> HashSet<Ballot<V>> {
        let mut result: HashSet<Ballot<V>> = Default::default();

        match self.topic {
            NominatePrepare(_, ref payload) | Prepare(ref payload) => {
                // If "prepared != NULL": "accept prepare(prepared)"
                // (p.13 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                if let Some(P) = &payload.P {
                    result.insert(P.clone());

                    // If "preparedPrime != NULL": "accept prepare(preparedPrime)"
                    // (p.13 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                    if let Some(PP) = &payload.PP {
                        result.insert(PP.clone());
                    }
                }
            }

            Commit(ref payload) => {
                // "accept prepare(<preparedCounter, ballot.value>)"
                // (p.17 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                result.insert(Ballot::new(payload.PN, &payload.B.X));
            }

            Externalize(ref payload) => {
                // "confirm prepare(<infinity, commit.value>)"
                // (p.18 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf))
                result.insert(Ballot::new(INFINITY, &payload.C.X));
            }

            _ => {}
        }

        result
    }

    /// Tells whether `self` votes commit(b) or accepts commit(b) for any ballot
    /// b whose value is `value` and whose counter is in the range [min, max]
    /// (inclusive). If so, returns the new min/max that is the overlap
    /// between the input and what `self` votes for or accepts.
    pub fn votes_or_accepts_commits(&self, value: &[V], min: u32, max: u32) -> Option<(u32, u32)> {
        assert!(min <= max);

        // Range of ballot counters for which this message implies "vote_or_accept
        // commit" for these values.
        let range = match self.topic {
            NominatePrepare(_, ref payload) | Prepare(ref payload) => {
                if &payload.B.X[..] == value && payload.CN != 0 {
                    // If "cCounter != 0":
                    //  "vote commit(<n, ballot.value>)" for every "cCounter <= n <= hCounter".
                    Some((payload.CN, payload.HN))
                } else {
                    None
                }
            }
            Commit(ref payload) => {
                if &payload.B.X[..] == value {
                    // "vote commit <n, B.X>" for all n >= CN.
                    Some((payload.CN, INFINITY))
                } else {
                    None
                }
            }
            Externalize(ref payload) => {
                if &payload.C.X[..] == value {
                    // "accept commit(n, commit.value)" for every "n >= commit.counter"
                    Some((payload.C.N, INFINITY))
                } else {
                    None
                }
            }
            _ => None,
        };

        range.and_then(|(a, b)| {
            // If [a,b] intersects with with [min,max], return the intersection.
            let intersects = a <= max && min <= b;
            if intersects {
                let intersection: (u32, u32) = (cmp::max(a, min), cmp::min(b, max));
                assert!(intersection.0 <= intersection.1);
                Some(intersection)
            } else {
                None
            }
        })
    }

    /// Tells whether `self` accepts commit(b) for any ballot b whose value is v
    /// and whose counter is in the range [min,max] (inclusive). If so,
    /// returns the new min/max that is the overlap between the input and
    /// what e accepts.
    pub fn accepts_commits(&self, value: &[V], min: u32, max: u32) -> Option<(u32, u32)> {
        assert!(min <= max);
        let range = match self.topic {
            Commit(ref payload) => {
                if &payload.B.X[..] == value {
                    // "accept commit(<n, ballot.value>)" for every "cCounter <= n <= hCounter".
                    Some((payload.CN, payload.HN))
                } else {
                    None
                }
            }
            Externalize(ref payload) => {
                if &payload.C.X[..] == value {
                    // "accept commit(<n, commit.value>)" for every "n >= commit.counter"
                    Some((payload.C.N, INFINITY))
                } else {
                    None
                }
            }
            _ => None,
        };

        range.and_then(|(a, b)| {
            // If [a,b] intersects with with [min,max], return the intersection.
            let intersects = a <= max && min <= b;
            if intersects {
                let intersection: (u32, u32) = (cmp::max(a, min), cmp::min(b, max));
                assert!(intersection.0 <= intersection.1);
                Some(intersection)
            } else {
                None
            }
        })
    }

    /// Returns all the values referenced by this message.
    pub fn values(&self) -> BTreeSet<V> {
        let mut values: BTreeSet<V> = Default::default();
        match &self.topic {
            Nominate(payload) => {
                values.extend(payload.X.clone());
                values.extend(payload.Y.clone());
            }
            NominatePrepare(nominate_payload, prepare_payload) => {
                values.extend(nominate_payload.X.clone());
                values.extend(nominate_payload.Y.clone());
                values.extend(prepare_payload.B.X.clone());
                if let Some(P) = &prepare_payload.P {
                    values.extend(P.X.clone());
                }
                if let Some(PP) = &prepare_payload.PP {
                    values.extend(PP.X.clone());
                }
            }
            Prepare(payload) => {
                values.extend(payload.B.X.clone());
                if let Some(P) = &payload.P {
                    values.extend(P.X.clone());
                }
                if let Some(PP) = &payload.PP {
                    values.extend(PP.X.clone());
                }
            }
            Commit(payload) => {
                values.extend(payload.B.X.clone());
            }
            Externalize(payload) => {
                values.extend(payload.C.X.clone());
            }
        };
        values
    }
}

impl<V: Value, ID: GenericNodeId> fmt::Display for Msg<V, ID> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let format_opt_ballot = |b: &Option<Ballot<V>>| match b {
            None => "<>".to_string(),
            Some(b) => format!("{}", b),
        };

        // Returns "<set.len, hash(set)>".
        let hasher_builder = HasherBuilder::default();
        let format_b_tree_set = |b_tree_set: &BTreeSet<V>| {
            let hash = {
                let mut hasher = hasher_builder.build_hasher();
                b_tree_set.hash(&mut hasher);
                hasher.finish()
            };
            format!("<{}:{}>", b_tree_set.len(), hash)
        };

        let topic = match &self.topic {
            Nominate(ref payload) => format!(
                "NOM X={}, Y={}",
                format_b_tree_set(&payload.X),
                format_b_tree_set(&payload.Y)
            ),
            NominatePrepare(ref nominate_payload, ref prepare_payload) => format!(
                "NOM/PREP X={}, Y={}, B={}, P={}, PP={}, HN={}, CN={}",
                format_b_tree_set(&nominate_payload.X),
                format_b_tree_set(&nominate_payload.Y),
                prepare_payload.B,
                format_opt_ballot(&prepare_payload.P),
                format_opt_ballot(&prepare_payload.PP),
                prepare_payload.HN,
                prepare_payload.CN
            ),
            Prepare(ref prepare_payload) => format!(
                "PREP B={}, P={}, PP={}, HN={}, CN={}",
                prepare_payload.B,
                format_opt_ballot(&prepare_payload.P),
                format_opt_ballot(&prepare_payload.PP),
                prepare_payload.HN,
                prepare_payload.CN
            ),
            Commit(ref payload) => format!(
                "COMMIT B={}, PN={}, HN={}, CN={}",
                payload.B, payload.PN, payload.HN, payload.CN
            ),
            Externalize(ref payload) => format!("EXT C={} HN={}", payload.C, payload.HN),
        };

        write!(f, "(V={} I={} {})", self.sender_id, self.slot_index, topic)
    }
}

#[cfg(test)]
mod msg_tests {
    use super::*;
    use crate::test_utils::test_node_id;
    use core::iter::FromIterator;
    use rand::seq::SliceRandom;

    #[test]
    /// Prepare implies "vote_or_accept prepare" for B, P, and PP.
    fn test_votes_or_accepts_prepared_with_prepare_topic() {
        let ballot = Ballot::new(10, &["meow"]);
        let prepared = Ballot::new(7, &["meow"]);
        let prepared_prime = Ballot::new(6, &["walrus"]);

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Prepare(PreparePayload {
                B: ballot.clone(),
                P: Some(prepared.clone()),
                PP: Some(prepared_prime.clone()),
                CN: 0,
                HN: 0,
            }),
        );

        let votes_or_accepts_prepared = msg.votes_or_accepts_prepared();

        // ballot, prepared, and prepared_prime have all been voted or accepted
        // prepared.
        assert_eq!(3, votes_or_accepts_prepared.len());
        assert!(votes_or_accepts_prepared.contains(&ballot));
        assert!(votes_or_accepts_prepared.contains(&prepared));
        assert!(votes_or_accepts_prepared.contains(&prepared_prime));
    }

    #[test]
    /// Commit implies "vote_or_accept prepare" for: <infinity, B.X>.
    fn test_votes_or_accepts_prepared_with_commit_topic() {
        let ballot = Ballot::new(10, &["meow"]);

        // Implies:
        // * "vote-or-accept prepare(<infinity, ballot.value>)".
        // * "accept prepare(<preparedCounter, ballot.value>)"
        // * "confirm prepare(<hCounter, ballot.value>)"
        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Commit(CommitPayload {
                B: ballot.clone(),
                PN: 9,
                CN: 7,
                HN: 8,
            }),
        );

        let votes_or_accepts_prepared = msg.votes_or_accepts_prepared();
        let expected = HashSet::from_iter([Ballot::new(INFINITY, &ballot.X)]);
        assert_eq!(votes_or_accepts_prepared, expected);
    }

    #[test]
    /// Externalize implies "vote_or_accept prepare <infinity, C.X>".
    fn test_votes_or_accepts_prepared_with_externalize_topic() {
        let ballot = Ballot::new(5, &["meow"]);

        // Implies "accept prepare(<infinity, commit.value>)".
        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Externalize(ExternalizePayload {
                C: ballot.clone(),
                HN: 8,
            }),
        );

        let votes_or_accepts_prepared = msg.votes_or_accepts_prepared();
        let expected = HashSet::from_iter([Ballot::new(INFINITY, &ballot.X)]);

        assert_eq!(votes_or_accepts_prepared, expected);
    }

    #[test]
    /// Prepare implies "accepts prepared" for P (if any), and PP (if any).
    fn test_accepts_prepared_with_prepare_topic() {
        // A Msg that implies an "accepts prepared" for P and PP.
        {
            let ballot = Ballot::new(10, &["meow"]);

            // highest accepted prepared ballot
            let prepared = Ballot::new(7, &["meow"]);

            // highest accepted prepared < prepared with with value != ballot.value
            let prepared_prime = Ballot::new(6, &["walrus"]);

            let msg = Msg::new(
                test_node_id(1),
                QuorumSet::empty(),
                1,
                Prepare(PreparePayload {
                    B: ballot.clone(),
                    P: Some(prepared.clone()),
                    PP: Some(prepared_prime.clone()),
                    CN: 0, /* c_counter -> if h_counter > 0, and ballot is confirmed prepared,
                            * c_counter = ballot.counter */
                    HN: 0, // h_counter -> highest confirmed prepared counter
                }),
            );

            let accepts_prepared = msg.accepts_prepared();
            let expected = HashSet::from_iter([prepared, prepared_prime]);
            assert_eq!(accepts_prepared, expected);
        }

        // A Msg that implies no accepted prepared ballot.
        {
            let msg = Msg::new(
                test_node_id(1),
                QuorumSet::empty(),
                1,
                Prepare(PreparePayload {
                    B: Ballot::new(10, &["meow"]), // ballot
                    P: None,                       // prepared -> highest accepted prepared ballot
                    PP: None,                      /* prepared_prime -> highest accepted prepared
                                                    * < prepared with with
                                                    * value != ballot.value */
                    CN: 0, /* c_counter -> if h_counter > 0, and ballot is confirmed prepared,
                            * c_counter = ballot.counter */
                    HN: 0, // h_counter -> highest confirmed prepared counter
                }),
            );

            let accepts_prepared = msg.accepts_prepared();
            assert!(accepts_prepared.is_empty());
        }
    }

    #[test]
    // Commit implies "accept prepare(<preparedCounter, ballot.value>)"
    fn test_accepts_prepared_with_commit_topic() {
        let ballot = Ballot::new(10, &["meow"]);

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Commit(CommitPayload {
                B: ballot.clone(),
                PN: 9,
                CN: 7,
                HN: 8,
            }),
        );

        let accepts_prepared = msg.accepts_prepared();
        let expected = HashSet::from_iter([Ballot::new(9, &ballot.X)]);
        assert_eq!(accepts_prepared, expected);
    }

    #[test]
    /// Externalize implies "accept prepare(<infinity, commit.value>)"
    fn test_accepts_prepared_with_externalize_topic() {
        let ballot = Ballot::new(10, &["meow"]);

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Externalize(ExternalizePayload {
                C: ballot.clone(),
                HN: 8,
            }),
        );

        let accepts_prepared = msg.accepts_prepared();
        let expected = HashSet::from_iter([Ballot::new(INFINITY, &ballot.X)]);
        assert_eq!(accepts_prepared, expected);
    }

    #[test]
    // If "cCounter != 0":
    // "vote commit(<n, ballot.value>)" for every "cCounter <= n <= hCounter".
    fn test_votes_or_accepts_commits_with_prepare_topic() {
        // A PreparePayload that does not imply `vote commit`:
        {
            let msg = Msg::new(
                test_node_id(1),
                QuorumSet::empty(),
                1,
                Prepare(PreparePayload {
                    B: Ballot::new(10, &["meow"]),
                    P: Some(Ballot::new(9, &["meow"])),
                    PP: None,
                    CN: 0,
                    HN: 1,
                }),
            );

            assert_eq!(msg.votes_or_accepts_commits(&["meow"], 0, INFINITY), None);
        }

        // A PreparePayload that implies
        // "vote commit(<n, ballot.value>)" for every "cCounter <= n <= hCounter".
        {
            let c_counter = 1;
            let h_counter = 3;

            let msg = Msg::new(
                test_node_id(1),
                QuorumSet::empty(),
                1,
                Prepare(PreparePayload {
                    B: Ballot::new(5, &["meow"]),
                    P: Some(Ballot::new(3, &["meow"])),
                    PP: None,
                    CN: c_counter,
                    HN: h_counter,
                }),
            );

            assert_eq!(
                msg.votes_or_accepts_commits(&["meow"], 0, INFINITY),
                Some((c_counter, h_counter))
            );
            assert_eq!(msg.votes_or_accepts_commits(&["xxx"], 0, INFINITY), None);
        }
    }

    #[test]
    // Commit implies "vote commit(<n, ballot.value>)" for every "n >= cCounter".
    fn test_votes_or_accepts_commits_with_commit_topic() {
        let c_counter = 7;
        let h_counter = 8;

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Commit(CommitPayload {
                B: Ballot::new(10, &["meow"]),
                PN: 9,
                CN: c_counter,
                HN: h_counter,
            }),
        );

        // Returns None if the values don't match.
        assert_eq!(msg.votes_or_accepts_commits(&["xxx"], 0, INFINITY), None);

        assert_eq!(
            msg.votes_or_accepts_commits(&["meow"], 0, INFINITY),
            Some((c_counter, INFINITY))
        );
    }

    #[test]
    // An ExternalizePayload implies "accept commit(<n, commit.value>)" for every "n
    // >= commit.counter"
    fn test_votes_or_accepts_commits_with_externalize_topic() {
        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Externalize(ExternalizePayload {
                C: Ballot::new(10, &["meow"]),
                HN: 8,
            }),
        );

        // Returns None if the values don't match.
        assert_eq!(msg.votes_or_accepts_commits(&["xxx"], 0, INFINITY), None);

        assert_eq!(
            msg.votes_or_accepts_commits(&["meow"], 0, INFINITY),
            Some((10, INFINITY))
        );
    }

    #[test]
    // A PreparePayload does not imply `accept commit`.
    fn test_accepts_commits_with_prepare_topic() {
        let c_counter = 7;
        let h_counter = 8;

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Prepare(PreparePayload {
                B: Ballot::new(10, &["meow"]),
                P: Some(Ballot::new(9, &["meow"])),
                PP: None,
                CN: c_counter,
                HN: h_counter,
            }),
        );

        assert_eq!(msg.accepts_commits(&["meow"], 0, INFINITY), None);
    }

    #[test]
    // A CommitPayload implies "accept commit(<n, ballot.value>)"
    // for every "cCounter <= n <= hCounter".
    fn test_accepts_commits_with_commit_topic() {
        let c_counter = 7;
        let h_counter = 8;

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Commit(CommitPayload {
                B: Ballot::new(10, &["meow"]),
                PN: 9,
                CN: c_counter,
                HN: h_counter,
            }),
        );

        assert_eq!(
            msg.accepts_commits(&["meow"], 0, INFINITY),
            Some((c_counter, h_counter))
        );
        assert_eq!(msg.accepts_commits(&["xxx"], 0, INFINITY), None);
    }

    #[test]
    // An ExternalizePayload implies "accept commit(<n, commit.value>)" for every "n
    // >= ballot.counter".
    fn test_accepts_commits_with_externalize_topic() {
        let ballot = Ballot::new(5, &["meow"]);

        let msg = Msg::new(
            test_node_id(1),
            QuorumSet::empty(),
            1,
            Externalize(ExternalizePayload {
                C: ballot.clone(),
                HN: 8,
            }),
        );

        assert_eq!(
            msg.accepts_commits(&["meow"], 0, INFINITY),
            Some((ballot.N, INFINITY))
        );
        assert_eq!(msg.accepts_commits(&["xxx"], 0, INFINITY), None);
    }

    #[test]
    // NominatePayload's BTreeSet's that are populated in a random order gets
    // serialized deterministically.
    fn nominatepayload_deterministic_serialize() {
        let values = "kantzzcemc xzbvuwkjae wllqmutprx hkhdtpehmo myfcxwjtim rihkjzfayw ykifmibexv fbyzrjpjte ylbycdyprn cflmqswwrf".split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
        let mut rng = mc_util_test_helper::get_seeded_rng();

        let reference = mc_util_serial::serialize(&NominatePayload {
            X: BTreeSet::from_iter(values.clone()),
            Y: BTreeSet::from_iter(values.clone()),
        })
        .unwrap();

        for _i in 0..100 {
            let mut test_values = values.clone();
            test_values.shuffle(&mut rng);
            let serialized = mc_util_serial::serialize(&NominatePayload {
                X: BTreeSet::from_iter(test_values.clone()),
                Y: BTreeSet::from_iter(test_values.clone()),
            })
            .unwrap();
            assert_eq!(reference, serialized);
        }
    }

    #[test]
    // NominatePayload serialize/deserialize work as expected.
    fn nominatepayload_deserialize_works() {
        let payload = NominatePayload::<u32> {
            X: BTreeSet::from_iter([1, 2, 3]),
            Y: BTreeSet::from_iter([10, 20, 30]),
        };

        let serialized_payload = mc_util_serial::serialize(&payload).unwrap();
        let payload2: NominatePayload<u32> =
            mc_util_serial::deserialize(&serialized_payload).unwrap();

        assert_eq!(payload, payload2);
    }
}
