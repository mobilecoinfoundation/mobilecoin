use clap::Parser;
use mc_consensus_scp::QuorumSet;

#[derive(Debug, Parser)]
#[clap(
    name = "light_client_verifier",
    about = "Validates blocks without needing to sync the entire blockchain"
)]
pub struct LightClientVerifierConfig {
    #[clap(long, value_parser = parse_quorum_set_from_json, env = "MC_QUORUM_SET")]
    quorum_set: QuorumSet,
}

fn parse_quorum_set_from_json(src: &str) -> Result<QuorumSet<ResponderId>, String> {
    let quorum_set: QuorumSet<ResponderId> = serde_json::from_str(src)
        .map_err(|err| format!("Error parsing quorum set {src}: {err:?}"))?;

    if !quorum_set.is_valid() {
        return Err(format!("Invalid quorum set: {quorum_set:?}"));
    }

    Ok(quorum_set)
}
