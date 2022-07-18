pub struct MintAuditorHttpService {
    /// Mint auditor database.
    mint_auditor_db: MintAuditorDb,

    /// Logger.
    logger: Logger,
}
impl MintAuditorHttpService {
    pub fn new(mint_auditor_db: MintAuditorDb, logger: Logger) -> Self {
        Self {
            mint_auditor_db,
            logger,
        }
    }
}
