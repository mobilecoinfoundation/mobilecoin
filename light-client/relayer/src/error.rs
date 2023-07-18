use displaydoc::Display;
use mc_watcher::error::WatcherDBError;

#[derive(Debug, Display)]
pub enum Error {
    /// Thread join error
    ThreadJoin,

    /// Burned transaction verification error
    InvalidBurnedTx(mc_light_client_verifier::Error),

    /// WatcherDb: {0}
    WatcherDb(WatcherDBError),
}

impl From<WatcherDBError> for Error {
    fn from(src: WatcherDBError) -> Self {
        Self::Watcher(src)
    }
}

impl From<mc_light_client_verifier::Error> for Error {
    fn from(src: mc_light_client_verifier::Error) -> Self {
        Self::InvalidBurnedTx(src)
    }
}
