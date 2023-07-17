use displaydoc::Display;
use mc_watcher::error::WatcherDBError;

#[derive(Debug, Display)]
pub enum Error {
    /// Thread join error
    ThreadJoin,
    
    /// Burned transaction verification error
    InvalidBurnedTx(mc_light_client_verifier::Error),

    /// Unable to get block signatures from watcher
    WatcherError(WatcherDBError),
}

impl From<WatcherDBError> for Error {
    fn from(src: WatcherDBError) -> Self {
        match src {
            _ => Self::WatcherError(src),
        }
    }
}

impl From<mc_light_client_verifier::Error> for Error {
    fn from(src: mc_light_client_verifier::Error) -> Self {
        match src {
            _ => Self::InvalidBurnedTx(src),
        }
    }
}