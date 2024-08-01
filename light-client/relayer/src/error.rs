use displaydoc::Display;
use mc_watcher::error::WatcherDBError;

#[derive(Debug, Display)]
pub enum Error {
    /// Thread join error
    ThreadJoin,

    /// Light client verifeir: {0}
    LightClientVerifer(mc_light_client_verifier::Error),

    /// WatcherDb: {0}
    WatcherDb(WatcherDBError),
}

impl From<WatcherDBError> for Error {
    fn from(src: WatcherDBError) -> Self {
        Self::WatcherDb(src)
    }
}

impl From<mc_light_client_verifier::Error> for Error {
    fn from(src: mc_light_client_verifier::Error) -> Self {
        Self::LightClientVerifer(src)
    }
}
