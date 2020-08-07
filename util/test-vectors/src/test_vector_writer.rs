use crate::TestVector;
use serde::ser;
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

#[derive(Debug)]
pub enum Error {
    Json(serde_json::error::Error),
    File(String, std::io::Error),
    Io(std::io::Error),
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Self {
        Self::Json(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct TestVectorWriter<T: TestVector> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: TestVector + ser::Serialize> TestVectorWriter<T> {
    pub fn write_jsonl(dir: &str) -> Result<(), Error> {
        let filepath = format!("{}/{}/{}.jsonl", dir, T::MODULE_SUBDIR, T::FILE_NAME);

        if let Some(dir) = Path::new(&filepath).parent() {
            fs::create_dir_all(dir)
                .map_err(|err| Error::File(format!("{}", dir.display()), err))?;
        }
        let mut f = File::create(filepath.clone()).map_err(|err| Error::File(filepath, err))?;

        for obj in T::generate() {
            serde_json::to_writer(BufWriter::new(f.try_clone()?), &obj)?;
            f.write_all(b"\n")?;
        }
        f.flush()?;
        Ok(())
    }
}
