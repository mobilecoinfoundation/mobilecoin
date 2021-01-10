use datatest::DataTestCaseDesc;
use serde::{de, ser};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

pub trait TestVector: Sized {
    const FILE_NAME: &'static str;
    const MODULE_SUBDIR: &'static str;

    fn from_jsonl(dir: &str) -> Vec<DataTestCaseDesc<Self>>
    where
        for<'a> Self: de::Deserialize<'a>,
    {
        let filename = format!("{}/{}/{}.jsonl", dir, Self::MODULE_SUBDIR, Self::FILE_NAME);
        let file = File::open(filename.clone())
            .unwrap_or_else(|_| panic!("cannot read file '{}'", filename));

        BufReader::new(file)
            .lines()
            .enumerate()
            .map(|(i, line)| {
                let line = line
                    .unwrap_or_else(|_| panic!("cannot read line {} of file '{}'", i, filename));
                let case: Self = serde_json::from_str(&line)
                    .unwrap_or_else(|_| panic!("cannot parse line {} of file '{}'", i, filename));
                DataTestCaseDesc {
                    name: None,
                    case,
                    location: format!("test_vector {}", i),
                }
            })
            .collect()
    }
}

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

pub fn write_jsonl<T: TestVector + ser::Serialize>(
    dir: &str,
    generator: fn() -> Vec<T>,
) -> Result<(), Error> {
    let filepath = format!("{}/{}/{}.jsonl", dir, T::MODULE_SUBDIR, T::FILE_NAME);

    if let Some(dir) = Path::new(&filepath).parent() {
        fs::create_dir_all(dir).map_err(|err| Error::File(format!("{}", dir.display()), err))?;
    }
    let mut f = File::create(filepath.clone()).map_err(|err| Error::File(filepath, err))?;

    for obj in generator() {
        serde_json::to_writer(BufWriter::new(f.try_clone()?), &obj)?;
        f.write_all(b"\n")?;
    }
    f.flush()?;
    Ok(())
}
