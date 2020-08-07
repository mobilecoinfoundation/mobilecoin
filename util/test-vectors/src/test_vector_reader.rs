use crate::TestVector;
use datatest::DataTestCaseDesc;
use serde::de;
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

pub trait TestVectorReader: Sized {
    fn from_jsonl(dir: &str) -> Vec<DataTestCaseDesc<Self>>;
}

impl<T: TestVector> TestVectorReader for T
where
    for<'a> Self: de::Deserialize<'a>,
{
    fn from_jsonl(dir: &str) -> Vec<DataTestCaseDesc<Self>> {
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
