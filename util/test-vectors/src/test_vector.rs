pub trait TestVector: Sized {
    const FILE_NAME: &'static str;
    const MODULE_SUBDIR: &'static str;

    fn generate() -> Vec<Self>;
}
