use mc_consensus_scp::{test_utils, CombineFn, ValidityFn};
use mc_util_serial::prost::alloc::fmt::Formatter;
use std::{fmt, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct TestOptions {
    /// Values can be submitted to all nodes in parallel (true) or to nodes in sequential order (false)
    pub submit_in_parallel: bool,

    /// Total number of values to submit. Tests run until all values are externalized by all nodes.
    /// N.B. if the validity fn doesn't enforce unique values, it's possible a value will appear in
    /// multiple places in the ledger, and that the ledger will contain more than values_to_submit
    pub values_to_submit: usize,

    /// Approximate rate that values are submitted to nodes. Unless we are testing slow submission
    /// is it better to set this quite high.
    pub submissions_per_sec: u64,

    /// We propose up to this many values from our pending set per slot.
    pub max_slot_proposed_values: usize,

    /// The total allowed testing time before forcing a panic
    pub allowed_test_time: Duration,

    /// wait this long for slog to flush values before ending a test
    pub log_flush_delay: Duration,

    /// This parameter sets the interval for round and ballot timeout.
    /// SCP suggests one second, but threads can run much faster.
    pub scp_timebase: Duration,

    /// The values validity function to use (typically trivial)
    pub validity_fn: ValidityFn<String, test_utils::TransactionValidationError>,

    /// The values combine function to use (typically trivial)
    pub combine_fn: CombineFn<String, test_utils::TransactionValidationError>,
}

impl TestOptions {
    pub fn new() -> Self {
        Self {
            submit_in_parallel: true,
            values_to_submit: 5000,
            submissions_per_sec: 20000,
            max_slot_proposed_values: 100,
            allowed_test_time: Duration::from_secs(300),
            log_flush_delay: Duration::from_millis(50),
            scp_timebase: Duration::from_millis(1000),
            validity_fn: Arc::new(test_utils::trivial_validity_fn::<String>),
            combine_fn: Arc::new(test_utils::get_bounded_combine_fn::<String>(100)),
        }
    }
}

impl fmt::Display for TestOptions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "TestOptions:")?;
        let submit = if self.submit_in_parallel {
            "parallel"
        } else {
            "sequential"
        };

        writeln!(f, "submit: {}", submit)?;
        writeln!(f, "values_to_submit: {}", self.values_to_submit)?;
        writeln!(f, "submissions_per_sec: {}", self.submissions_per_sec)?;
        writeln!(
            f,
            "max_slot_proposed_values: {}",
            self.max_slot_proposed_values
        )?;
        writeln!(
            f,
            "allowed_test_time: {} seconds",
            self.allowed_test_time.as_secs_f32()
        )
    }
}
