// Simple YARA demo binary. Contains a marker string used by rules/yara/example_test_string.yar.
// Runs in a loop to demonstrate active response (process termination).
use std::{thread, time::Duration};

const MARKER: &str = "RUSTINEL_TEST_MARKER";

fn main() {
    println!("YARA demo started. Contains marker: {}", MARKER);
    println!("Looping every 2 seconds. Press Ctrl+C to exit (or wait for response engine termination)...");

    let mut count = 0;
    loop {
        count += 1;
        println!("[{}] Still running... (marker present)", count);
        thread::sleep(Duration::from_secs(2));
    }
}
