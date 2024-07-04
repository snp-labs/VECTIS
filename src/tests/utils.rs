pub trait Average<T> {
    fn average(&self) -> T;
}

impl Average<u128> for Vec<u128> {
    fn average(&self) -> u128 {
        let sum: u128 = self.iter().sum();
        if self.is_empty() {
            0
        } else {
            sum / (self.len() as u128)
        }
    }
}

pub fn format_time(microseconds: u128) -> String {
    if microseconds >= 1_000_000 {
        let seconds = microseconds as f64 / 1_000_000.0;
        format!("{:.3} s", seconds)
    } else if microseconds >= 1_000 {
        let milliseconds = microseconds as f64 / 1_000.0;
        format!("{:.3} ms", milliseconds)
    } else {
        format!("{} µs", microseconds)
    }
}
