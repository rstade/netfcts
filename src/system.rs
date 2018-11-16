use std::fs::File;
use std::io::Read;

const CPU_CLOCK_PATH: &str = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";

#[derive(Clone)]
pub struct SystemData {
    pub cpu_clock: u64, // base clock for rdtsc in Hz
}

impl SystemData {
    pub fn detect() -> SystemData {
        let mut khz = String::new();
        File::open(CPU_CLOCK_PATH)
            .and_then(|mut f| f.read_to_string(&mut khz))
            .expect(&format!("cannot read {}", CPU_CLOCK_PATH));
        khz.pop(); // remove CR/LF
        SystemData {
            cpu_clock: khz.parse::<u64>().unwrap() * 1000,
        }
    }
}
