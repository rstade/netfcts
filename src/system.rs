use std::fs::File;
use std::io::Read;
use eui48::MacAddress;
use std::path::Path;
use errors::*;

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

pub fn get_mac_from_ifname(ifname: &str) -> Result<MacAddress> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    File::open(iface).map_err(|e| e.into()).and_then(|mut f| {
        f.read_to_string(&mut macaddr)
            .map_err(|e| e.into())
            .and_then(|_| MacAddress::parse_str(&macaddr.lines().next().unwrap_or("")).map_err(|e| e.into()))
    })
}

pub fn get_mac_string_from_ifname(ifname: &str) -> Result<String> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    File::open(iface).map_err(|e| e.into()).and_then(|mut f| {
        f.read_to_string(&mut macaddr)
            .map_err(|e| e.into())
            .and_then(|_| Ok(macaddr.lines().next().unwrap_or("").to_string()))
    })
}
