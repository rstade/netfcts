extern crate e2d2;
extern crate eui48;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate ipnet;
extern crate separator;
#[macro_use]
extern crate error_chain;
extern crate toml;
extern crate rand;

pub mod comm;
pub mod tasks;
pub mod tcp_common;
pub mod timer_wheel;
pub mod system;
pub mod io;
pub mod errors;
pub mod utils;

use std::collections::HashMap;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::Arc;
use std::fmt;
use std::slice::Iter;
use std::cmp::Ordering;
use std::cell::RefCell;
use std::rc::Rc;

use ipnet::Ipv4Net;
use separator::Separatable;

use e2d2::allocators::CacheAligned;
use e2d2::interface::{FlowDirector, PmdPort, PortQueue, PortType};
use e2d2::scheduler::NetBricksContext;
use e2d2::utils as e2d2_utils;

use tcp_common::{ReleaseCause, TcpRole, TcpState};


#[derive(Clone, Debug)]
pub struct ConRecord {
    stamps: [u32; 6],
    state: [u16; 8],
    base_stamp: u64,
    pub role: TcpRole,
    pub port: u16,
    pub sock: Option<(u32, u16)>,
    uid: u64,
    state_count: usize,
    pub payload_packets: usize,
    pub server_index: usize,
    release_cause: ReleaseCause,
}

// we map cycle differences from u64 to u32 to minimize record size in the cache (performance)
const TIME_STAMP_REDUCTION_FACTOR:u64 = 1000;

impl ConRecord {
    #[inline]
    pub fn init(&mut self, role: TcpRole, port: u16, sock: Option<(u32, u16)>) {
        self.port = port;
        self.state_count = 1;
        self.base_stamp = 0;
        self.payload_packets = 0;
        if role == TcpRole::Client {
            self.state[0] = TcpState::Closed as u16;
            self.uid = e2d2_utils::rdtsc_unsafe();
        } else {
            self.state[0] = TcpState::Listen as u16;
            // server connections get the uuid from associated client connection if any
            self.uid = 0;
        }
        self.server_index = 0;
        self.sock = sock;
        self.role = role;
    }

    #[inline]
    pub fn released(&mut self, cause: ReleaseCause) {
        self.release_cause = cause;
    }

    #[inline]
    pub fn get_release_cause(&self) -> ReleaseCause {
        self.release_cause
    }

    #[inline]
    pub fn new() -> ConRecord {
        ConRecord {
            role: TcpRole::Client,
            server_index: 0,
            release_cause: ReleaseCause::Unknown,
            // we are using an Array, not Vec for the state history, the latter eats too much performance
            state_count: 0,
            base_stamp: 0,
            state: [TcpState::Closed as u16; 8],
            stamps: [0u32; 6],
            port: 0u16,
            sock: None,
            payload_packets: 0,
            uid: 0,
        }
    }

    #[inline]
    pub fn push_state(&mut self, state: TcpState) {
        self.state[self.state_count] = state as u16;
        if self.state_count == 1 {
            self.base_stamp = e2d2_utils::rdtsc_unsafe();
        } else {
            self.stamps[self.state_count - 2] = ((e2d2_utils::rdtsc_unsafe() - self.base_stamp) / TIME_STAMP_REDUCTION_FACTOR) as u32;
        }
        self.state_count += 1;
    }

    #[inline]
    pub fn last_state(&self) -> TcpState {
        TcpState::from(self.state[self.state_count - 1])
    }

    #[inline]
    pub fn get_last_stamp(&self) -> Option<u64> {
        match self.state_count {
            0 => None,
            1 => None,
            2 => Some(self.base_stamp),
            _ => Some(self.base_stamp + self.stamps[self.state_count - 3] as u64 * TIME_STAMP_REDUCTION_FACTOR)
        }
    }

    #[inline]
    pub fn get_first_stamp(&self) -> Option<u64> {
        if self.state_count > 1 {
            Some(self.base_stamp)
        } else {
            None
        }
    }

    #[inline]
    pub fn states(&self) -> Vec<TcpState> {
        let mut result= vec![TcpState::Listen; self.state_count];
        for i in 0..self.state_count {
            result[i]=TcpState::from(self.state[i]);
        }
        result
    }

    #[inline]
    pub fn uid(&self) -> u64 { self.uid }

    #[inline]
    pub fn set_uid(&mut self, new_uid: u64) { self.uid = new_uid }

    pub fn deltas_since_synsent_or_synrecv(&self) -> Vec<u32> {
        //let synsent = self.stamps[1];
        if self.state_count >= 3 {
            self.stamps[0..(self.state_count - 3)].iter().map(|s| *s).collect()
        } else {
            vec![]
        }
    }
}

impl fmt::Display for ConRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({:?}, {:21}, {:6}, {:3}, {:?}, {:?}, {}, {:?})",
            self.role,
            if self.sock.is_some() {
                SocketAddrV4::new(Ipv4Addr::from(self.sock.unwrap().0), self.sock.unwrap().1).to_string()
            } else {
                "none".to_string()
            },
            self.port,
            self.server_index,
            self.states(),
            self.release_cause,
            self.base_stamp.separated_string(),
            self.deltas_since_synsent_or_synrecv()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug)]
pub struct RecordStore {
    store: Vec<ConRecord>,
    used_slots: usize,
}

impl RecordStore {
    pub fn with_capacity(capacity: usize) -> RecordStore {
        RecordStore {
            store: vec![ConRecord::new(); capacity],
            used_slots: 0,
        }
    }

    #[inline]
    pub fn get_unused_slot(&mut self) -> usize {
        assert!(self.used_slots < self.store.len());
        self.used_slots += 1;
        self.used_slots - 1
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.used_slots
    }

    #[inline]
    pub fn iter(&self) -> Iter<ConRecord> {
        self.store[0..self.used_slots].iter()
    }

    #[inline]
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut ConRecord> {
        if slot < self.used_slots {
            Some(&mut self.store[slot])
        } else {
            None
        }
    }

    #[inline]
    pub fn get(&self, slot: usize) -> Option<&ConRecord> {
        if slot < self.used_slots {
            Some(&self.store[slot])
        } else {
            None
        }
    }

    pub fn sort_by<F>(&mut self, compare: F)
        where F: FnMut(&ConRecord, &ConRecord) -> Ordering {
        self.store[0..self.used_slots].sort_by(compare)
    }
}
/*
impl Iterator for RecordStore {
    type Item = ConRecord;

    fn next(&mut self) -> Option<Self::Item> {
        self.store.iter().next()
    }
}
*/

pub trait ConRecordOperations {

    /// return reference to reference counted pointer to store in connection
    #[inline]
    fn store(&self) -> &Rc<RefCell<RecordStore>>;

    /// return index of connection record in store
    #[inline]
    fn con_rec(&self) -> usize;

    /// remove references to connection record and its store from connection
    #[inline]
     fn release_conrec(&mut self);

    #[inline]
     fn con_established(&mut self) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().push_state(TcpState::Established);
    }

    #[inline]
     fn server_syn_sent(&mut self) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().push_state(TcpState::SynSent);
        //self.con_rec().s_syn_sent = utils::rdtsc_unsafe();
    }

    #[inline]
     fn port(&self) -> u16 {
        self.store().borrow().get(self.con_rec()).unwrap().port
    }

    #[inline]
     fn in_use(&self) -> bool;

    #[inline]
     fn server_index(&self) -> usize {
        self.store().borrow().get(self.con_rec()).unwrap().server_index
    }

    #[inline]
     fn set_server_index(&mut self, index: usize) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().server_index = index
    }

    #[inline]
     fn payload_packets(&self) -> usize {
        self.store().borrow().get(self.con_rec()).unwrap().payload_packets
    }

    #[inline]
     fn increment_payload_packets(&self) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().payload_packets += 1
    }

    #[inline]
     fn last_state(&self) -> TcpState {
        self.store().borrow().get(self.con_rec()).unwrap().last_state()
    }

    #[inline]
     fn states(&self) -> Vec<TcpState> {
        self.store().borrow().get(self.con_rec()).unwrap().states()
    }

    #[inline]
     fn push_state(&self, state: TcpState) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().push_state(state)
    }

    #[inline]
     fn released(&self, cause: ReleaseCause) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().released(cause)
    }

    #[inline]
     fn set_port(&mut self, port: u16) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().port = port;
    }

    #[inline]
     fn get_dut_sock(&self) -> Option<(u32, u16)> {
        self.store().borrow().get(self.con_rec()).unwrap().sock
    }

    #[inline]
     fn set_dut_sock(&mut self, dut_sock: (u32, u16)) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().sock = Some(dut_sock);
    }

    #[inline]
     fn set_uid(&mut self, uid: u64) {
        self.store().borrow_mut().get_mut(self.con_rec()).unwrap().set_uid(uid);
    }

    #[inline]
     fn get_uid(&self) -> u64 {
        self.store().borrow().get(self.con_rec()).unwrap().uid()
    }
}

#[inline]
pub fn is_kni_core(pci: &CacheAligned<PortQueue>) -> bool {
    pci.rxq() == 0
}

pub fn setup_kni(kni_name: &str, ip_net: &Ipv4Net, mac_address: &String, kni_netns: &String, ip_address_count: usize) {
    let ip_addr_first = ip_net.addr();
    let prefix_len = ip_net.prefix_len();

    debug!("setup_kni");
    //# ip link set dev vEth1 address XX:XX:XX:XX:XX:XX
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "address", mac_address])
        .output()
        .expect("failed to assign MAC address to kni i/f");
    let reply = output.stderr;

    debug!(
        "assigning MAC addr {} to {}: {}, {}",
        mac_address,
        kni_name,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    //# ip netns add nskni
    let output = Command::new("ip")
        .args(&["netns", "add", kni_netns])
        .output()
        .expect("failed to create namespace for kni i/f");
    let reply = output.stderr;

    debug!(
        "creating network namespace {}: {}, {}",
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );

    // ip link set dev vEth1 netns nskni
    let output = Command::new("ip")
        .args(&["link", "set", "dev", kni_name, "netns", kni_netns])
        .output()
        .expect("failed to move kni i/f to namespace");
    let reply = output.stderr;

    debug!(
        "moving kni i/f {} to namesapce {}: {}, {}",
        kni_name,
        kni_netns,
        output.status,
        String::from_utf8_lossy(&reply)
    );
    for i in 0..ip_address_count {
        // e.g. ip netns exec nskni ip addr add w.x.y.z/24 dev vEth1
        let ip_net = Ipv4Net::new(Ipv4Addr::from(u32::from(ip_addr_first) + i as u32), prefix_len)
            .unwrap()
            .to_string();
        let output = Command::new("ip")
            .args(&["netns", "exec", kni_netns, "ip", "addr", "add", &ip_net, "dev", kni_name])
            .output()
            .expect("failed to assign IP address to kni i/f");
        let reply = output.stderr;
        debug!(
            "assigning IP addr {} to {}: {}, {}",
            ip_net,
            kni_name,
            output.status,
            String::from_utf8_lossy(&reply)
        );
    }
    // e.g. ip netns exec nskni ip link set dev vEth1 up
    let output1 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "link", "set", "dev", kni_name, "up"])
        .output()
        .expect("failed to set kni i/f up");
    let reply1 = output1.stderr;
    debug!(
        "ip netns exec {} ip link set dev {} up: {}, {}",
        kni_netns,
        kni_name,
        output1.status,
        String::from_utf8_lossy(&reply1)
    );
    // e.g. ip netns exec nskni ip addr show dev vEth1
    let output2 = Command::new("ip")
        .args(&["netns", "exec", kni_netns, "ip", "addr", "show", "dev", kni_name])
        .output()
        .expect("failed to show IP address of kni i/f");
    let reply2 = output2.stdout;
    info!("show IP addr: {}\n {}", output.status, String::from_utf8_lossy(&reply2));
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
pub enum FlowSteeringMode {
    // Port is default
    Port,
    Ip,
}

#[inline]
fn get_tcp_port_base(port: &PmdPort, count: u16) -> u16 {
    let port_mask = port.get_tcp_dst_port_mask();
    port_mask - count * (!port_mask + 1)
}

pub fn initialize_flowdirector(
    context: &NetBricksContext,
    steering_mode: FlowSteeringMode,
    ipnet: &Ipv4Net,
) -> HashMap<i32, Arc<FlowDirector>> {
    let mut fdir_map: HashMap<i32, Arc<FlowDirector>> = HashMap::new();
    for port in context.ports.values() {
        if *port.port_type() == PortType::Dpdk {
            // initialize flow director on port, cannot do this in parallel from multiple threads
            let mut flowdir = FlowDirector::new(port.clone());
            let ip_addr_first = ipnet.addr();
            for (i, core) in context.active_cores.iter().enumerate() {
                match context.rx_queues.get(&core) {
                    // retrieve all rx queues for this core
                    Some(set) => match set.iter().last() {
                        // select one (should be the only one)
                        Some(queue) => match steering_mode {
                            FlowSteeringMode::Ip => {
                                let dst_ip = u32::from(ip_addr_first) + i as u32 + 1;
                                let dst_port = port.get_tcp_dst_port_mask();
                                debug!(
                                    "set fdir filter on port {} for rfs mode IP: queue= {}, ip= {}, port base = {}",
                                    port.port_id(),
                                    queue.rxq(),
                                    Ipv4Addr::from(dst_ip),
                                    dst_port,
                                );
                                flowdir.add_fdir_filter(queue.rxq(), dst_ip, dst_port).unwrap();
                            }
                            FlowSteeringMode::Port => {
                                let dst_ip = u32::from(ip_addr_first);
                                let dst_port = get_tcp_port_base(port, i as u16);
                                debug!(
                                    "set fdir filter on port {} for rfs mode Port: queue= {}, ip= {}, port base = {}",
                                    port.port_id(),
                                    queue.rxq(),
                                    Ipv4Addr::from(dst_ip),
                                    dst_port,
                                );
                                flowdir.add_fdir_filter(queue.rxq(), dst_ip, dst_port).unwrap();
                            }
                        },
                        None => (),
                    },
                    None => (),
                }
            }
            fdir_map.insert(port.port_id(), Arc::new(flowdir));
        }
    }
    fdir_map
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
