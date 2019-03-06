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
mod recstore;

pub use recstore::RecordStore;
pub use recstore::SimpleStore;
pub use recstore::Store64;
pub use recstore::Storable;
pub use recstore::ConRecordOperations;

use std::collections::HashMap;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;
use std::sync::Arc;
use std::fmt;
use std::mem;

use ipnet::Ipv4Net;
use separator::Separatable;
use eui48::MacAddress;

use e2d2::allocators::CacheAligned;
use e2d2::interface::{FlowDirector, PmdPort, PortQueue, PortType, Packet};
use e2d2::interface::update_tcp_checksum;
use e2d2::scheduler::NetBricksContext;
use e2d2::utils as e2d2_utils;
use e2d2::native::zcsi::ipv4_phdr_chksum;
use e2d2::headers::{EndOffset, IpHeader, MacHeader, TcpHeader};

use tcp_common::{ReleaseCause, TcpRole, TcpState, L234Data};
use tcp_common::tcp_start_state;

#[derive(Clone, Copy, Debug)]
//#[repr(align(64))]
pub struct ConRecord {
    base_stamp: u64,
    uid: u64,
    stamps: [u32; 6],
    payload_packets: u32,
    client_ip: u32,
    client_port: u16,
    port: u16,
    state: [u8; 7],
    state_count: u8,
    server_index: u8,
    release_cause: u8,
    role: u8,
    server_state: u8,
}

// we map cycle differences from u64 to u32 to minimize record size in the cache (performance)
pub const TIME_STAMP_REDUCTION_FACTOR: u64 = 1000;


pub trait HasTcpState {
    fn push_state(&mut self, state: TcpState);
    fn last_state(&self) -> TcpState;
    fn states(&self) -> Vec<TcpState>;
    fn get_last_stamp(&self) -> Option<u64>;
    fn get_first_stamp(&self) -> Option<u64>;
    fn deltas_to_base_stamp(&self) -> Vec<u32>;
    fn release_cause(&self) -> ReleaseCause;
    fn set_release_cause(&mut self, cause: ReleaseCause);
}


pub trait HasConData {
    fn sock(&self) -> (u32, u16);
    fn set_sock(&mut self, s: (u32, u16));
    fn port(&self) -> u16;
    fn set_port(&mut self, port: u16);
    fn uid(&self) -> u64;
    fn set_uid(&mut self, new_uid: u64);
    fn server_index(&self) -> u8;
    fn set_server_index(&mut self, index: u8);
    fn payload_packets(&self) -> u32;
    fn increment_payload_packets(&mut self) -> u32;
    fn server_state(&self) -> TcpState;
    fn set_server_state(&mut self, state: TcpState);
}


impl ConRecord {
    #[inline]
    pub fn init(&mut self, role: TcpRole, port: u16, sock: Option<(u32, u16)>) {
        self.state_count = 0;
        self.base_stamp = 0;
        self.payload_packets = 0;
        self.uid = e2d2_utils::rdtsc_unsafe();
        self.server_index = 0;
        let s = sock.unwrap_or((0, 0));
        self.client_ip = s.0;
        self.client_port = s.1;
        self.role = role as u8;
        self.port = port;
        self.server_state = tcp_start_state(self.role()) as u8;
    }

    #[inline]
    pub fn role(&self) -> TcpRole {
        TcpRole::from(self.role)
    }

    #[inline]
    pub fn base_stamp(&self) -> u64 {
        self.base_stamp
    }


}

impl HasConData for ConRecord {
    #[inline]
    fn sock(&self) -> (u32, u16) { (self.client_ip, self.client_port) }

    #[inline]
    fn set_sock(&mut self, s: (u32, u16)) {
        self.client_ip = s.0;
        self.client_port = s.1;
    }

    #[inline]
    fn port(&self) -> u16 { self.port }

    #[inline]
    fn set_port(&mut self, port: u16) { self.port = port }

    #[inline]
    fn uid(&self) -> u64 { self.uid }

    #[inline]
    fn set_uid(&mut self, new_uid: u64) { self.uid = new_uid }

    #[inline]
    fn server_index(&self) -> u8 { self.server_index }

    #[inline]
    fn set_server_index(&mut self, index: u8) { self.server_index = index }

    #[inline]
    fn payload_packets(&self) -> u32 { self.payload_packets }

    #[inline]
    fn increment_payload_packets(&mut self) -> u32 {
        self.payload_packets += 1;
        self.payload_packets
    }

    #[inline]
    fn server_state(&self) -> TcpState {
        TcpState::from(self.server_state)
    }

    #[inline]
    fn set_server_state(&mut self, state: TcpState) {
        self.server_state = state as u8;
    }

}



impl HasTcpState for ConRecord {
    #[inline]
    fn push_state(&mut self, state: TcpState) {
        self.state[self.state_count as usize] = state as u8;
        if self.state_count == 0 {
            self.base_stamp = e2d2_utils::rdtsc_unsafe();
        } else {
            self.stamps[self.state_count as usize - 1] = ((e2d2_utils::rdtsc_unsafe() - self.base_stamp) / TIME_STAMP_REDUCTION_FACTOR) as u32;
        }
        self.state_count += 1;
    }



    #[inline]
    fn last_state(&self) -> TcpState {
        if self.state_count == 0 {
            tcp_start_state(self.role())
        } else {
            TcpState::from(self.state[self.state_count as usize - 1])
        }
    }

    #[inline]
    fn states(&self) -> Vec<TcpState> {
        let mut result = vec![tcp_start_state(self.role()); self.state_count as usize +1];
        for i in 0..self.state_count as usize {
            result[i+1] = TcpState::from(self.state[i]);
        }
        result
    }

    #[inline]
    fn get_last_stamp(&self) -> Option<u64> {
        match self.state_count {
            0 => None,
            1 => Some(self.base_stamp),
            _ => Some(self.base_stamp + self.stamps[self.state_count as usize - 2] as u64 * TIME_STAMP_REDUCTION_FACTOR)
        }
    }

    #[inline]
    fn get_first_stamp(&self) -> Option<u64> {
        if self.state_count > 0 {
            Some(self.base_stamp)
        } else {
            None
        }
    }

    fn deltas_to_base_stamp(&self) -> Vec<u32> {
        if self.state_count >= 2 {
            self.stamps[0..(self.state_count as usize - 1)].iter().map(|s| *s).collect()
        } else {
            vec![]
        }
    }

    #[inline]
    fn release_cause(&self) -> ReleaseCause {
        ReleaseCause::from(self.release_cause)
    }

    #[inline]
    fn set_release_cause(&mut self, cause: ReleaseCause) {
        self.release_cause = cause as u8;
    }

}

impl fmt::Display for ConRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({:?}, {:21}, {:6}, {:3}, {:7}, {:?}, {:?}, {}, {:?})",
            self.role(),
            if self.client_ip != 0 {
                SocketAddrV4::new(Ipv4Addr::from(self.client_ip), self.client_port).to_string()
            } else {
                "none".to_string()
            },
            self.port(),
            self.server_index,
            self.payload_packets,
            self.states(),
            self.release_cause(),
            self.base_stamp.separated_string(),
            self.deltas_to_base_stamp()
                .iter()
                .map(|u| u.separated_string())
                .collect::<Vec<_>>(),
        )
    }
}

impl Storable for ConRecord {
    #[inline]
    fn new() -> ConRecord {
        ConRecord {
            role: TcpRole::Client as u8,
            server_index: 0,
            release_cause: ReleaseCause::Unknown as u8,
            state_count: 0,
            base_stamp: 0,
            state: [TcpState::Closed as u8; 7],
            stamps: [0u32; 6],
            port: 0u16,
            client_ip: 0,
            client_port: 0,
            payload_packets: 0,
            uid: 0,
            server_state: TcpState::Listen as u8
        }
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
) -> HashMap<u16, Arc<FlowDirector>> {
    let mut fdir_map: HashMap<u16, Arc<FlowDirector>> = HashMap::new();
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


pub struct HeaderState<'a> {
    pub mac: &'a mut MacHeader,
    pub ip: &'a mut IpHeader,
    pub tcp: &'a mut TcpHeader,
}

impl<'a> HeaderState<'a> {
    #[inline]
    pub fn set_dst_socket(&mut self, ip: u32, port: u16) {
        self.ip.set_dst(ip);
        self.tcp.set_dst_port(port);
    }

    #[inline]
    pub fn tcp_payload_len(&self) -> usize {
        self.ip.length() as usize - self.tcp.offset() - self.ip.ihl() as usize * 4
    }
}

#[inline]
pub fn do_ttl(h: &mut HeaderState) {
    let ttl = h.ip.ttl();
    if ttl >= 1 {
        h.ip.set_ttl(ttl - 1);
    }
    h.ip.update_checksum();
}

#[inline]
pub fn prepare_checksum_and_ttl<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, h: &mut HeaderState) {
    let ttl = h.ip.ttl();
    if ttl >= 1 {
        h.ip.set_ttl(ttl - 1);
    }
    //often the mbuf still contains rx offload flags if we received it from the NIC, this may fail the tx offload logic
    p.clear_rx_offload_flags();
    if p.tcp_checksum_tx_offload() {
        h.ip.set_csum(0);
        unsafe {
            let csum = ipv4_phdr_chksum(h.ip, 0);
            h.tcp.set_checksum(csum);
        }
        p.set_l2_len(mem::size_of::<MacHeader>() as u64);
        p.set_l3_len(mem::size_of::<IpHeader>() as u64);
        p.set_l4_len(mem::size_of::<TcpHeader>() as u64);
        debug!("l234len = {}, {}, {}, ol_flags= 0x{:X}, validate= {}", p.l2_len(), p.l3_len(), p.l4_len(), p.ol_flags(), p.validate_tx_offload());
    } else {
        h.ip.update_checksum();
        update_tcp_checksum(p, h.ip.payload_size(0), h.ip.src(), h.ip.dst());
        // debug!("checksum recalc = {:X}",p.get_header().checksum());
    }
}

#[inline]
pub fn set_header(server: &L234Data, port: u16, h: &mut HeaderState, me_mac: &MacAddress, me_ip: u32) {
    h.mac.set_dmac(&server.mac);
    h.mac.set_smac(me_mac);
    h.set_dst_socket(server.ip, server.port);
    h.ip.set_src(me_ip);
    h.tcp.set_src_port(port);
}


// remove tcp options for SYN and SYN-ACK,
// pre-requisite: no payload exists, because any payload is not shifted up
#[inline]
pub fn remove_tcp_options<M: Sized + Send>(p: &mut Packet<TcpHeader, M>, h: &mut HeaderState) {
    let old_offset = h.tcp.offset() as u16;
    if old_offset > 20 {
        debug!("trimming tcp-options by { } bytes", old_offset - 20);
        h.tcp.set_data_offset(5u8);
        // minimum mbuf data length is 60 bytes
        h.ip.trim_length_by(old_offset - 20u16);
        //                        let trim_by = min(p.data_len() - 60usize, (old_offset - 20u16) as usize);
        //                        82599 does padding itself !?
        let trim_by = old_offset - 20;
        let payload_sz=p.payload_size(); // this may include padding bytes
        let written= p.write_from_tail_down(payload_sz, 0x0u8);
        debug!("erased {} bytes from a payload of {} bytes", written, payload_sz);
        p.trim_payload_size(trim_by as usize);
    }
}


#[inline]
pub fn make_reply_packet(h: &mut HeaderState, inc: u32) {
    let smac = h.mac.src;
    let dmac = h.mac.dst;
    let sip = h.ip.src();
    let dip = h.ip.dst();
    let sport = h.tcp.src_port();
    let dport = h.tcp.dst_port();
    h.mac.set_smac(&dmac);
    h.mac.set_dmac(&smac);
    h.ip.set_dst(sip);
    h.ip.set_src(dip);
    h.tcp.set_src_port(dport);
    h.tcp.set_dst_port(sport);
    h.tcp.set_ack_flag();
    let ack_num = h.tcp.seq_num().wrapping_add(h.tcp_payload_len() as u32 + inc);
    h.tcp.set_ack_num(ack_num);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
