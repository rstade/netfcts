use rand::thread_rng;
use rand::seq::SliceRandom;

pub struct TimeAdder {
    sum: u64,
    count: u64,
    name: String,
    sample_size: u64,
}

impl TimeAdder {
    pub fn new(name: &str, sample_size: u64) -> TimeAdder {
        TimeAdder {
            sum: 0,
            count: 0,
            name: name.to_string(),
            sample_size,
        }
    }

    pub fn add(&mut self, time_diff: u64) {
        self.sum += time_diff;
        self.count += 1;

        if self.count % self.sample_size == 0 {
            println!(
                "TimeAdder {:24}: sum = {:12}, count= {:9}, per count= {:6}",
                self.name,
                self.sum,
                self.count,
                self.sum / self.count
            );
        }
    }
}

pub fn shuffle_ports(first_port: u16, last_port: u16) -> Vec<u16> {
    let mut vec: Vec<u16> = (first_port..last_port + 1).collect();
    {
        let slice: &mut [u16] = &mut vec;
        slice.shuffle(&mut thread_rng());
    }
    vec
}

use std::collections::{VecDeque, BTreeMap};

pub struct Sock2Index {
    sock_tree: BTreeMap<u32, usize>,
    port_maps: Vec<Box<[u16; 0xFFFF]>>,
    free_maps: VecDeque<usize>,
}

impl<'a> Sock2Index {
    pub fn new() -> Sock2Index {
        Sock2Index {
            sock_tree: BTreeMap::new(),
            port_maps: vec![Box::new([0; 0xFFFF]); 8],
            free_maps: (0..8).collect(),
        }
    }

    #[inline]
    pub fn get(&self, sock: &(u32, u16)) -> Option<&u16> {
        let ip = sock.0;
        let port = sock.1;
        assert!(port > 0);
        let port_map = self.sock_tree.get(&ip);
        match port_map {
            None => None,
            Some(port_map) => match self.port_maps[*port_map][(port - 1) as usize] {
                0 => None,
                _ => Some(&self.port_maps[*port_map][(port - 1) as usize]),
            },
        }
    }

    #[inline]
    pub fn insert(&mut self, sock: (u32, u16), index: u16) {
        let ip = sock.0;
        let is_new_ip = self.sock_tree.get(&ip).is_none();
        if is_new_ip {
            let free_map_ix = self
                .free_maps
                .pop_front()
                .expect("currently only 8 IP source addresses are supported");
            self.sock_tree.insert(ip, free_map_ix);
        }
        let port_map_ix = self.sock_tree.get(&ip).unwrap();
        self.port_maps[*port_map_ix][(sock.1 - 1) as usize] = index;
    }

    #[inline]
    pub fn remove(&mut self, sock: &(u32, u16)) -> Option<u16> {
        let port_map_ix = self.sock_tree.get(&sock.0);
        if port_map_ix.is_none() {
            return None;
        } else {
            let pm_ix = **port_map_ix.as_ref().unwrap();
            let old = self.port_maps[pm_ix][(sock.1 - 1) as usize];
            self.port_maps[pm_ix][(sock.1 - 1) as usize] = 0;
            match old {
                0 => None,
                _ => Some(old),
            }
        }
    }

    pub fn values(&'a self) -> Vec<u16> {
        self.sock_tree
            .values()
            .flat_map(|i| {
                self.port_maps[*i as usize]
                    .iter()
                    .filter(|ix| **ix != 0)
                    .map(|ix| *ix)
                    .collect::<Vec<u16>>()
            })
            .collect()
    }
}



#[test]
fn test_shuffling() {
    let vec = shuffle_ports(0, 100);
    let sum: u16 = vec.iter().sum();
    assert_eq!(sum, 5050);
    let h1: u16 = vec.iter().enumerate().filter(|(i, _x)| i < &50).map(|(_i, x)| x).sum();
    let h2: u16 = vec.iter().enumerate().filter(|(i, _x)| i >= &50).map(|(_i, x)| x).sum();
    println!("h1= {}, h2= {}", h1 ,h2);
    assert!((h1 as i32 - 2525).abs() < 500 );
}