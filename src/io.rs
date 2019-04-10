use comm::PipelineId;
use tcp_common::TcpCounter;
use separator::Separatable;
use std::ptr;
use e2d2::native::zcsi::*;

pub fn print_hard_statistics(port_id: u16) -> i32 {
    let stats = RteEthStats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(port_id, &stats as *const RteEthStats);
    }
    if retval == 0 {
        println!("Port {}:\n{}\n", port_id, stats);
    }
    retval
}

pub fn print_soft_statistics(port_id: u16) -> i32 {
    let stats = RteEthStats::new();
    let retval;
    unsafe {
        retval = rte_eth_stats_get(port_id, &stats as *const RteEthStats);
    }
    if retval == 0 {
        println!("Port {}:\n{}\n", port_id, stats);
    }
    retval
}

pub fn print_xstatistics(port_id: u16) -> i32 {
    let len;
    unsafe {
        len = rte_eth_xstats_get_names_by_id(port_id, ptr::null(), 0, ptr::null());
        if len < 0 {
            return len;
        }
        let xstats_names = vec![
            RteEthXstatName {
                name: [0; RTE_ETH_XSTATS_NAME_SIZE],
            };
            len as usize
        ];
        let ids = vec![0u64; len as usize];
        if len != rte_eth_xstats_get_names_by_id(port_id, xstats_names.as_ptr(), len as u32, ptr::null()) {
            return -1;
        };
        let values = vec![0u64; len as usize];

        if len != rte_eth_xstats_get_by_id(port_id, ptr::null(), values.as_ptr(), 0 as u32) {
            return -1;
        }

        for i in 0..len as usize {
            rte_eth_xstats_get_id_by_name(port_id, xstats_names[i].to_ptr(), &ids[i]);
            {
                println!("{}, {}: {}", i, xstats_names[i].to_str().unwrap(), values[i]);
            }
        }
    }
    len
}

pub fn print_tcp_counters(pipeline_id: &PipelineId, tcp_counter_to: &TcpCounter, tcp_counter_from: &TcpCounter) {
    println!("\n\n");
    println!("{}: client side {}", pipeline_id, tcp_counter_to);
    println!("{}: server side {}", pipeline_id, tcp_counter_from);
}

pub fn print_rx_tx_counters(pipeline_id: &PipelineId, rx_tx_stats: &Vec<(u64, usize, usize)>) {
    println!("\n\n");

    if rx_tx_stats.len() > 0 {
        println!("{}: rx/tx packets over time", pipeline_id);
        println!("      {:>24} -{:>24} -{:>8} {:>8}", "cycles", "delta cycles", "rx", "tx");
        println!(
            "{:4}: {:>24} -{:>24} -{:8} {:8}",
            0,
            rx_tx_stats[0].0.separated_string(),
            "-",
            rx_tx_stats[0].1,
            rx_tx_stats[0].2
        );
    }
    if rx_tx_stats.len() > 1 {
        rx_tx_stats
            .iter()
            .zip(&rx_tx_stats[1..])
            .enumerate()
            .for_each(|(i, (&prev, &next))| {
                println!(
                    "{:4}: {:>24} -{:>24} -{:8} {:8}",
                    i + 1,
                    next.0.separated_string(),
                    (next.0 - prev.0).separated_string(),
                    (next.1 - prev.1),
                    (next.2 - prev.2)
                )
            });
    }
}
