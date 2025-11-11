#![allow(non_snake_case)]

use std::env;
use std::thread::sleep;
use std::time::{Duration, Instant};
use get_if_addrs::get_if_addrs;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use tokio::runtime::{Builder, Runtime};
use crate::simulation::leader_aggregator::LeaderAggregator;
use crate::simulation::simulator::Simulator;
use crate::simulation::leaf_aggregator::LeafAggregator;
use crate::simulation::leaf_node::LeafNode;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

// Thread pool 1: 4 threads
pub(crate) static RUN_POOL: Lazy<Runtime> = Lazy::new(|| {

    let args: Vec<String> = env::args().collect();
    let mut core_count = 4;
    if args.len() > 2 {
        core_count = args[2].parse::<usize>().unwrap();
    }

    Builder::new_multi_thread()
        .worker_threads(core_count)
        .thread_name("run")
        .enable_all()
        .build()
        .unwrap()
});

// Thread pool 2: 4 threads
pub(crate) static PREPARE_POOL: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("run")
        .enable_all()
        .build()
        .unwrap()
});

/// We want to run this with m = 320/256, Cores = 4,6,8,12,16 (need 20 core machine) So parameters is cargo run -- 320/256 4/16
pub(crate) async fn main() {

    let args: Vec<String> = env::args().collect();

    let mut ip: String = "127.0.0.1".parse().unwrap();
    for iface in get_if_addrs().unwrap() {
        if iface.name == "eth0" {
            if let std::net::IpAddr::V4(ipv4) = iface.ip() {
                ip = iface.ip().to_string()
                // You can now use this IP for binding or logging
            }
        }
    }

    println!("Starting simulation {}", ip);

    // Fanout we're considering.
    let mut m = 820;

    if args.len() > 1 {
        m = args[1].parse::<usize>().unwrap();
    }

    // Participation modifier for cost calculation. It's 2x3 (3 for 1/3) for 2/3 participation and 2*10 for 9/10, and 2*100 for 99/100
    let mut participation_modifier = 6;

    if args.len() > 3 {
        participation_modifier = args[3].parse::<usize>().unwrap();
    }
    
    //TODO: Redo with 2m nodes.

    // Set up simulator connections.

    // Random 100KB block data (about realistic).
    let mut proposal = vec![0u8; 100_000];
    OsRng.fill_bytes(&mut proposal);

    let mut simulator = Simulator::new(m, &proposal, &ip);
    let (public_keys, private_keys, agg_sig, my_sig, sig_vec) = simulator.init().await;

    let mut final_time = 0;
    for _ in 0..10 {
        simulator.open_connections(&sig_vec).await;
        println!("Finished preparing Simulator");

        // Set up validator connections.
        let mut leader_aggregator = LeaderAggregator::new(m, &proposal, public_keys.clone(), &ip, &private_keys);
        leader_aggregator.open_connections().await;


        let mut leaf_node = LeafNode::new(&proposal, public_keys.clone(), my_sig, agg_sig, &ip, participation_modifier);
        leaf_node.connect().await;

        let mut leaf_aggregator = LeafAggregator::new(&proposal, public_keys.clone(), &ip, &private_keys);

        leaf_aggregator.connect().await;

        // Send out network messages of simulator for the validator to process.
        simulator.run().await;
        println!("Started up Simulator");
        let mut network = 0;

        // Actually run the validator and measure time it took.
        let time_now = Instant::now();
        leaf_node.run().await;
        network += 200;
        println!("Now 1: {}", time_now.elapsed().as_millis());
        leaf_aggregator.run().await;
        println!("Now 2: {}", time_now.elapsed().as_millis());
        leader_aggregator.run().await;

        let time_final = time_now.elapsed().as_millis() + network;

        final_time+=time_final;

        println!("Time final: {}", time_final);

        // ----- Types of Roles: -----
        // Leaf node: Verifies initial proposal, signs it, and sends sig out (done)
        // Leaf aggregator: Collect leaf votes, aggregate and broadcast (done)
        // Internal aggregator: Collect aggregates from leaf aggregators, aggregate into 2 separate aggregate (largest & majority) and send up to next station (done)
        // Leader aggregator. Collect aggregates from others and join 2 aggregates that we've gotten. (done)

        // Leaf sends to 128 parents, one of them is real (simulator only has to create 127 now, we create a new validatortype for this that listens to the m input.)

        //todo: Simulate average case
        //todo: Make it work in docker with netem - actually 200ms

        // Give the program time to wrap up.
        tokio::time::sleep(Duration::from_secs(5)).await;

        simulator.kill().await;
        leader_aggregator.kill().await;

        tokio::time::sleep(Duration::from_secs(60)).await;
    }

    let result = final_time/10;
    println!("Result final: {} for {:?}", result, env::args());
}