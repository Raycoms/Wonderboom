#![allow(non_snake_case)]

use std::env;
use std::thread::sleep;
use std::time::{Duration, Instant};
use get_if_addrs::get_if_addrs;
use once_cell::sync::Lazy;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::broadcast;
use crate::simulation::crypto;
use crate::simulation::depth_based_internal_aggregator::DepthBasedInternalAggregator;
use crate::simulation::first_internal_aggregator::FirstInternalAggregator;
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
    let mut m = 256;

    if args.len() > 1 {
        m = args[1].parse::<usize>().unwrap();
    }

    let additional_depth = 2;
    let leader_divider = 1;

    let ((private_keys, public_keys, signatures), proposal) = crypto::generate_or_load((m/16).pow( (additional_depth + 1) as u32) * m / leader_divider).await;

    for participation_modifier in [6, 20, 200] {
        // Set up simulator connections.
        let mut simulator = Simulator::new(m, additional_depth, &proposal, leader_divider, &ip);
        let (agg_sig, my_sig) = simulator.init(private_keys.clone(), public_keys.clone(), signatures.clone()).await;

        let mut final_time = Vec::new();
        for _ in 0..5 {
            simulator.open_connections().await;
            println!("Finished preparing Simulator");

            let mut depth_based_internal_aggregator_vec = Vec::new();

            let mut depth_channels: Vec<broadcast::Sender<()>> = Vec::new();

            for i in 0..additional_depth + 4 {
                depth_channels.push(broadcast::channel(2).0);
            }

            for i in (0..additional_depth).rev() {
                depth_based_internal_aggregator_vec.push(DepthBasedInternalAggregator::new(m, i, additional_depth, proposal.clone(), public_keys.clone(), &ip, private_keys.clone(), participation_modifier, depth_channels.get(i).unwrap().clone()));
            }

            // Set up validator connections.
            let mut first_internal_aggregator = FirstInternalAggregator::new(m, additional_depth, &proposal, public_keys.clone(), &ip, private_keys.clone(), depth_channels.get(additional_depth).unwrap().clone());
            first_internal_aggregator.open_connections().await;
            for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
                dep_based.open_connections().await;
            }

            let mut leaf_aggregator = LeafAggregator::new(m, &proposal, public_keys.clone(), &ip, private_keys.clone(), depth_channels.get(additional_depth + 1).unwrap().clone());
            leaf_aggregator.open_connections().await;

            simulator.connect().await;

            let mut leaf_node = LeafNode::new(m, &proposal, public_keys.clone(), my_sig, agg_sig, &ip, participation_modifier, depth_channels.get(additional_depth + 2).unwrap().clone());
            leaf_node.connect().await;

            leaf_aggregator.connect().await;

            first_internal_aggregator.connect().await;
            for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
                dep_based.connect().await;
            }

            // Send out network messages of simulator for the validator to process.
            simulator.run(depth_channels.clone(), signatures.clone()).await;
            println!("Started up Simulator");

            sleep(Duration::from_secs(3));

            // Actually run the validator and measure time it took.
            let time_now = Instant::now();
            leaf_node.run().await;
            println!("Now 1: {}", time_now.elapsed().as_millis());
            leaf_aggregator.run().await;
            println!("Now 2: {}", time_now.elapsed().as_millis());
            first_internal_aggregator.run().await;
            println!("Now 3: {}", time_now.elapsed().as_millis());
            for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
                dep_based.run().await;
                println!("Now 4x: {}", time_now.elapsed().as_millis());
            }

            let time_final = time_now.elapsed().as_millis();

            final_time.push(time_final);

            println!("Time final: {}", time_final);

            // Give the program time to wrap up.
            sleep(Duration::from_secs(5));

            simulator.kill().await;
            leaf_aggregator.kill().await;
            first_internal_aggregator.kill().await;
            for mut dep_based in depth_based_internal_aggregator_vec.iter_mut() {
                dep_based.kill().await;
            }
            sleep(Duration::from_secs(10));
        }

        println!("Result final: {:?} for {:?} and {}", final_time, env::args(), participation_modifier);
    }
}