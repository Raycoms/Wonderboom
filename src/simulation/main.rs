#![allow(non_snake_case)]

use std::env;
use std::thread::sleep;
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::broadcast;
use crate::simulation::crypto;
use crate::simulation::leader_aggregator::LeaderAggregator;
use crate::simulation::simulator::Simulator;
use crate::simulation::leaf_aggregator::LeafAggregator;

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

    println!("Starting simulation");

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

    let ((private_keys, public_keys, signatures), proposal) = crypto::generate_or_load(m * 2048).await;

    let mut simulator = Simulator::new(m, &proposal);
    let agg_sig = simulator.init(private_keys.clone(), public_keys.clone(), signatures.clone()).await;

    let mut final_time = Vec::new();
    for _ in 0..10 {

        let depth_channel_leaf: broadcast::Sender<()> = broadcast::Sender::new(2);
        let depth_channel_agg: broadcast::Sender<()> = broadcast::Sender::new(2);

        simulator.open_connections(&signatures.clone(), depth_channel_leaf.clone()).await;
        println!("Finished preparing Simulator");

        // Set up validator connections.
        let mut leader_aggregator = LeaderAggregator::new(m, &proposal, public_keys.clone());
        leader_aggregator.open_connections().await;

        let mut leaf_aggregator = LeafAggregator::new(&proposal, public_keys.clone(), private_keys.clone(), participation_modifier, m, agg_sig, signatures.get(0).unwrap().clone(), depth_channel_leaf.clone(), depth_channel_agg.clone());

        leaf_aggregator.connect().await;

        // Send out network messages of simulator for the validator to process.
        simulator.run(depth_channel_agg.clone()).await;

        sleep(Duration::from_secs(3));
        println!("Started up Simulator");

        // Actually run the validator and measure time it took.
        let time_now = Instant::now();
        println!("Now 1: {}", time_now.elapsed().as_millis());
        leaf_aggregator.run().await;
        println!("Now 2: {}", time_now.elapsed().as_millis());
        leader_aggregator.run().await;

        let time_final = time_now.elapsed().as_millis();

        final_time.push(time_final);

        println!("Time final: {}", time_final);

        // Give the program time to wrap up.
        tokio::time::sleep(Duration::from_secs(5)).await;

        simulator.kill().await;
        leader_aggregator.kill().await;

        tokio::time::sleep(Duration::from_secs(120)).await;
    }

    println!("Result final: {:?} for {:?}", final_time, env::args());
}
