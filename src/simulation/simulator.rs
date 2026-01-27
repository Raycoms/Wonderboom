#![allow(non_snake_case)]

use crate::simulation::main::{DST, PREPARE_POOL};
use bit_vec::BitVec;
use blst::byte;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;

pub struct Simulator {
    // fanout
    pub m: usize,
    // Total number of nodes.
    pub N: usize,
    // Proposal byte vector.
    pub proposal: Vec<byte>,
    pub leaf_channels: broadcast::Sender<()>,
    pub leaf_parent_channels: broadcast::Sender<()>,
    pub consensus_data: Arc<HashMap<usize, Vec<(PublicKey, Signature, BitVec)>>>,
    pub priv_keys: Arc<Vec<SecretKey>>,
}

impl Simulator {
    pub fn new(m: usize, proposal: &Vec<u8>) -> Self {
        let N = m * 2048;
        Simulator {
            m,
            N,
            proposal: proposal.clone(),
            leaf_channels: broadcast::channel(2).0,
            leaf_parent_channels: broadcast::channel(2).0,
            priv_keys: Arc::new(Vec::new()),
            consensus_data: Arc::new(HashMap::new()),
        }
    }

    pub async fn init(&mut self, private_keys: Arc<Vec<SecretKey>>, public_keys: Arc<Vec<PublicKey>>, signatures: Arc<Vec<Signature>>) -> Signature {
        // We set up connections for: Leaf nodes, siblings & parent nodes.

        println!("Starting Simulator with {} - {}", self.N, self.m);

        println!("Finished Signatures, Starting Aggregation");
        self.priv_keys = private_keys.clone();

        // Map for agg per depth.
        let mut agg_map = HashMap::new();
        // Aggregate them into agg map.
        let mut agg_vec = Vec::new();

        let mut curr_index = 0;
        for _ in 0..2048 {
            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            for _ in 0..self.m {
                curr_pub_ref_vec.push(&public_keys[curr_index]);
                curr_sig_ref_vec.push(&signatures[curr_index]);
                curr_index+=1;
            }
            let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, true).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();
            agg_vec.push((agg_pub, agg_sig, BitVec::from_elem(self.m, true)));
        }
        agg_map.insert(0, agg_vec);

        println!("Finished First Aggregation, Starting Recursive Aggregation for {}", agg_map.get(&0).unwrap().len());

        let mut sigs = Vec::new();
        for (pub_key, sig, bit_vec) in agg_map.get(&0).unwrap().iter() {
            sigs.push(sig);
        }

        let agg_sig = AggregateSignature::aggregate(&sigs, false).unwrap().to_signature();
        self.consensus_data = Arc::new(agg_map);

        println!("Finished Aggregation, Opening Connections");
        agg_sig
    }

    pub async fn open_connections(&mut self, sig_vec: &Arc<Vec<Signature>>, depth_channel_leaf: Sender<()>) {

        // Leaf nodes will send out messages to their parent
        setup_leaf_nodes(self, sig_vec, depth_channel_leaf).await;
        println!("Finished preparing Simulator leaf connections");

        // Sleep a sec and let the thread creation and listener creation finish.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self, depth_channel_agg: Sender<()>) {

        connect_to_leaf_as_leaf(self).await;

        connect_to_leader(&self, depth_channel_agg).await;

        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        println!("Finished connecting children to parent");
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        self.leaf_channels.send(()).unwrap();
        self.leaf_parent_channels.send(()).unwrap();
    }
}

pub async fn setup_leaf_nodes(simulator: &mut Simulator, sigs: &Arc<Vec<Signature>>, depth_channel_leaf: Sender<()>) {

    let leaf_channel = simulator.leaf_channels.clone();
    let sigs = sigs.clone();
    let m_clone = simulator.m;

    PREPARE_POOL.spawn(async move {

        for i in 1..m_clone {
            let port = 10_000 + i;
            let addr = format!("{}:{}", "leaf", port);
            let listener = TcpListener::bind(&addr).await.unwrap();

            let mut rx = leaf_channel.subscribe();
            let depth_channel = depth_channel_leaf.clone();

            let sigs_clone = sigs.clone();
            // Spawn a task to accept connections on this listener
            PREPARE_POOL.spawn(async move {
                let mut rx2 = depth_channel.subscribe();
                // We atm only need a single connection per port here (saves us from having a lot of async tasks doing nothing).
                match listener.accept().await {
                    Ok((mut socket, addr)) => {
                        // Spawn a new task for each connection
                        rx.recv().await.unwrap();

                        // Wait for activation message from the normal leaf.
                        rx2.recv().await.unwrap();

                        socket.write(&i.to_be_bytes()).await.unwrap();

                        socket.write(&sigs_clone[i].to_bytes()).await.unwrap();

                        // Await second channel to close connection.

                        let _ = rx.recv().await;
                    }
                    Err(e) => {
                        eprintln!("Failed to accept connection: {}", e);
                    }
                }
            });
        }
    });
}

/// These are the child processes of the first internal aggregator.
pub async fn connect_to_leader(simulator: &Simulator, depth_channel_agg: Sender<()>) {

    // The leader gets messages from 32 slots * 64 committees per slot * 16 committee representatives - 1 (which we send in the leaf aggregator)
    // We don't do the /16 because that's too many open connections, we just send x 16 here.
    for i in 1..(32 * 64) {

        let data_copy = simulator.consensus_data.clone();
        // Every 16th is a different group out of the 32 * 64 ones.
        let local_idx = i;
        let priv_key = simulator.priv_keys.get(local_idx).unwrap().clone();

        let depth_channel = depth_channel_agg.clone();

        PREPARE_POOL.spawn(async move {
            let mut rx = depth_channel.subscribe();
            let mut stream = TcpStream::connect(&format!("{}:{}", "leader", 10_000)).await.unwrap();
            rx.recv().await.unwrap();

            let copy = data_copy.get(&0).unwrap();
            let sub_copy = copy.get(local_idx);

            if sub_copy.is_none() {
                panic!("Couldn't find signature for child connection {}", i);
            }

            let (pub_key, agg_sig, bit_vec) = sub_copy.unwrap();

            let mut msg_bytes = agg_sig.to_bytes().to_vec();
            msg_bytes.append(&mut bit_vec.to_bytes().to_vec());

            let personal_sig = priv_key.sign(&msg_bytes, DST, &[]);

            stream.write(&local_idx.to_be_bytes()).await.unwrap();

            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&agg_sig.to_bytes()).await.unwrap();
            stream.write(&personal_sig.to_bytes()).await.unwrap();
        });
    }
}

pub async fn connect_to_leaf_as_leaf(simulator: &Simulator) {

    // We have m-1 connections. Each of them sends a signature aggregate. 20 distinct ones. The first one we already did!
    for _ in 1..simulator.m {
        let port = 10_000;
        let addr = format!("{}:{}", "aggregator", port);

        let mut rx = simulator.leaf_parent_channels.subscribe();

        PREPARE_POOL.spawn(async move {
            let mut stream = TcpStream::connect(&addr).await.unwrap();

            let mut buffer = [0; 96];
            stream.read_exact(&mut buffer).await.unwrap();

            rx.recv().await.unwrap();
        });
    }
}
