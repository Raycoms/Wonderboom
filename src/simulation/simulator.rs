#![allow(non_snake_case)]

use crate::simulation::main::{DST, PREPARE_POOL};
use bit_vec::BitVec;
use blst::byte;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use rand_core::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

pub struct Simulator {
    // Fanout.
    pub(crate) m: usize,
    // Total depth above leaf aggregator.
    pub depth: usize,
    // Total number of nodes.
    pub N: usize,
    // Divider of leader fanout.
    pub leader_divider: usize,
    // Proposal byte vector.
    pub proposal: Vec<byte>,
    pub leaf_channels: broadcast::Sender<()>,
    pub parent_channels: broadcast::Sender<()>,
    pub leaf_parent_channels: broadcast::Sender<()>,
    pub consensus_data: Arc<HashMap<usize, Vec<(PublicKey, Signature, BitVec)>>>,
    pub priv_keys: Vec<Arc<SecretKey>>,
    pub ip : String,
}

impl Simulator {
    pub fn new(m: usize, depth: usize, proposal: &Vec<u8>, leader_divider: usize, ip: &String) -> Self {
        let N = (m/16).pow( (depth + 1) as u32) * m / leader_divider;
        Simulator {
            m,
            depth,
            N,
            leader_divider,
            proposal: proposal.clone(),
            leaf_channels: broadcast::channel(2).0,
            parent_channels: broadcast::channel(2).0,
            leaf_parent_channels: broadcast::channel(2).0,
            priv_keys: Vec::new(),
            consensus_data: Arc::new(HashMap::new()),
            ip: ip.clone(),
        }
    }

    pub async fn init(&mut self, private_keys: Arc<Vec<SecretKey>>, public_keys: Arc<Vec<PublicKey>>, signatures: Arc<Vec<Signature>>, proposal: Vec<u8>) -> (Signature, Signature) {
        // We set up connections for: Leaf nodes, siblings & parent nodes.
        println!("Starting Simulator with {} {}", self.N, self.m);


        // Map for agg per depth.
        let mut agg_map = HashMap::new();
        // Aggregate them into agg map.
        let mut agg_vec = Vec::new();

        let first_depth_size = self.N/self.m;
        let mut curr_index = 0;
        for _ in 0..first_depth_size {
            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            for _ in 0..self.m {
                curr_pub_ref_vec.push(&public_keys[curr_index]);
                curr_sig_ref_vec.push(&signatures[curr_index]);
                curr_index+=1;
            }
            let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();
            agg_vec.push((agg_pub, agg_sig, BitVec::from_elem(self.m, true)));
        }
        agg_map.insert(0, agg_vec);

        println!("Finished First Aggregation, Starting Recursive Aggregation");


        let mut map_idx = 0;
        println!("In map: {} {}", map_idx, agg_map.get(&0).unwrap().len());

        // Recursively build all levels of the tree.
        loop
        {
            let agg_vec = agg_map.get(&map_idx).unwrap();

            let mut local_agg_vec = Vec::new();

            let mut curr_pub_ref_vec = Vec::new();
            let mut curr_sig_ref_vec = Vec::new();
            let mut compound_bit_vec = BitVec::new();

            let mut divider = 1;
            if (map_idx + 1) == self.depth {
                divider = self.leader_divider;
            }

            for (pub_key, sig, bitvec) in agg_vec {
                curr_pub_ref_vec.push(pub_key);
                curr_sig_ref_vec.push(sig);

                compound_bit_vec.extend(bitvec);

                if curr_sig_ref_vec.len() == (self.m/16) {
                    let agg_pub = AggregatePublicKey::aggregate(&curr_pub_ref_vec, false).unwrap().to_public_key();
                    let agg_sig = AggregateSignature::aggregate(&curr_sig_ref_vec, false).unwrap().to_signature();

                    local_agg_vec.push((agg_pub, agg_sig, compound_bit_vec.clone()));

                    curr_sig_ref_vec.clear();
                    curr_sig_ref_vec.clear();
                    compound_bit_vec = BitVec::new();
                }
            }

            if local_agg_vec.len() <= 1 {
                break;
            }
            println!("In map: {} {} {}", map_idx+1, local_agg_vec.len(), divider);
            agg_map.insert(map_idx+1, local_agg_vec);
            map_idx+=1;
        }

        for i in agg_map.iter() {
            println!("In map: {} {}", i.0, i.1.len());
        }

        let mut sigs = Vec::new();
        for (pub_key, sig, bit_vec) in agg_map.get(&(agg_map.len()-1)).unwrap().iter() {
            sigs.push(sig);
        }

        let agg_sig = AggregateSignature::aggregate(&sigs, false).unwrap().to_signature();
        self.consensus_data = Arc::new(agg_map);

        println!("Finished Aggregation, Opening Connections");
        (agg_sig, signatures.get(0).unwrap().clone())
    }

    pub async fn open_connections(&mut self, sig_vec: Arc<Vec<Signature>>) {

        // Leaf nodes will send out messages to their parent
        setup_leaf_nodes(self, 10_000, self.m-1, sig_vec).await;
        println!("Finished preparing Simulator leaf connections");

        setup_parent_connections(self, 30_000, 127).await;
        println!("Finished preparing Simulator parent connections");

        for i in 1..self.depth {
            let base_port = 40_000 + 2000 * i;
            setup_parent_connections(self,base_port, 127).await;
        }

        println!("Finished Connections, sleeping for a sec");


        // Sleep a sec and let the thread creation and listener creation finish.
        sleep(Duration::from_secs(1));
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        setup_leaf_parent_connections(self,10_000, self.m).await;

        setup_children_connections(&self,30_000, self.m).await;

        for i in 0..self.depth {
            let base_port = 40_000 + 2000 * i;
            if i == 0 {
                setup_depth_children_connections(&self, base_port, self.m/self.leader_divider - 1, i, self.leader_divider).await;
            }
            else {
                setup_depth_children_connections(&self, base_port, self.m - 1, i, 1).await;
            }
        }
        println!("Finished connecting children to parent");
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        self.leaf_channels.send(()).unwrap();
        self.parent_channels.send(()).unwrap();
        self.leaf_parent_channels.send(()).unwrap();
    }
}

pub async fn setup_leaf_nodes(
    simulator: &mut Simulator,
    base_port: usize,
    range: usize,
    sigs: Arc<Vec<Signature>>
) {
    for i in 1..(range+1) {
        let port = base_port + i;
        let addr = format!("{}:{}", "leaf_aggregator", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = simulator.leaf_channels.subscribe();

        let clone = sigs.clone();
        // Spawn a task to accept connections on this listener
        PREPARE_POOL.spawn(async move {
            // We atm only need a single connection per port here (saves us from having a lot of async tasks doing nothing).
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    // Spawn a new task for each connection
                    rx.recv().await.unwrap();
                    socket.write(&clone[i].to_bytes()).await.unwrap();

                    // Await second channel to close connection.
                    rx.recv().await.unwrap();
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
}

pub async fn setup_parent_connections(
    simulator: &mut Simulator,
    base_port: usize,
    range: usize,
) {
    println!("Opening Ports: {} to {}", base_port + 1, base_port + range + 1);
    for i in 0..range {
        let port = base_port + i + 1;
        let addr = format!("{}:{}", "leaf_aggregator", port);
        let listener = TcpListener::bind(&addr).await.unwrap();

        let mut rx = simulator.parent_channels.subscribe();

        // Spawn a task to accept connections on this listener
        PREPARE_POOL.spawn(async move {
            let listener = listener;

            // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).
            match listener.accept().await {
                Ok((socket, addr)) => {
                    // Wait before closing connection.
                    rx.recv().await.unwrap();
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
}

/// These are the child processes of the first internal aggregator.
pub async fn setup_children_connections(simulator: &Simulator, base_port: usize, range: usize) {

    // We have m-1 connections. Each of them sends a signature aggregate. 20 distinct ones. The first one we already did!
    for i in 1..range {
        let port = base_port;
        let addr = format!("{}:{}", "aggregator1", port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let data_copy = simulator.consensus_data.clone();
        let local_idx = i/16;
        let priv_key = simulator.priv_keys.get(local_idx).unwrap().clone();

        PREPARE_POOL.spawn(async move {
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

pub async fn setup_leaf_parent_connections(simulator: &Simulator, base_port: usize, range: usize) {

    // We have m-1 connections. Each of them sends a signature aggregate. 20 distinct ones. The first one we already did!
    for i in 1..range {
        let port = base_port + i;
        let addr = format!("{}:{}", "leaf", port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        let mut rx = simulator.leaf_parent_channels.subscribe();

        PREPARE_POOL.spawn(async move {
            rx.recv().await.unwrap();
        });
    }
}

pub async fn setup_depth_children_connections(simulator: &Simulator, base_port: usize, range: usize, depth: usize, leader_divider: usize) {

    let reverse_idx = simulator.consensus_data.len() - depth - 1;

    for i in 1..(range+1) {
        let port = base_port;
        let addr = format!("{}:{}", format!("aggregator{}", depth) , port);
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        let data_copy = simulator.consensus_data.clone();

        let local_idx = i/16;

        let priv_key = simulator.priv_keys.get(local_idx).unwrap().clone();

        PREPARE_POOL.spawn(async move {
            let copy = data_copy.get(&reverse_idx).unwrap();
            let sub_copy = copy.get(local_idx);
            if sub_copy.is_none() {
                panic!("Couldn't find sig at depth {} {} {} {}", i, depth, reverse_idx, copy.len());
            }

            let (pub_key, agg_sig, bit_vec) = sub_copy.unwrap();

            let mut msg_bytes = agg_sig.to_bytes().to_vec();
            msg_bytes.append(&mut bit_vec.to_bytes().to_vec());
            msg_bytes.append(&mut agg_sig.to_bytes().to_vec());
            msg_bytes.append(&mut bit_vec.to_bytes().to_vec());

            let personal_sig = priv_key.sign(&msg_bytes, DST, &[]);

            stream.write(&local_idx.to_be_bytes()).await.unwrap();

            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&agg_sig.to_bytes()).await.unwrap();

            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&agg_sig.to_bytes()).await.unwrap();

            stream.write(&personal_sig.to_bytes()).await.unwrap();
        });
    }
}
