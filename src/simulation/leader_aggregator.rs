#![allow(non_snake_case)]

use std::collections::{BTreeMap};
use std::sync::{Arc};
use async_channel::{Receiver, Sender};
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use tokio::io::{AsyncReadExt};
use tokio::net::{TcpListener};
use tokio::sync::{broadcast};
use crate::simulation::main::{DST, RUN_POOL};

pub struct LeaderAggregator {
    pub m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    // Channels to wake up children connection to start reading messages.
    pub child_channels: broadcast::Sender<()>,
    // Public keys of all nodes in the system.
    pub public_keys: Arc<Vec<PublicKey>>,
    // Channel to hand signatures that come from the children and process them.
    pub signature_receiver: Receiver<(usize,BitVec, Signature, PublicKey)>,
}

impl Default for LeaderAggregator {
    fn default() -> Self {
        LeaderAggregator {
            m: 0,
            proposal: Arc::new(Vec::new()),
            child_channels: broadcast::Sender::new(2),
            public_keys: Arc::new(Vec::new()),
            signature_receiver: async_channel::unbounded().1,
        }
    }
}

impl LeaderAggregator {

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Arc<Vec<PublicKey>>) -> Self {
        LeaderAggregator {
            m,
            proposal: Arc::new(proposal.clone()),
            public_keys: public_keys.clone(),
            ..Default::default()
        }
    }

    pub async fn open_connections(&mut self) {

        let (signature_sender, signature_receiver) = async_channel::bounded(2048*16);
        connect_to_child_nodes(self.m, &self.proposal, &self.public_keys, &mut self.child_channels, signature_sender).await;
        self.signature_receiver=signature_receiver;

        println!("Finished preparing internal aggregator connections");
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {

        // Activate the child connection to start receiving messages.
        self.child_channels.send(()).unwrap();

        println!("Finished preparing Validator sibling connections");

        let mut biggest_result_map: BTreeMap<usize, (BitVec, Signature, PublicKey)> = BTreeMap::new();

        let mut runs = 0;
        while let Ok((idx, bit_vec, sig, pub_key)) = self.signature_receiver.recv().await {
            runs+=1;

            if let Some((local_bit_vec, local_sig, local_pub_key)) = biggest_result_map.get(&idx) {
                if bit_vec.count_ones() > local_bit_vec.count_ones() {
                    // If bigger insert.
                    biggest_result_map.insert(idx, (bit_vec.clone(), sig, pub_key));
                }
            } else {
                biggest_result_map.insert(idx, (bit_vec.clone(), sig, pub_key));
                continue
            }

            if runs >= 2048 * 16 {
                break;
            }
        }

        println!("Got all the sigs {}", biggest_result_map.len());

        let biggest_future = RUN_POOL.spawn_blocking(move || {
            // do some expensive computation
            let mut pub_vec = Vec::new();
            let mut sig_vec = Vec::new();
            let mut result_bit_vec = BitVec::new();
            for (idx, (bit_vec, sig, pub_key)) in biggest_result_map.iter() {
                result_bit_vec.extend(bit_vec);
                sig_vec.push(sig);
                pub_vec.push(pub_key);
            }

            // let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap().to_public_key();
            let agg_sig = AggregateSignature::aggregate(&sig_vec, false).unwrap().to_signature();

            //disable, not necessary.
            //if !agg_sig.verify(false, &proposal_copy, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
            //    panic!("Failed to verify agg signature");
            //}
            return (result_bit_vec, agg_sig);
        });

        let (biggest_bit_vec, biggest_agg_sig) = biggest_future.await.unwrap();
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        // Send out the leaf votes.
        self.child_channels.send(()).unwrap();
    }
}

// connect to m child nodes. So we assume they're al
pub async fn connect_to_child_nodes(m: usize, proposal: &Arc<Vec<byte>>, public_keys: &Arc<Vec<PublicKey>>, sender: &broadcast::Sender<()>, signature_sender: Sender<(usize, BitVec, Signature, PublicKey)>) {

    // Listen on base port for connection attempts.
    let port = 10_000;
    let addr = format!("{}:{}", "leader", port);
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on {}", addr);
    let mut local_sender = sender.clone();

    let sender_copy = signature_sender.clone();
    let public_keys_copy = public_keys.clone();
    let proposal_copy = proposal.clone();
    let m_copy = m.clone();
    RUN_POOL.spawn(async move {
        for _ in 0..(32*64) {
            let mut rx = local_sender.subscribe();
            let port_string = port.to_string();
            let local_sender_copy = sender_copy.clone();
            let local_public_keys_copy = public_keys_copy.clone();
            let local_proposal_copy = proposal_copy.clone();
            match listener.accept().await {
                Ok((mut socket, address)) => {

                    RUN_POOL.spawn(async move {
                        // We atm only need a single connection per port here (saves us from having a lot of thread doing nothing).

                        // Wait before starting operation
                        rx.recv().await.unwrap();
                        
                        let mut group_id_buffer = [0; size_of::<usize>()];
                        socket.read_exact(&mut group_id_buffer).await.unwrap();
                        let group_id = usize::from_be_bytes(group_id_buffer);

                        let mut bit_vec_buffer = vec![0u8; m_copy.div_ceil(8)];
                        socket.read_exact(&mut bit_vec_buffer).await.unwrap();
                        let bit_vec = BitVec::from_bytes(&bit_vec_buffer);

                        let mut sig_buffer = [0; 96];
                        socket.read_exact(&mut sig_buffer).await.unwrap();
                        let sig = match Signature::from_bytes(&sig_buffer) {
                            Ok(sig) => {
                                sig
                            }
                            Err(err) => {
                                eprintln!("FI: BLS load Error 1 {:?}", err);
                                return;
                            }
                        };

                        let mut personal_sig_buffer = [0; 96];
                        socket.read_exact(&mut personal_sig_buffer).await.unwrap();

                        let personal_sig = match Signature::from_bytes(&personal_sig_buffer) {
                            Ok(sig) => {
                                sig
                            }
                            Err(err) => {
                                eprintln!("FI: BLS load Error 2 {:?}", err);
                                return;
                            }
                        };

                        let mut msg = sig_buffer.to_vec();
                        msg.append(&mut bit_vec_buffer.to_vec());
                        
                        for _ in 0..16 {
                            if !personal_sig.verify(false, &msg, DST, &[], &local_public_keys_copy.get(group_id).unwrap(), false).eq(&BLST_SUCCESS) {
                                println!("1 Invalid Sig from {}", address);
                            } else {
                                let mut pubs = Vec::new();
                                let start_index = group_id * m_copy;
                                for (local_index, available) in bit_vec.iter().enumerate() {
                                    if available {
                                        let index = start_index + local_index;
                                        pubs.push(local_public_keys_copy.get(index).unwrap());
                                    }
                                }
                                let pub_key = AggregatePublicKey::aggregate(&pubs, false).unwrap().to_public_key();

                                // This verify is only necessary in the worst case here. For a best/avg-case simulation we can drop this.
                                if sig.verify(false, &local_proposal_copy, DST, &[], &pub_key, false).eq(&BLST_SUCCESS) {
                                    local_sender_copy.send((group_id, bit_vec.clone(), sig, pub_key)).await.unwrap();
                                } else {
                                    println!("FI: Invalid Sig from {} {}", group_id, address);
                                }
                            }
                        }
                        
                        // Wait before closing connection.
                        rx.recv().await.unwrap();
                    });
                }
                e => {
                    println!("Connection from {:?} not accepted", e);
                }
            }
        }
    });
}

