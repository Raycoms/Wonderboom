#![allow(non_snake_case)]

use std::sync::Arc;
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use futures::SinkExt;
use rand_core::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::simulation::main::{DST, RUN_POOL};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

pub struct LeafAggregator {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    pub private_key: Arc<SecretKey>,
    pub leaf_channels: broadcast::Sender<()>,
    pub parent_channels: broadcast::Sender<(BitVec, Signature)>,
    pub public_keys: Arc<Vec<PublicKey>>,
    pub signature_channel: (async_channel::Sender<(usize, Signature)>, async_channel::Receiver<(usize, Signature)>),
    pub ip: String,
    pub depth_channel: broadcast::Sender<()>,
}

impl Default for LeafAggregator {
    fn default() -> Self {
        LeafAggregator {
            m: 0,
            private_key: Arc::new(SecretKey::default()),
            proposal: Arc::new(Vec::new()),
            leaf_channels: broadcast::Sender::new(2),
            parent_channels: broadcast::Sender::new(2),
            public_keys: Arc::new(Vec::new()),
            signature_channel: async_channel::bounded(1),
            depth_channel: broadcast::Sender::new(2),
            ip: "127.0.0.1".to_string(),
        }
    }
}

impl LeafAggregator {

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Arc<Vec<PublicKey>>, ip: &String, private_keys: Arc<Vec<SecretKey>>, depth_channel: broadcast::Sender<()>) -> Self {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        let private_key = Arc::new(private_keys.get(0).unwrap().clone());

        LeafAggregator {
            m,
            private_key,
            proposal: Arc::new(proposal.clone()),
            public_keys,
            ip: ip.clone(),
            depth_channel,
            signature_channel: async_channel::bounded(m),
            ..Default::default()
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {

        setup_parent_connections(&mut self.parent_channels, &self.private_key, self.depth_channel.clone()).await;
    }

    pub async fn open_connections(&mut self) {

        // We set up connections for: Leaf nodes, siblings & parent nodes.

        // Signature processing channel. todo move to constructor, those need to stay alive.
        // Leaf nodes will send out messages to their parent
        connect_to_leaf_nodes(10_000, self.m, self.signature_channel.0.clone(), &mut self.leaf_channels, self.proposal.clone(), self.public_keys.clone()).await;
        println!("Finished preparing Validator leaf connections");
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {

        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        let workers = RUN_POOL.metrics().num_workers();

        // How many sigs/pubs we want to aggregate in parallel.
        let parallel_slices = self.m.div_ceil(workers); //43
        let (mut final_agg_sender, mut final_agg_receiver) = mpsc::channel(100);

        let overshoot = parallel_slices * workers - self.m;

        for i in 0..workers {
            let mut rx2 = self.signature_channel.1.clone();
            let mut final_agg_sender_copy = final_agg_sender.clone();
            let m = self.m;
            let local_public_keys = self.public_keys.clone();
            let i_clone = i.clone();
            let m_copy = self.m.clone();

            //let proposal  = self.proposal.clone();
            RUN_POOL.spawn(async move {
                let mut pub_vec = Vec::with_capacity(parallel_slices);
                let mut sig_vec = Vec::with_capacity(parallel_slices);

                let mut pub_bit_vec = BitVec::from_elem(m, false);

                loop {
                    match rx2.recv().await {
                        Ok((id, sig)) => {
                            pub_vec.push(local_public_keys.get(id).unwrap());
                            sig_vec.push(sig);

                            pub_bit_vec.set(id.clone(), true);
                        }
                        _ => {}
                    }

                    if pub_vec.len() >= parallel_slices || (i_clone == workers - 1 && pub_vec.len() >= parallel_slices - overshoot) {
                        break;
                    }
                }

                let sig_refs: Vec<&Signature> = sig_vec.iter().collect();
                let agg_sig = AggregateSignature::aggregate(&sig_refs, false).unwrap();
                let agg_pub = AggregatePublicKey::aggregate(&pub_vec, false).unwrap();

                //agg_sig.to_signature().verify(false, &proposal, DST, &[], &agg_pub.to_public_key(), false);
                final_agg_sender_copy.send((pub_bit_vec, agg_sig, agg_pub, pub_vec.len())).await.unwrap();
            });
        }

        let (mut bit_vec, mut agg_sig, mut agg_pub, mut len) = final_agg_receiver.recv().await.unwrap();
        loop {
            let (local_bit_vec, local_agg_sig, local_agg_pub, local_len) = final_agg_receiver.recv().await.unwrap();
            agg_sig.add_aggregate(&local_agg_sig);
            agg_pub.add_aggregate(&local_agg_pub);
            len += local_len;
            bit_vec.or(&local_bit_vec);

            if len >= self.m {
                break;
            }
        }

        self.parent_channels.send((bit_vec, agg_sig.to_signature())).unwrap();
        self.parent_channels.closed().await;
    }

    // Kill simulator by closing all sockets and killing all idling threads.
    pub async fn kill(&mut self) {
        // Send command to close channels and connections to all channels in all channel types.
        // Send out the leaf votes.
        let _ = self.leaf_channels.send(());

        // Send out the sibling votes.
        //let _ = self.sibling_channels.send(());
    }
}

pub async fn connect_to_leaf_nodes(base_port : usize, range: usize, signature_sender: async_channel::Sender<(usize, Signature)>, sender: &mut broadcast:: Sender<()>, proposal: Arc<Vec<byte>>, local_public_keys: Arc<Vec<PublicKey>>) {
    let addr = format!("{}:{}", format!("leaf_aggregator"), base_port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    let tx_clone1 = signature_sender.clone();
    let mut rx1 = sender.clone();

    RUN_POOL.spawn(async move {
        for _ in 0..range {
            // Spawn a task to accept connections on this listener
            let mut rx = rx1.subscribe();

            let tx_clone = tx_clone1.clone();
            let local_public_keys = local_public_keys.clone();
            let proposal_clone = proposal.clone();
            match listener.accept().await {
                Ok((mut socket, addr)) => {
                    RUN_POOL.spawn(async move {
                        // Spawn a new task for each connection
                        // Wait to start reading messages.
                        rx.recv().await.unwrap();

                        // We're just expecting a single message from each leaf node.
                        let mut id_buffer = [0; size_of::<usize>()];
                        socket.read_exact(&mut id_buffer).await.unwrap();
                        let id = usize::from_be_bytes(id_buffer);

                        let mut buffer = [0; 96];
                        socket.read_exact(&mut buffer).await.unwrap();
                        if let Ok(sig) = Signature::from_bytes(&buffer) {
                            if sig.verify(false, &proposal_clone, DST, &[], local_public_keys.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                                tx_clone.send((id.clone(), sig)).await.unwrap();
                            }
                        } else {
                            eprintln!("Invalid signature bytes");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    });
}

pub async fn setup_parent_connections(sender: &mut broadcast::Sender<(BitVec, Signature)>, private_key: &Arc<SecretKey>, depth_channel: broadcast::Sender<()>) {
    for i in 0..128 {
        let port = 30_000 + i;
        let addr = format!("{}:{}", format!("aggregator2"), port);

        // Spawn a task to accept connections on this listener
        let mut rx = sender.subscribe();
        let private_key = private_key.clone();
        
        let i_clone = i.clone();
        let depth_channel = depth_channel.clone();

        RUN_POOL.spawn(async move {
            let mut stream = TcpStream::connect(&addr).await.unwrap();

            // Connect to parent for sending.
            // Just send a single message and disconnect.
            if let Ok((bit_vec, agg_sig)) = rx.recv().await {
                
                if i_clone == 0 {
                    depth_channel.send(()).unwrap();
                }

                let mut msg_bytes = agg_sig.to_bytes().to_vec();
                msg_bytes.append(&mut bit_vec.to_bytes().to_vec());

                let personal_sig = private_key.sign(&msg_bytes, DST, &[]);

                let index : usize = 0;
                stream.write(&index.to_be_bytes()).await.unwrap();
                stream.write(&bit_vec.to_bytes()).await.unwrap();
                stream.write(&agg_sig.to_bytes()).await.unwrap();
                stream.write(&personal_sig.to_bytes()).await.unwrap();
            }
        });
    }
}
