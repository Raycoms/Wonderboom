#![allow(non_snake_case)]

use std::sync::Arc;
use bit_vec::BitVec;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use futures::SinkExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::simulation::main::{DST, PREPARE_POOL, RUN_POOL};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::sync::broadcast::Sender;

pub struct LeafAggregator {
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    pub public_key: PublicKey,
    pub private_key: Arc<SecretKey>,
    pub leaf_channels: broadcast::Sender<()>,
    pub parent_channels: broadcast::Sender<(BitVec, Signature)>,
    pub public_keys: Arc<Vec<PublicKey>>,
    pub signature_channel: (async_channel::Sender<(usize, Signature)>, async_channel::Receiver<(usize, Signature)>),
    pub pub_cache: Vec<AggregatePublicKey>,
    pub participation_modifier: usize,
    pub agg_sig: Signature,
    pub my_sig: Signature,
    pub m: usize,
    pub depth_channel_leaf: broadcast::Sender<()>,
    pub depth_channel_agg: broadcast::Sender<()>
}

impl LeafAggregator {

    pub fn new(proposal: &Vec<u8>, public_keys: Arc<Vec<PublicKey>>, private_keys: Arc<Vec<SecretKey>>, participation_modifier: usize, m: usize, agg_sig: Signature, my_sig: Signature, depth_channel_leaf: Sender<()>, depth_channel_agg: Sender<()>) -> Self {
        let private_key = Arc::new(private_keys.get(0).unwrap().clone());

        LeafAggregator {
            public_key: private_key.sk_to_pk(),
            private_key,
            proposal: Arc::new(proposal.clone()),
            public_keys,
            participation_modifier,
            pub_cache: Vec::new(),
            signature_channel: async_channel::bounded(m),
            leaf_channels: broadcast::Sender::new(2),
            parent_channels: broadcast::Sender::new(2),
            agg_sig,
            my_sig,
            m,
            depth_channel_leaf,
            depth_channel_agg
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {

        // We set up connections for: Leaf nodes, siblings & parent nodes.

        // Signature processing channel.

        // Leaf nodes will send out messages to their parent
        connect_to_leaf_nodes_send(&mut self.leaf_channels, self.my_sig.clone(), self.m, self.depth_channel_leaf.clone()).await;
        connect_to_leaf_nodes_receive(self.signature_channel.0.clone(), &mut self.leaf_channels, self.m, self.proposal.clone(), self.public_keys.clone()).await;

        println!("Finished preparing Validator leaf connections");

        let workers = RUN_POOL.metrics().num_workers();

        for i in 0..workers {
            let share = self.public_keys.len().div_ceil(workers);
            let pubs_copy = self.public_keys.clone();
            let j = i.clone() * share;
            let mut pub_vec = Vec::new();
            for index in j..(j+share).min(pubs_copy.len()){
                pub_vec.push(pubs_copy.get(index).unwrap());
            }

            self.pub_cache.push(AggregatePublicKey::aggregate(&pub_vec, false).unwrap());
        }

        setup_leader_connection(&mut self.parent_channels, &self.private_key, self.depth_channel_agg.clone()).await;

        let _ = self.signature_channel.0.send((0, self.my_sig.clone())).await;
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {

        println!("Starting up Leaf node");

        self.verify(self.participation_modifier).await;

        println!("Finished Verification");

        // Send out the leaf votes.
        self.leaf_channels.send(()).unwrap();

        let workers = RUN_POOL.metrics().num_workers();
        let m_clone = self.m.clone();

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

        println!("Reached Aggregation part.");

        let (mut bit_vec, mut agg_sig, mut agg_pub, mut len) = final_agg_receiver.recv().await.unwrap();
        loop {
            let (local_bit_vec, local_agg_sig, local_agg_pub, local_len) = final_agg_receiver.recv().await.unwrap();
            agg_sig.add_aggregate(&local_agg_sig);
            agg_pub.add_aggregate(&local_agg_pub);
            len += local_len;
            bit_vec.or(&local_bit_vec);

            if len >= m_clone {
                break;
            }
        }

        self.parent_channels.send((bit_vec, agg_sig.to_signature())).unwrap();
        self.parent_channels.closed().await;
    }

    pub async fn verify(&mut self, participation_modifier: usize) {
        let mut handles = Vec::new();

        let workers = RUN_POOL.metrics().num_workers();
        for i in 0..workers {
            let share = self.public_keys.len().div_ceil(workers);
            let mut pubs_cache_copy = self.pub_cache.get(i).unwrap().clone();
            let pubs_copy = self.public_keys.clone();

            let j = i.clone() * share;
            handles.push(RUN_POOL.spawn(async move {
                for index in j..(j+share).min(pubs_copy.len()) {
                    if index % participation_modifier == 0 {
                        pubs_cache_copy.add_public_key(&invert_pub(pubs_copy.get(index).unwrap()), false).unwrap();
                    }
                }

                for index in j..(j+share).min(pubs_copy.len()) {
                    if index % participation_modifier == 0 {
                        pubs_cache_copy.add_public_key(pubs_copy.get(index).unwrap(), false).unwrap();
                    }
                }
                pubs_cache_copy.to_public_key()
            }));
        }

        let mut final_pub_vec = Vec::new();
        for handle in handles {
            final_pub_vec.push(handle.await.unwrap());
        }

        let final_pub_vec = final_pub_vec.iter().collect::<Vec<&PublicKey>>();

        let agg_pub = AggregatePublicKey::aggregate(&final_pub_vec, false).unwrap().to_public_key();


        // This is the same proposal we're signing, but that's okay. It's just for complexity sake.
        if !self.agg_sig.verify(false, &self.proposal, DST, &[], &agg_pub, false).eq(&BLST_SUCCESS) {
            panic!("Failed to verify agg signature");
        }
    }
}

pub fn invert_pub(pk: &PublicKey) -> PublicKey {
    let affine: &blst::blst_p1_affine = pk.into();
    let mut p1 = blst::blst_p1::default();
    unsafe { blst::blst_p1_from_affine(&mut p1, affine) };
    unsafe { blst::blst_p1_cneg(&mut p1, true) };
    let mut neg_affine = blst::blst_p1_affine::default();
    unsafe { blst::blst_p1_to_affine(&mut neg_affine, &p1) };
    PublicKey::from(neg_affine)
}

pub async fn connect_to_leaf_nodes_send(sender: &mut Sender<()>, signature: Signature, m: usize, depth_channel_leaf: broadcast::Sender<()>) {
    let port = 10_000;
    let addr = format!("{}:{}", "aggregator", port);
    let listener = TcpListener::bind(&addr).await.unwrap();

    println!("Listening on {}", addr);
    let mut local_sender = sender.clone();

    let m_copy = m.clone();
    PREPARE_POOL.spawn(async move {
        for i in 1..m_copy {
            let mut rx = local_sender.subscribe();
            let sig_copy = signature.clone();
            let depth_channel = depth_channel_leaf.clone();
            let i_clone = i.clone();

            match listener.accept().await {
                Ok((mut socket, address)) => {
                    RUN_POOL.spawn(async move {
                        rx.recv().await.unwrap();

                        if i_clone == 1 {
                            depth_channel.send(()).unwrap();
                        }
                        socket.write(&i_clone.to_be_bytes()).await.unwrap();

                        socket.write(&sig_copy.to_bytes()).await.unwrap();
                    });
                }
                e => {
                    println!("Connection from {:?} not accepted", e);
                }
            }
        }
    });
}

// Connect to the other leaf nodes and receive m signatures for aggregation.
pub async fn connect_to_leaf_nodes_receive(signature_sender: async_channel::Sender<(usize, Signature)>, sender: &mut Sender<()>, m: usize, proposal: Arc<Vec<byte>>, local_public_keys: Arc<Vec<PublicKey>>) {
    for i in 1..m {
        let port = 10_000 + i;
        let addr = format!("{}:{}", "leaf", port);

        let mut local_sender = sender.subscribe();

        let local_public_keys = local_public_keys.clone();
        let proposal_clone = proposal.clone();
        // Spawn a task to accept connections on this listener
        let tx_clone = signature_sender.clone();
        RUN_POOL.spawn(async move {
            let mut stream = TcpStream::connect(&addr).await.unwrap();

            // Wait to start reading messages.
            local_sender.recv().await.unwrap();

            let mut id_buffer = [0; size_of::<usize>()];
            stream.read_exact(&mut id_buffer).await.unwrap();
            let id = usize::from_be_bytes(id_buffer);

            // We're just expecting a single message from each leaf node.
            let mut buffer = [0; 96];
            stream.read_exact(&mut buffer).await.unwrap();
            if let Ok(sig) = Signature::from_bytes(&buffer) {
                if sig.verify(false, &proposal_clone, DST, &[], local_public_keys.get(id).unwrap(), false).eq(&BLST_SUCCESS) {
                    tx_clone.send((id.clone(), sig)).await.unwrap();
                }
            } else {
                eprintln!("Invalid signature bytes");
            }
        });
    }
}

// Connect to leader and send aggregate.
pub async fn setup_leader_connection(sender: &mut Sender<(BitVec, Signature)>, private_key: &Arc<SecretKey>, depth_channel_agg: Sender<()>) {
    let addr = format!("{}:{}", "leader", 10_000);

    // Spawn a task to accept connections on this listener
    let mut rx = sender.subscribe();
    let private_key = private_key.clone();

    RUN_POOL.spawn(async move {
        let mut stream = TcpStream::connect(&addr).await.unwrap();

        // Connect to parent for sending.
        // Just send a single message and disconnect.
        if let Ok((bit_vec, agg_sig)) = rx.recv().await {
            let mut msg_bytes = agg_sig.to_bytes().to_vec();
            msg_bytes.append(&mut bit_vec.to_bytes().to_vec());

            let personal_sig = private_key.sign(&msg_bytes, DST, &[]);

            depth_channel_agg.send(()).unwrap();

            let index: usize = 0;
            stream.write(&index.to_be_bytes()).await.unwrap();
            stream.write(&bit_vec.to_bytes()).await.unwrap();
            stream.write(&agg_sig.to_bytes()).await.unwrap();
            stream.write(&personal_sig.to_bytes()).await.unwrap();
        }
    });
}
