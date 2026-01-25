#![allow(non_snake_case)]

use std::sync::Arc;
use blst::{byte};
use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use rand_core::RngCore;
use tokio::io::{AsyncWriteExt};
use crate::simulation::main::{DST, RUN_POOL};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;

pub struct LeafNode {
    // Fanout.
    pub(crate) m: usize,
    // Proposal byte vector.
    pub proposal: Arc<Vec<byte>>,
    pub public_keys: Arc<Vec<PublicKey>>,
    pub my_sig: Signature,
    pub agg_sig: Signature,
    pub parent_channels: broadcast::Sender<Signature>,
    pub pub_cache: Vec<AggregatePublicKey>,
    pub ip: String,
    pub participation_modifier: usize,
    pub depth_channel: broadcast::Sender<()>,
}

impl LeafNode {

    pub fn new(m: usize, proposal: &Vec<u8>, public_keys: Arc<Vec<PublicKey>>, my_sig: Signature, agg_sig: Signature, ip: &String, participation_modifier: usize, depth_channel: broadcast::Sender<()>) -> Self {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);

        LeafNode {
            m,
            proposal: Arc::new(proposal.clone()),
            public_keys,
            my_sig,
            agg_sig,
            parent_channels: Sender::new(2),
            pub_cache: Vec::new(),
            ip: ip.clone(),
            depth_channel,
            participation_modifier
        }
    }

    // Prepare simulator. Open all necessary sockets and initiate signatures and public keys.
    pub async fn connect(&mut self) {

        // We set up connections for: parent nodes.
        setup_parent_connections( 128, &mut self.parent_channels, self.depth_channel.clone()).await;
        println!("Finished preparing leaf connections");

        for i in 0..4 {
            let share = self.public_keys.len()/4;
            let pubs_copy = self.public_keys.clone();
            let j = i.clone()*share;
            let mut pub_vec = Vec::new();
            for index in j..(j+share){
                pub_vec.push(pubs_copy.get(index).unwrap());
            }

            self.pub_cache.push(AggregatePublicKey::aggregate(&pub_vec, false).unwrap());
        }
    }

    // Run simulator by notifying all threads to send the message to the client.
    pub async fn run(&mut self) {
        println!("Starting up Leaf node");

        self.verify(self.participation_modifier).await;
        self.verify(self.participation_modifier).await;

        self.parent_channels.send(self.my_sig.clone()).unwrap();
        println!("Awaiting sending proposal");
        self.parent_channels.closed().await;
    }

    pub async fn verify(&mut self, participation_modifier: usize) {
        let mut handles = Vec::new();
        let workers = RUN_POOL.metrics().num_workers();

        for i in 0..workers {
            let share = self.public_keys.len().div_ceil(workers);
            let mut pubs_cache_copy = self.pub_cache.get(i).unwrap().clone();
            let pubs_copy = self.public_keys.clone();

            let j = i.clone()*share;
            handles.push(RUN_POOL.spawn(async move {
                for index in j..(j+share).min(pubs_copy.len()){
                    if index % participation_modifier == 0 {
                        pubs_cache_copy.add_public_key(&crate::simulation::depth_based_internal_aggregator::invert_pub(pubs_copy.get(index).unwrap()), false).unwrap();
                    }
                }

                for index in j..(j+share).min(pubs_copy.len()){
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

pub async fn setup_parent_connections(range: usize, sender: &mut Sender<Signature>, depth_channel: broadcast::Sender<()>) {
    for i in 0..range {
        let port = 10_000 + i;
        let addr = format!("{}:{}", format!("leaf_aggregator"), port);

        // Spawn a task to accept connections on this listener
        let mut rx2 = sender.subscribe();
        let i_clone = i.clone();
        let rx = depth_channel.clone();

        RUN_POOL.spawn(async move {
            let mut stream = TcpStream::connect(&addr).await.unwrap();

            // Spawn a new task for each connection
            if let Ok(sig) = rx2.recv().await {

                if i_clone == 0 {
                    rx.send(()).unwrap();
                }

                let index : usize = 0;
                stream.write(&index.to_be_bytes()).await.unwrap();

                stream.write(&sig.to_bytes()).await.unwrap();
            }
        });
    }
}
