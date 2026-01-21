use std::fs::{File, OpenOptions};
use std::{fs, io};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::sync::Arc;
use bincode::{de::Decoder, enc::Encoder, Decode, Encode};
use blst::min_pk::{PublicKey, SecretKey, Signature};
use rand_core::{OsRng, RngCore};
use crate::simulation::main::{DST, PREPARE_POOL};

struct CryptoTuple {
    secret_key: SecretKey,
    public_key: PublicKey,
    signature: Signature,
}

impl Encode for CryptoTuple {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), bincode::error::EncodeError> {
        // Encode fields in order
        bincode::Encode::encode(&self.secret_key.to_bytes(), encoder)?;
        bincode::Encode::encode(&(self.signature.to_bytes()), encoder)?;

        Ok(())
    }
}

impl <Context> Decode<Context> for CryptoTuple {
    fn decode<D: Decoder<Context = Context>>(decoder: &mut D, ) -> Result<Self, bincode::error::DecodeError> {
        let secret_bytes: [u8; 32] = bincode::Decode::decode(decoder)?;
        let sig_bytes: [u8; 96] = bincode::Decode::decode(decoder)?;

        let secret_key: SecretKey = SecretKey::from_bytes(&secret_bytes).unwrap();
        let signature: Signature = Signature::from_bytes(&sig_bytes).unwrap();

        Ok(CryptoTuple {
            public_key: secret_key.sk_to_pk(),
            secret_key,
            signature
        })
    }
}

pub async fn generate_or_load(N: usize) -> ((Arc<Vec<SecretKey>>, Arc<Vec<PublicKey>>, Arc<Vec<Signature>>), Vec<u8>) {

    let mut proposal = vec![0u8; 100_000];
    load_or_create_proposal(&mut proposal);
    (load_or_create_crypto(N, &proposal).await, proposal)
}

fn load_or_create_proposal(buffer: &mut [u8]) {
    let path = "data/proposal.txt";
    fs::create_dir_all("data").unwrap();

    match File::open(path) {
        Ok(mut file) => {
            if let Err(e) = file.read_exact(buffer) {
               println!("Failed to read proposal {}", e);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            OsRng.fill_bytes(buffer);
            let mut file = File::create(path).unwrap();
            file.write_all(buffer).unwrap();
            file.sync_all().unwrap();
        }
        _ => {}
    }
}

async fn load_or_create_crypto(N: usize, proposal: &Vec<u8>) -> (Arc<Vec<SecretKey>>, Arc<Vec<PublicKey>>, Arc<Vec<Signature>>) {

    let mut private_keys = Vec::with_capacity(N);
    let mut public_keys = Vec::with_capacity(N);
    let mut signatures = Vec::with_capacity(N);
    let config = bincode::config::standard().with_fixed_int_encoding();;

    match File::open("data/signatures.bin") {
        Ok(file) => {
            let mut reader = BufReader::new(file);

            // Keep deserializing until the end of the file
            loop {
                let result: Result<CryptoTuple, _> = bincode::decode_from_std_read(&mut reader, config);

                match result {
                    Ok(crypto_tuple) => {
                        private_keys.push(crypto_tuple.secret_key);
                        public_keys.push(crypto_tuple.public_key);
                        signatures.push(crypto_tuple.signature);
                    }
                    Err(e) => {
                        // Check if we hit the end of the file naturally
                        if let bincode::error::DecodeError::Io { inner, .. } = &e {
                            if inner.kind() == ErrorKind::UnexpectedEof {
                                break; // Finished successfully
                            }
                        }
                        panic!("error reading! {:?}", e);
                    }
                }
            }
        }
        _ => {}
    };

    if public_keys.len() > N {
        private_keys.truncate(N);
        public_keys.truncate(N);
        signatures.truncate(N);

        return (Arc::new(private_keys), Arc::new(public_keys), Arc::new(signatures));
    }
    let missing = N - public_keys.len();
    let file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("data/signatures.bin").unwrap();

    if missing > 0 {
        println!("{} signatures missing, generating now.", missing);

        let (sender, mut receiver) = tokio::sync::mpsc::channel(N);
        let share = missing.div_ceil(8);
        let mut missing_share = missing;
        for _ in 0..8 {
            let proposal_copy = proposal.clone();
            let local_share = share.min(missing_share);
            let sender_clone = sender.clone();

            missing_share -= local_share;
            PREPARE_POOL.spawn(async move {
                println!("Starting task with share: {}", local_share);
                for _ in 0..local_share {
                    let mut ikm = [0u8; 32];
                    {
                        let mut rng = rand::thread_rng();
                        rng.fill_bytes(&mut ikm);
                    }
                    let pvt_key = SecretKey::key_gen(&ikm, &[]).unwrap();
                    let pub_key = pvt_key.sk_to_pk();
                    sender_clone.send((pub_key, pvt_key.sign(&proposal_copy, DST, &[]), pvt_key)).await.unwrap();
                }
                drop(sender_clone);
            });
        }
        drop(sender);

        let mut writer = BufWriter::new(file);
        while let Some((pub_key, sig, pvt_key)) = receiver.recv().await {
            public_keys.push(pub_key.clone());
            private_keys.push(pvt_key.clone());
            signatures.push(sig.clone());
            if signatures.len() % 100_000 == 0 {
                println!("Got 100k Sigs, now at: {}", signatures.len());
            }
            bincode::encode_into_std_write(&CryptoTuple { public_key: pub_key, secret_key: pvt_key, signature: sig }, &mut writer, config).unwrap();
        }
        writer.flush().unwrap();
    }

    private_keys.truncate(N);
    public_keys.truncate(N);
    signatures.truncate(N);

    (Arc::new(private_keys), Arc::new(public_keys), Arc::new(signatures))
}
