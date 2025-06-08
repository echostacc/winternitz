use rand;
use hex;
use sha2::{Sha256, Digest};

fn pretty_print_pairs(private_keys: Vec<String>, public_keys: Vec<String>) {
    // Pair private and public keys
    let pairs: Vec<(String, String)> = private_keys
        .iter()
        .zip(public_keys.iter())
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect();

    // Pretty print pairs
    for pair in pairs {
        println!("Private key: {} Public key: {}", pair.0, pair.1);
    }
}

fn main() {
    // Generate private keys (32x256-bit)
    let private_keys: Vec<String> = (0..32)
        .map(|_| {
            let private_key: [u8; 32] = rand::random();
            hex::encode(private_key)
        })
        .collect();

    let w: u8 = 8;
    let iterations = 1 << w; // 2^w iterations

    let mut public_keys: Vec<String> = Vec::new();
    
    // Generate public keys (32x256-bit), by hashing private keys w times
    for key in &private_keys {
        let mut hasher = Sha256::new();
        let mut current_key = key.clone();
        
        for _ in 0..iterations {
            hasher.update(current_key.as_bytes());
            let hash = hasher.clone().finalize();
            current_key = hex::encode(hash);
        }
        
        public_keys.push(current_key);
    }

    pretty_print_pairs(private_keys, public_keys);
}