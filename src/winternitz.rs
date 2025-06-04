use rand::RngCore;
use sha2::{Sha256, Digest};

/// Winternitz One-Time Signature (WOTS) implementation
/// 
/// This is a quantum-resistant digital signature scheme based on hash functions.
/// Each key pair can only be used to sign ONE message securely.
/// 
/// The security is based on the one-way property of cryptographic hash functions.
pub struct Winternitz {
    /// Winternitz parameter: determines the trade-off between signature size and computation
    /// Higher values = smaller signatures but more computation
    w: u8,
    
    /// Private key: collection of random seeds, one for each hash chain
    /// Each seed is the starting point of a hash chain of length 2^w - 1
    private_key: Vec<Vec<u8>>,
    
    /// Public key: collection of final hash values from each chain
    /// These are obtained by hashing each private key seed 2^w - 1 times
    public_key: Vec<Vec<u8>>,
}

impl Winternitz {
    /// Creates a new Winternitz signature scheme instance
    /// 
    /// # Arguments
    /// * `w` - Winternitz parameter
    /// 
    /// # Returns
    /// A new Winternitz instance with generated private and public keys
    pub fn new(w: u8) -> Self {
        let mut rng = rand::thread_rng();
        
        // Calculate number of hash chains needed to cover all bits of SHA-256 hash
        // For SHA-256 (256 bits) with parameter w, we need ceil(256/w) chains
        // The +1 accounts for potential remainder and checksum
        let n = 256 / w as usize + 1;
        
        // Calculate the maximum length of each hash chain
        // Each chain can represent values from 0 to 2^w - 1
        let chain_length = (1 << w) - 1; // 2^w - 1

        let mut private_key = Vec::new();
        let mut public_key = Vec::new();

        // Generate n independent hash chains
        for _ in 0..n {
            let mut seed = vec![0u8; 32];
            rng.fill_bytes(&mut seed);

            // Start with the seed as the first element of the chain
            let mut current = seed.clone();

            // Apply SHA-256 hash chain_length times to create the public key
            // This creates a one-way chain: seed -> hash(seed) -> hash(hash(seed)) -> ... -> public_key
            for _ in 0..chain_length {
                current = Sha256::digest(&current).to_vec();
            }

            // Store the seed as private key (start of chain)
            private_key.push(seed);
            // Store the final hash as public key (end of chain)
            public_key.push(current);
        }

        Self {
            w,
            private_key,
            public_key,
        }
    }

    /// Signs a message using the Winternitz one-time signature scheme
    /// 
    /// # Arguments
    /// * `message` - The message bytes to be signed
    /// 
    /// # Returns
    /// A signature as a vector of hash values, one for each hash chain
    /// 
    /// # Algorithm
    /// 1. Hash the message using SHA-256
    /// 2. Split the hash into blocks based on parameter w
    /// 3. For each block value i, take the i-th element from the corresponding hash chain
    pub fn sign(&self, message: &[u8]) -> Vec<Vec<u8>> {
        let hash = Sha256::digest(message).to_vec();
        let mut signature = Vec::new();

        // Process each hash chain to generate signature components
        for i in 0..self.private_key.len() {
            // Extract the block value from the message hash
            // If we've processed all hash bytes, use 0 (for checksum chains)
            let block_value = if i < hash.len() {
                (hash[i] as usize).min((1 << self.w) - 1)
            } else {
                0
            };

            // Generate signature by hashing the private key seed block_value times
            // This reveals part of the hash chain up to position block_value
            let mut current = self.private_key[i].clone();
            for _ in 0..block_value {
                current = Sha256::digest(&current).to_vec();
            }
            signature.push(current);
        }

        signature
    }

    /// Verifies a Winternitz signature against a message
    /// 
    /// # Arguments
    /// * `message` - The original message that was signed
    /// * `signature` - The signature to verify
    /// 
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    /// 
    /// # Algorithm
    /// 1. Hash the message using SHA-256
    /// 2. For each signature component, continue hashing until reaching the public key
    /// 3. Compare the result with the stored public key
    pub fn verify(&self, message: &[u8], signature: &[Vec<u8>]) -> bool {
        let hash = Sha256::digest(message).to_vec();

        for i in 0..signature.len() {
            // Extract the same block value that was used during signing
            let block_value = if i < hash.len() {
                (hash[i] as usize).min((1 << self.w) - 1)
            } else {
                0 // For checksum chains
            };

            // Start with the signature component
            let mut current = signature[i].clone();
            
            // Calculate how many more hashes are needed to reach the public key
            // Public key is at position (2^w - 1), signature is at position block_value
            let remaining_hashes = ((1usize << self.w) - 1).saturating_sub(block_value);

            // Reach the public key
            for _ in 0..remaining_hashes {
                current = Sha256::digest(&current).to_vec();
            }

            // Compare the computed value with the stored public key
            if current != self.public_key[i] {
                return false; // Verification failed
            }
        }

        true // All components verified successfully
    }

    /// Returns a reference to the public key
    /// 
    /// The public key can be shared publicly and is used by others
    /// to verify signatures created with the corresponding private key.
    /// 
    /// # Returns
    /// A reference to the vector containing all public key components
    pub fn get_public_key(&self) -> &Vec<Vec<u8>> {
        &self.public_key
    }
}