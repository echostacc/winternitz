//! # Winternitz One-Time Signature Implementation
//! 
//! A comprehensive, secure implementation of the Winternitz One-Time Signature (WOTS) scheme in Rust.
//! 
//! ## Features
//! 
//! - **Quantum-Resistant**: Based on hash functions, resistant to quantum computer attacks
//! - **Configurable**: Supports different Winternitz parameters (w) for size/performance trade-offs
//! - **Secure**: Implements proper overflow protection and error handling
//! - **Well-Documented**: Comprehensive documentation and examples
//! 
//! ## Security Warning
//! 
//! **CRITICAL**: Each Winternitz key pair should only be used to sign ONE message!
//! Reusing keys compromises security and may leak private key information.
//! 
//! ## Example
//! 
//! ```rust
//! use winternitz::winternitz::Winternitz;
//! 
//! // Create a new Winternitz instance with parameter w=8
//! let wots = Winternitz::new(8);
//! 
//! // Sign a message (only do this ONCE per key pair!)
//! let message = b"Hello, quantum-resistant world!";
//! let signature = wots.sign(message);
//! 
//! // Verify the signature
//! let is_valid = wots.verify(message, &signature);
//! assert!(is_valid);
//! ```

pub mod winternitz;

pub use winternitz::Winternitz;