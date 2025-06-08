#[path = "../src/winternitz.rs"]
mod winternitz;
use winternitz::Winternitz;

fn main() {
    println!("Winternitz One-Time Signature Demo");
    println!("================================================\n");

    let parameters = [4, 8, 16];
    
    for w in parameters {
        println!("Testing with Winternitz parameter w = {}", w);
        
        let winternitz = Winternitz::new(w);
        
        let message = format!("Signing with w={}", w);
        let message_bytes = message.as_bytes();
        
        let start_time = std::time::Instant::now();
        let signature = winternitz.sign(message_bytes);
        let sign_duration = start_time.elapsed();
        
        let start_time = std::time::Instant::now();
        let is_valid = winternitz.verify(message_bytes, &signature);
        let verify_duration = start_time.elapsed();
        
        println!("    Message: {}", message);
        println!("    Signing time: {:?}", sign_duration);
        println!("    Verification time: {:?}", verify_duration);
        println!("    Signature size: {} components", signature.len());
        println!("    Signature valid: {}", is_valid);
        
        if let Some(first_component) = signature.first() {
            println!("    First signature component (hex): {}", 
                hex::encode(&first_component[..8.min(first_component.len())]));
        }
        
        println!();
    }
    
    let winternitz = Winternitz::new(8);
    let public_key = winternitz.get_public_key();
    println!("Public Key Information:");
    println!("   Components: {}", public_key.len());
    println!("   Each component size: {} bytes", 
        public_key.first().map_or(0, |c| c.len()));
    println!("   Total public key size: {} bytes", 
        public_key.iter().map(|c| c.len()).sum::<usize>());
    
    println!("\nDemo completed successfully!");
}
