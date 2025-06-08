# Winternitz One-Time Signature

A quantum-resistant implementation of the Winternitz One-Time Signature (WOTS) scheme in Rust.

## Usage

```rust
use winternitz::Winternitz;

fn main() {
    // Create a new Winternitz instance
    let winternitz = Winternitz::new(8);
    
    // Sign a message
    let message = b"Hello, quantum-safe world!";
    let signature = winternitz.sign(message);
    
    // Verify the signature
    let is_valid = winternitz.verify(message, &signature);
    assert!(is_valid);
}
```

## API

- `Winternitz::new(w: u8)` - Create new instance
- `sign(&self, message: &[u8])` - Sign a message
- `verify(&self, message: &[u8], signature: &[Vec<u8>])` - Verify signature
- `get_public_key(&self)` - Get public key for distribution

## Parameter Selection

| w | Signature Size | Speed | Use Case |
|---|----------------|-------|----------|
| 4 | Large | Fast | High-frequency signing |
| 8 | Medium | Balanced | General purpose |
| 16 | Small | Slow | Space-constrained |

## Testing

```bash
cargo test
cargo run --example basic_usage
```

## License

MIT License - see [LICENSE](LICENSE) file.