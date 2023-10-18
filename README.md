# A (naive) implementation of AES en/decryption for Noir

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains a Noir crate implementing the AES-128 encryption function.
It should be noted that this implementation only uses basic optimizations and mostly serves as a comparison point for more Zk-friendly encryption functions such as
[GMiMC](https://github.com/TaceoLabs/noir-gmimc) or [Hydra](https://github.com/TaceoLabs/noir-aes).

## Performance

A single call of the AES-128 encryption function requires about 380k constraints in the backend, compared to 4-6k for GMiMC and Hydra (which also encrypt 4 full field elements instead of 16 `u8`s).

## Installation

In your `Nargo.toml` file, add the following dependency:

```toml
[dependencies]
aes = { tag = "v0.1.0", git = "https://github.com/TaceoLabs/noir-aes" }
```

## Examples

To compute a hash from three Field elements, write:

```Rust
use dep::aes;

let pt = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
let key = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f];
let ct = [0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a];
assert(aes::aes_128_enc(pt, key) == ct);
```

## Disclaimer

This is **experimental software** and is provided on an "as is" and "as available" basis. We do **not give any warranties** and will **not be liable for any losses** incurred through any use of this code base.
