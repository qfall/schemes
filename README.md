# qFALL-schemes
[<img alt="github" src="https://img.shields.io/badge/qfall--schemes-github?style=for-the-badge&logo=github&label=github&color=8da0cb" height="20">](https://github.com/qfall/schemes)
[<img alt="crates.io" src="https://img.shields.io/badge/qfall--schemes-cratesio?style=for-the-badge&logo=rust&label=crates&color=fc8d62" height="20">](https://crates.io/crates/qfall-schemes)
[<img alt="docs.rs" src="https://img.shields.io/badge/qfall--schemes-docs?style=for-the-badge&logo=docs.rs&label=docs.rs&color=66c2a5" height="20">](https://docs.rs/qfall-schemes)
[<img alt="tutorial" src="https://img.shields.io/badge/book-tutorial?style=for-the-badge&logo=mdBook&label=Tutorial&color=ffd92f" height="20">](https://qfall.github.io/book)
[<img alt="build" src="https://img.shields.io/github/actions/workflow/status/qfall/schemes/push.yml?branch=main&style=for-the-badge" height="20">](https://github.com/qfall/schemes/actions/workflows/push.yml)
[<img alt="license" src="https://img.shields.io/badge/License-MPL_2.0-blue.svg?style=for-the-badge" height="20">](https://github.com/qfall/schemes/blob/dev/LICENSE)

`qFALL` is a prototyping library for lattice-based cryptography.
This `schemes`-crate collects implementations of lattice-based constructions to reuse them more easily in more complex constructions or protocols.

## Quick-Start
First, ensure that you use a Unix-like distribution (Linux or MacOS). Setup [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) if you're using Windows. This is required due to this crate's dependency on FLINT.
Then, make sure your `rustc --version` is `1.85` or newer. 

Furthermore, it's required that `m4`, a C-compiler such as `gcc`, and `make` are installed.
```bash
sudo apt-get install m4 gcc make
```
Then, add you can add this crate to your project by executing the following command.
```bash
cargo add qfall-schemes
```
- Find further information on [our website](https://qfall.github.io/). Also check out [`qfall-math`](https://crates.io/crates/qfall-math) and [`qfall-tools`](https://crates.io/crates/qfall-tools).
- Read the [documentation of this crate](https://docs.rs/qfall-schemes).
- We recommend [our tutorial](https://qfall.github.io/book) to start working with qFALL.

## What does qFALL-schemes offer?
qFALL-schemes collects prototype implementations of lattice-based constructions to reuse them more easily in more complex constructions or protocols.

List of prototypes available
- [Public Key Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/index.html)
  - [LWE Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/struct.Regev.html)
  - [Dual LWE Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/struct.DualRegev.html)
  - [LPR Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/struct.LPR.html)
  - [Ring-based LPR Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/struct.RingLPR.html)
  - [K-PKE](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/struct.KPKE.html), which is the foundation of [CRYSTALS-Kyber](https://pq-crystals.org/kyber/) and [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
  - [CCA-secure Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/pk_encryption/struct.CCSfromIBE.html)
- [Signatures](https://docs.rs/qfall-schemes/latest/qfall_schemes/signature/index.html)
  - [Full-Domain Hash (FDH)](https://docs.rs/qfall-schemes/latest/qfall_schemes/signature/fdh/struct.FDHGPV.html)
  - [Probabilistic FDH (PFDH)](https://docs.rs/qfall-schemes/latest/qfall_schemes/signature/pfdh/struct.PFDHGPV.html)
  - [Ring-based FDH](https://docs.rs/qfall-schemes/latest/qfall_schemes/signature/fdh/struct.FDHGPVRing.html)
- [Identity Based Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/identity_based_encryption/index.html)
  - [From Dual LWE Encryption](https://docs.rs/qfall-schemes/latest/qfall_schemes/identity_based_encryption/struct.DualRegevIBE.html)
- [Hash Functions](https://docs.rs/qfall-schemes/latest/qfall_schemes/hash/index.html)
  - [SIS-Hash Function](https://docs.rs/qfall-schemes/latest/qfall_schemes/hash/struct.SISHash.html)
  - [SHA-256-based Hash](https://docs.rs/qfall-schemes/latest/qfall_schemes/hash/sha256/index.html)

## Quick Examples
Kyber's Public-Key Encryption
```rust
use qfall_schemes::pk_encryption::{KPKE, PKEncryptionScheme};
use qfall_math::integer::Z;

// setup public parameters
let k_pke = KPKE::ml_kem_512();

// generate (pk, sk) pair
let (pk, sk) = k_pke.gen();

// encrypt a message
let msg = Z::from_uft8("Hello");
let cipher = k_pke.enc(&pk, &msg);

// decrypt the ciphertext
let m = k_pke.dec(&sk, &cipher);

assert_eq!(msg, m);
```

GPV-based Probabilistic Full-Domain Hash
```rust
use qfall_schemes::signature::{pfdh::PFDHGPV, SignatureScheme};

let mut pfdh = PFDHGPV::setup(4, 113, 17, 128);

let msg = "Hello World!";

let (pk, sk) = pfdh.gen();
let sigma = pfdh.sign(msg.clone(), &sk, &pk);

assert!(pfdh.vfy(msg.clone(), &sigma, &pk));
```

## Bugs
Please report bugs through the [GitHub issue tracker](https://github.com/qfall/schemes/issues).

## Contributions
Contributors are:
- Marvin Beckmann
- Phil Milewski
- Jan Niklas Siemer

A few reasons to merge your prototype into qFALL-schemes.
- In case of API changes, a version update of Rust or adapted formatting requirements, prototypes in this crate be kept executable and up-to-date.
- qFALL may benefit from your contribution as most prototypes are built with some optimisation in mind. We may consider integrating your optimisation into [`qfall-math`](https://crates.io/crates/qfall-math) and [`qfall-tools`](https://crates.io/crates/qfall-tools).
- We ensure that prototypes are properly formatted, modularised, and documented before merging s.t. prototypes yield a reusable resource to the community.
- Researchers and developers may benefit from the public exposure of their prototype (and the often associated paper).

See [Contributing](https://github.com/qfall/schemes/blob/dev/CONTRIBUTING.md) for details on how to contribute.

## Citing
Please use the following bibtex entry to cite [qFALL](https://qfall.github.io).
```text
TODO: Update to eprint
```

## Dependencies
This project is based on [qfall-math](https://crates.io/crates/qfall-math) and [qfall-tools](https://crates.io/crates/qfall-tools), which build on top of the C-based, optimised math-library [FLINT](https://flintlib.org/). We utilise [serde](https://crates.io/crates/serde) and [serde_json](https://crates.io/crates/serde_json) to (de-)serialize objects to and from JSON. This crate relies on [criterion](https://crates.io/crates/criterion) for benchmarking purposes. An extensive list can be found in our `Cargo.toml` file.

## License
This library is distributed under the [Mozilla Public License Version 2.0](https://github.com/qfall/schemes/blob/dev/LICENSE).
Permissions of this weak copyleft license are conditioned on making the source code of licensed files and modifications of those files available under the same license (or in certain cases, under one of the GNU licenses). Copyright and license notices must be preserved. Contributors provide an express grant of patent rights. However, a larger work using the licensed work may be distributed under different terms and without source code for files added to the larger work.
