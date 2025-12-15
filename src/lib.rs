// Copyright © 2023 Niklas Siemer, Marvin Beckmann
//
// This file is part of qFALL-schemes.
//
// qFALL-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! `qFALL` is a prototyping library for lattice-based cryptography.
//! `qFALL-schemes` collects prototype implementations of lattice-based cryptography
//! s.t. the community can reuse them in more complex constructions or protocols.
//! Among these are traits and implemented constructions of:
//! - [Public-Key Encryption schemes](pk_encryption) implementations such as [Regev's Encryption](pk_encryption::Regev), [its dual version](pk_encryption::DualRegev), [LPR](pk_encryption::LPR), or [K-PKE](pk_encryption::KPKE),
//! - [Signature schemes](signature) implementations such as GPV-based [FDH](signature::fdh) or [PFDH](signature::fdh),
//! - an [Identity-based Encryption](identity_based_encryption) from [Dual Regev](identity_based_encryption::DualRegevIBE), as well as
//! - [Hash functions](hash) such as the [SIS hash](hash::SISHash) or a [SHA256-based hash](hash::sha256).
//!
//! The `qFALL` project contains two more crates called [`qFALL-math`](https://crates.io/crates/qfall-math)
//! and [`qFALL-tools`](https://crates.io/crates/qfall-tools) to support prototyping.
//! - Find further information on [our website](https://qfall.github.io/).
//! - We recommend [our tutorial](https://qfall.github.io/book) to start working with qFALL.
//!
//! ## Quick Example
//! ```
//! use qfall_schemes::pk_encryption::{KPKE, PKEncryptionScheme};
//! use qfall_math::integer::Z;
//!
//! // setup public parameters
//! let k_pke = KPKE::ml_kem_512();
//!
//! // generate (pk, sk) pair
//! let (pk, sk) = k_pke.key_gen();
//!
//! // encrypt a message
//! let msg = Z::from_utf8("Hello");
//! let cipher = k_pke.enc(&pk, &msg);
//!
//! // decrypt the ciphertext
//! let m = k_pke.dec(&sk, &cipher);
//!
//! assert_eq!(msg, m);
//! ```

pub mod hash;
pub mod identity_based_encryption;
pub mod pk_encryption;
pub mod signature;
