// Copyright © 2023 Niklas Siemer, Marvin Beckmann
//
// This file is part of qFALL-schemes.
//
// qFALL-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! # What is qFALL-schemes?
//! qFall-schemes provides cryptographic basics such as mathematical primitives,
//! fundamental lattice-based cryptographic constructions, and samplable distributions/
//! possibilities to sample instances of lattice problems to prototype
//! lattice-based cryptographic constructions and more.
//!
//! Currently qFALL-schemes supports 3 main construction types:
//! - [Identity-Based Encryptions](identity_based_encryption::IBEScheme)
//! - [Public-Key Encryptions](pk_encryption::PKEncryptionScheme)
//! - [Signatures](signature::SignatureScheme)
//!
//! These are identified by traits and then implemented for specific constructions, e.g.
//! [`RingLPR`](pk_encryption::RingLPR).
//!
//! qfall-schemes is free software: you can redistribute it and/or modify it under
//! the terms of the Mozilla Public License Version 2.0 as published by the
//! Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.
//!
//! ## Tutorial + Website
//! You can find a dedicated [tutorial](https://qfall.github.io/book/index.html) to qFALL-schemes on our [website](https://qfall.github.io/).
//! The tutorial explains the basic steps starting from installation and
//! continues with basic usage.
//! qfall-schemes is co-developed together with qFALL-math and qfall-crypto which provides the basic
//! foundation that is used to implement the cryptographic constructions.
//!
//! This module contains fundamental cryptographic constructions, on which other
//! constructions can be build on.
//!
//! Among others, these include encryption schemes and signature schemes.
//! A construction is always build the same way:
//!
//! 1. A trait that combines the common feature, e.g.
//!    [`public key encryption`](pk_encryption::PKEncryptionScheme).
//! 2. Explicit implementations of the trait, e.g.
//!    [`RingLPR`](pk_encryption::RingLPR).

pub mod hash;
pub mod identity_based_encryption;
pub mod pk_encryption;
pub mod signature;
