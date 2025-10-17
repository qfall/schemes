// Copyright © 2023 Niklas Siemer, Marvin Beckmann
//
// This file is part of qFALL-schemes.
//
// qFALL-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! # What is qFALL-schemes?
//! qFall-schemes provides lattice-based cryptographic constructions to enable prototyping
//! based on the existing constructions.
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
//! qfall-schemes is co-developed together with qFALL-math and qFALL-tools which provide the
//! foundation that is used to implement the cryptographic constructions.

pub mod hash;
pub mod identity_based_encryption;
pub mod pk_encryption;
pub mod signature;
