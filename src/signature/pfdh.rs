// Copyright © 2023 Phil Milewski
//
// This file is part of qFALL-schemes.
//
// qfall-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! Contains a generic implementation of the probabilistic full domain
//! hash signature scheme.
//!
//! The constructions follow the general definition of a hash-then-sign signature scheme
//! that uses a hash function as in [\[1\]](<../index.html#:~:text=[1]>) and a PSF.
//!
//! These signature schemes also include randomness into the hashed strings rather than
//! using a storage, so it is stateless.
//!
//! Requirements
//! - `psf`: The PSF which has to implement the [`PSF`](qfall_tools::primitive::psf::PSF) trait
//!   and must also be (de-)serializable.
//! - `hash`: The hash-function which has to map a string into the correct domain.
//! - `randomness_length`: The length of the salt that is added to the string before
//!   hashing.
//!
//! # Example
//! ## Signature Scheme from [`PSFGPV`](qfall_tools::primitive::psf::PSFGPV)
//! ```
//! use qfall_schemes::signature::{pfdh::PFDHGPV, SignatureScheme};
//!
//! let mut pfdh = PFDHGPV::setup(4, 113, 17, 128);
//!
//! let m = "Hello World!";
//!
//! let (pk, sk) = pfdh.key_gen();
//! let sigma = pfdh.sign(m.to_owned(), &sk, &pk);
//!
//! assert!(pfdh.vfy(m.to_owned(), &sigma, &pk));
//! ```

mod gpv;

pub use gpv::PFDHGPV;
