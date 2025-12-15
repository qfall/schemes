// Copyright © 2023 Niklas Siemer
//
// This file is part of qFALL-schemes.
//
// qfall-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! Contains traits and implementations related to hash functions.
//!
//! References:
//! - \[1\] Peikert, Chris (2016).
//!   A decade of lattice cryptography.
//!   In: Theoretical Computer Science 10.4.
//!   <https://web.eecs.umich.edu/~cpeikert/pubs/lattice-survey.pdf>

pub mod sha256;
mod sis;

pub use sis::SISHash;

/// This trait should be implemented by hashes with domain [`str`].
pub trait HashInto<DigestSpace> {
    /// Hashes a given String literal.
    ///
    /// Paramters:
    /// - `m`: specifies the string message to be hashed
    ///
    /// Returns a hash of type Domain.
    fn hash(&self, m: &str) -> DigestSpace;
}
