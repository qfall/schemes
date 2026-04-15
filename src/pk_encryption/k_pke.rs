// Copyright 2025 Jan Niklas Siemer
//
// This file is part of qFALL-schemes.
//
// qfall-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! Contains a naive implementation of the K-PKE scheme used as foundation for ML-KEM and Kyber.
//!
//! **WARNING:** This implementation is a toy implementation of the basics below
//! ML-KEM and mostly supposed to showcase the prototyping capabilities of the `qFALL`-library.

use crate::pk_encryption::PKEncryptionScheme;
use qfall_math::{
    integer::{MatPolyOverZ, PolyOverZ, Z},
    integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq, PolynomialRingZq},
};
use qfall_tools::{
    compression::LossyCompressionFIPS203,
    utils::{
        common_encodings::{decode_value_from_polynomialringzq, encode_value_in_polynomialringzq},
        common_moduli::new_anticyclic,
    },
};
use serde::{Deserialize, Serialize};

/// This is a naive toy-implementation of the [`PKEncryptionScheme`] used
/// as a basis for ML-KEM.
///
/// This implementation is not supposed to be an implementation of the FIPS 203 standard in [\[6\]](<index.html#:~:text=[6]>), but
/// is supposed to showcase the prototyping capabilities of `qFALL` and does not cover byte decomposition algorithms
/// as specified in the FIPS 203 document or NTT-multiplication.
///
/// Attributes:
/// - `q`: defines the modulus polynomial `(X^n + 1) mod p`
/// - `k`: defines the width and height of matrix `A`
/// - `eta_1`: defines that vectors `s`, `e`, and `y` are sampled according to Bin(eta_1, 1/2) centered around 0
/// - `eta_2`: defines that vector `e_1` and `e_2` are sampled according to Bin(eta_2, 1/2) centered around 0
///
/// # Examples
/// ```
/// use qfall_schemes::pk_encryption::{KPKE, PKEncryptionScheme};
///
/// // setup public parameters
/// let k_pke = KPKE::ml_kem_512();
///
/// // generate (pk, sk) pair
/// let (pk, sk) = k_pke.key_gen();
///
/// // encrypt a message
/// let msg = 250;
/// let cipher = k_pke.enc(&pk, &msg);
///
/// // decrypt the ciphertext
/// let m = k_pke.dec(&sk, &cipher);
///
/// assert_eq!(msg, m);
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct KPKE {
    q: ModulusPolynomialRingZq, // modulus (X^n + 1) mod p
    k: i64,                     // defines both dimensions of matrix A
    eta_1: i64, // defines the binomial distribution of the secret and error drawn in `key_gen`
    eta_2: i64, // defines the binomial distribution of the error drawn in `enc`
    d_u: i64,   // defines the number of kept upper-order bits per entry of vector `u`
    d_v: i64,   // defines the number of kept upper-order bits per entry of `v`
}

impl KPKE {
    /// Returns a [`KPKE`] instance with public parameters according to the ML-KEM-512 specification.
    pub fn ml_kem_512() -> Self {
        let q = new_anticyclic(256, 3329).unwrap();
        Self {
            q,
            k: 2,
            eta_1: 3,
            eta_2: 2,
            d_u: 10,
            d_v: 4,
        }
    }

    /// Returns a [`KPKE`] instance with public parameters according to the ML-KEM-768 specification.
    pub fn ml_kem_768() -> Self {
        let q = new_anticyclic(256, 3329).unwrap();
        Self {
            q,
            k: 3,
            eta_1: 2,
            eta_2: 2,
            d_u: 10,
            d_v: 4,
        }
    }

    /// Returns a [`KPKE`] instance with public parameters according to the ML-KEM-1024 specification.
    pub fn ml_kem_1024() -> Self {
        let q = new_anticyclic(256, 3329).unwrap();
        Self {
            q,
            k: 4,
            eta_1: 2,
            eta_2: 2,
            d_u: 11,
            d_v: 5,
        }
    }
}

impl PKEncryptionScheme for KPKE {
    type PublicKey = (MatPolynomialRingZq, MatPolynomialRingZq);
    type SecretKey = MatPolynomialRingZq;
    type Cipher = (MatPolyOverZ, PolyOverZ);

    /// Generates a `(pk, sk)` pair by following these steps:
    /// - A <- R_q^{k x k}
    /// - s <- Bin(eta_1, 0.5)^k centered around 0
    /// - e <- Bin(eta_1, 0.5)^k centered around 0
    /// - t = A * s + e
    ///
    /// Then, `pk = (A^T, t)` and `sk = s` are returned.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::pk_encryption::{PKEncryptionScheme, KPKE};
    /// let k_pke = KPKE::ml_kem_512();
    ///
    /// let (pk, sk) = k_pke.key_gen();
    /// ```
    fn key_gen(&self) -> (Self::PublicKey, Self::SecretKey) {
        // 5 𝐀[𝑖,𝑗] ← SampleNTT(𝜌‖𝑗‖𝑖)
        // Reminder: NTT-representation, sampling and multiplication are not part of this prototype
        let mat_a = MatPolynomialRingZq::sample_uniform(self.k, self.k, &self.q);
        // 9 𝐬[𝑖] ← SamplePolyCBD_𝜂_1(PRF_𝜂_1 (𝜎, 𝑁))
        let vec_s = MatPolynomialRingZq::sample_binomial_with_offset(
            self.k,
            1,
            &self.q,
            -self.eta_1,
            2 * self.eta_1,
            0.5,
        )
        .unwrap();
        // 13 𝐞[𝑖] ← SamplePolyCBD_𝜂_1(PRF_𝜂_1 (𝜎, 𝑁))
        let vec_e = MatPolynomialRingZq::sample_binomial_with_offset(
            self.k,
            1,
            &self.q,
            -self.eta_1,
            2 * self.eta_1,
            0.5,
        )
        .unwrap();

        // 18 𝐭 ← 𝐀 ∘ 𝐬 + 𝐞
        let vec_t = &mat_a * &vec_s + vec_e;

        let pk = (mat_a.transpose(), vec_t);
        let sk = vec_s;
        (pk, sk)
    }

    /// Encrypts a `message` with the provided public key by following these steps:
    /// - y <- Bin(eta_1, 0.5)^k centered around 0
    /// - e_1 <- Bin(eta_2, 0.5)^k centered around 0
    /// - e_2 <- Bin(eta_2, 0.5) centered around 0
    /// - u = A^T * y + e_1
    /// - v = t^T * y + e_2 + 𝜇, where 𝜇 is the {q/2, 0} encoding of the bits of `message`
    /// - Compress u and v
    ///
    /// Then, ciphertext `(u, v)` is returned.
    ///
    /// Parameters:
    /// - `pk`: specifies the public key `pk = (A, t)`
    /// - `message`: specifies the message that should be encrypted, which should not extend 256 bits (and be positive)
    ///
    /// Returns a ciphertext `(u, v)` of type [`MatPolynomialRingZq`] and [`PolynomialRingZq`].
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::pk_encryption::{PKEncryptionScheme, KPKE};
    /// let k_pke = KPKE::ml_kem_512();
    /// let (pk, sk) = k_pke.key_gen();
    ///
    /// let c = k_pke.enc(&pk, 1);
    /// ```
    fn enc(&self, pk: &Self::PublicKey, message: impl Into<Z>) -> Self::Cipher {
        // 10 𝐲[𝑖] ← SamplePolyCBD_𝜂_1(PRF_𝜂_1 (𝑟, 𝑁))
        let vec_y = MatPolynomialRingZq::sample_binomial_with_offset(
            self.k,
            1,
            &self.q,
            -self.eta_1,
            2 * self.eta_1,
            0.5,
        )
        .unwrap();
        // 𝐞_𝟏[𝑖] ← SamplePolyCBD_𝜂_2(PRF_𝜂_2 (𝑟, 𝑁))
        let vec_e_1 = MatPolynomialRingZq::sample_binomial_with_offset(
            self.k,
            1,
            &self.q,
            -self.eta_2,
            2 * self.eta_2,
            0.5,
        )
        .unwrap();
        // 𝑒_2 ← SamplePolyCBD_𝜂_2(PRF_𝜂_2 (𝑟, 𝑁))
        let e_2 = PolynomialRingZq::sample_binomial_with_offset(
            &self.q,
            -self.eta_2,
            2 * self.eta_2,
            0.5,
        )
        .unwrap();

        // 19 𝐮 ← NTT^−1(𝐀^⊺ ∘ 𝐲) + 𝐞_𝟏
        let vec_u = &pk.0 * &vec_y + vec_e_1;

        // 20 𝜇 ← Decompress_1(ByteDecode_1(𝑚))
        let mu = encode_value_in_polynomialringzq(message, 2, &self.q).unwrap();

        // 21 𝑣 ← NTT^−1(𝐭^⊺ ∘ 𝐲) + 𝑒_2 + 𝜇
        let v = pk.1.dot_product(&vec_y).unwrap() + e_2 + mu;

        // 22: 𝑐_1 ← ByteEncode_{𝑑_𝑢}(Compress_{𝑑_𝑢}(𝐮))
        let vec_u = vec_u.lossy_compress(self.d_u);
        // 23: 𝑐_2 ← ByteEncode_{𝑑_𝑣}(Compress_{𝑑_𝑣}(𝑣))
        let v = v.lossy_compress(self.d_v);

        (vec_u, v)
    }

    /// Decrypts the provided `cipher` using the secret key `sk` by following these steps:
    /// - Decompress u and v
    /// - w = v - s^T * u
    /// - returns the decoding of `w` with 1 and 0 set in the returned [`Z`] instance
    ///   if the corresponding coefficient was closer to q/2 or 0 respectively
    ///
    /// Parameters:
    /// - `sk`: specifies the secret key `sk = s`
    /// - `cipher`: specifies the ciphertext containing `cipher = (u, v)`
    ///
    /// Returns the decryption of `cipher` as a [`Z`] instance.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::pk_encryption::{PKEncryptionScheme, KPKE};
    /// let k_pke = KPKE::ml_kem_512();
    /// let (pk, sk) = k_pke.key_gen();
    /// let c = k_pke.enc(&pk, 1);
    ///
    /// let m = k_pke.dec(&sk, &c);
    ///
    /// assert_eq!(1, m);
    /// ```
    fn dec(&self, sk: &Self::SecretKey, (u, v): &Self::Cipher) -> Z {
        // 3: 𝐮′ ← Decompress_{𝑑_𝑢}(ByteDecode_{𝑑_𝑢}(𝑐_1))
        let u = MatPolynomialRingZq::lossy_decompress(u, self.d_u, &self.q);
        // 4: 𝑣′ ← Decompress_{𝑑_𝑣}(ByteDecode_{𝑑_𝑣}(𝑐_2))
        let v = PolynomialRingZq::lossy_decompress(v, self.d_v, &self.q);

        // 6 𝑤 ← 𝑣′ − NTT^−1(𝐬^⊺ ∘ NTT(𝐮′))
        let w = v - sk.dot_product(&u).unwrap();

        // 7 𝑚 ← ByteEncode_1(Compress_1(𝑤))
        decode_value_from_polynomialringzq(&w, 2).unwrap()
    }
}

#[cfg(test)]
mod test_kpke {
    use crate::pk_encryption::{PKEncryptionScheme, k_pke::KPKE};

    /// Ensures that [`KPKE`] works for all ML-KEM specifications by
    /// performing a round trip of several messages.
    #[test]
    fn correctness() {
        let k_pkes = [KPKE::ml_kem_512(), KPKE::ml_kem_768(), KPKE::ml_kem_1024()];
        for k_pke in k_pkes {
            let messages = [0, 1, 13, 255, 2047, 4294967295_u32];

            for message in messages {
                let (pk, sk) = k_pke.key_gen();
                let c = k_pke.enc(&pk, message);
                let m = k_pke.dec(&sk, &c);

                assert_eq!(message, m);
            }
        }
    }
}
