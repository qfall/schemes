// Copyright 2026 Jan Niklas Siemer
//
// This file is part of qFALL-schemes.
//
// qfall-schemes is free software: you can redistribute it and/or modify it under
// the terms of the Mozilla Public License Version 2.0 as published by the
// Mozilla Foundation. See <https://mozilla.org/en-US/MPL/2.0/>.

//! Contains a naive implementation of ML-DSA (Dilithium).
//!
//! **WARNING:** This implementation is a toy implementation of the basics below
//! ML-DSA and is mostly supposed to showcase the prototyping capabilities of the `qFALL` library.
//! It omits certain strict encoding/decoding constraints, specific byte-level hash prunings,
//! and NTT-representations defined in FIPS 204.

use crate::signature::SignatureScheme;
use qfall_math::{
    integer::{MatPolyOverZ, PolyOverZ, Z},
    integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq},
    traits::{GetCoefficient, MatrixDimensions, MatrixGetEntry, MatrixSetEntry, SetCoefficient},
};
use qfall_tools::utils::common_moduli::new_anticyclic;
use rand::{RngExt, SeedableRng, rngs::SmallRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// This is a naive toy-implementation of the [`SignatureScheme`] used
/// as a basis for ML-DSA (Dilithium).
///
/// This implementation is not supposed to be an implementation of the FIPS 204 standard in [\[2\]](<index.html#:~:text=[2]>), but
/// is supposed to showcase the prototyping capabilities of `qFALL` and omits certain encoding/decoding
/// steps, byte-level optimizations, and specific NTT-representations as specified in the FIPS 204 document.
/// Furthermore, note that this implementation uses [`Sha256`] rather than SHAKE as specified in FIPS 204.
///
/// Attributes:
/// - `modulus`: defines the modulus polynomial `(X^phi + 1) mod q`
/// - `k`: defines the height of matrix `A` (number of rows)
/// - `ell`: defines the width of matrix `A` (number of columns)
/// - `tau`: defines the number of non-zero coefficients (+1 or -1) in the challenge polynomial `c`
/// - `eta`: defines the uniform distribution range `[-eta, eta]` for the secret key vectors `s_1` and `s_2`
/// - `power2_of_d`: defines the power of 2 representing the number of dropped bits from `t`
/// - `gamma_1`: defines the coefficient range `[-gamma_1 + 1, gamma_1]` of the masking vector `y`
/// - `gamma_2`: defines the low-order rounding range used for hints
/// - `omega`: defines the maximum allowed Hamming weight (number of 1s) in the hint matrix `h`
/// - `phi`: defines the degree of the modulus polynomial `(X^phi + 1) mod q`
///
/// # Examples
/// ```
/// use qfall_schemes::signature::{SignatureScheme, MLDSA};
///
/// // setup public parameters
/// let mut ml_dsa = MLDSA::ml_dsa_44();
///
/// // generate (pk, sk) pair
/// let (pk, sk) = ml_dsa.key_gen();
///
/// // sign a message
/// let msg = String::from("Hello world!");
/// let signature = ml_dsa.sign(msg.clone(), &sk, &pk);
///
/// // verify the signature
/// let is_valid = ml_dsa.vfy(msg, &signature, &pk);
///
/// assert!(is_valid);
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct MLDSA {
    pub modulus: ModulusPolynomialRingZq, // modulus (X^n + 1) mod q
    pub k: i64,                           // dimension of matrix A
    pub ell: i64,                         // dimension of matrix A
    pub tau: i64,                         // defines the binomial distribution
    pub eta: i64,                         // private key range
    pub power2_of_d: Z,                   // power of 2 of number of dropped bits from t
    pub gamma_1: i64,                     // coefficient range of y
    pub gamma_2: i64,                     // low-order rounding range
    pub omega: u64,                       // max # of 1’s in the hint h
    pub phi: i64, // max degree or rather, defines the modulus (X^phi + 1) mod q
}

impl MLDSA {
    /// Returns a [`MLDSA`] instance with public parameters according to the ML-DSA-44 specification.
    pub fn ml_dsa_44() -> Self {
        let modulus = new_anticyclic(256, 8380417).unwrap();
        Self {
            modulus: modulus.clone(),
            k: 4,
            ell: 4,
            tau: 39,
            eta: 2,
            power2_of_d: Z::from(2_i64.pow(13)),
            gamma_1: 2_i64.pow(17),
            gamma_2: 95232,
            omega: 80,
            phi: 256,
        }
    }

    /// Returns a [`MLDSA`] instance with public parameters according to the ML-DSA-65 specification.
    pub fn ml_dsa_65() -> Self {
        let modulus = new_anticyclic(256, 8380417).unwrap();
        Self {
            modulus: modulus.clone(),
            k: 6,
            ell: 5,
            tau: 49,
            eta: 4,
            power2_of_d: Z::from(2_i64.pow(13)),
            gamma_1: 2_i64.pow(19),
            gamma_2: 261888,
            omega: 55,
            phi: 256,
        }
    }

    /// Returns a [`MLDSA`] instance with public parameters according to the ML-DSA-87 specification.
    pub fn ml_dsa_87() -> Self {
        let modulus = new_anticyclic(256, 8380417).unwrap();
        Self {
            modulus: modulus.clone(),
            k: 8,
            ell: 7,
            tau: 60,
            eta: 2,
            power2_of_d: Z::from(2_i64.pow(13)),
            gamma_1: 2_i64.pow(19),
            gamma_2: 261888,
            omega: 75,
            phi: 256,
        }
    }

    /// Extracts the higher-order and lower-order bits of the elements of a vector.
    ///
    /// This is used during key generation to split the public key vector `t` into
    /// a high-order part `t_1` (which is published) and a low-order part `t_0` (kept secret).
    /// Note: This implementation stores the literal difference `t - t_0` rather than
    /// explicitly dividing by `2^d`.
    ///
    /// Parameters:
    /// - `vector`: The vector of polynomials to be split.
    ///
    /// Returns a tuple `(vec1, vec0)`, each of type [`MatPolyOverZ`], representing the high bits and low bits respectively.
    pub fn power2round(&self, vector: MatPolynomialRingZq) -> (MatPolyOverZ, MatPolyOverZ) {
        let mut vec0 = MatPolyOverZ::new(vector.get_num_rows(), vector.get_num_columns());
        let mut vec1 = MatPolyOverZ::new(vector.get_num_rows(), vector.get_num_columns());

        for row in 0..vector.get_num_rows() {
            for col in 0..vector.get_num_columns() {
                let entry: PolyOverZ = unsafe { vector.get_entry_unchecked(row, col) };
                let mut entry0 = PolyOverZ::default();
                let mut entry1 = PolyOverZ::default();

                for i in 0..self.phi {
                    let coeff = unsafe { entry.get_coeff_unchecked(i) };

                    // 2: r_0 <- r^+ mod 2^d
                    let coeff0 = mod_pm(&coeff, &self.power2_of_d);
                    // 3: implicit: r_1 = (r^+ − r_0)/2^d
                    let coeff1 = coeff - &coeff0; // We omit dividing by 2^d

                    unsafe { entry0.set_coeff_unchecked(i, coeff0) };
                    unsafe { entry1.set_coeff_unchecked(i, coeff1) };
                }

                unsafe { vec0.set_entry_unchecked(row, col, entry0) };
                unsafe { vec1.set_entry_unchecked(row, col, entry1) };
            }
        }

        (vec1, vec0)
    }

    /// Decomposes a vector into higher-order and lower-order bits modulo `q`.
    ///
    /// This function separates a polynomial into its high bits `r_1` and low bits `r_0`
    /// based on the `gamma_2` parameter. It specifically handles the `q - 1` edge case
    /// to ensure values wrap correctly around the finite field boundary.
    /// Note: Coefficients in `vec0` are defined w.r.t. the modulus centered around `0` rather than the usual field `[0, q-1]`.
    ///
    /// Parameters:
    /// - `vector`: The vector of polynomials to decompose.
    ///
    /// Returns a tuple `(vec1, vec0)`, each of type [`MatPolyOverZ`], representing the high bits and low bits respectively.
    pub fn decompose(&self, vector: &MatPolynomialRingZq) -> (MatPolyOverZ, MatPolyOverZ) {
        let mut vec0 = MatPolyOverZ::new(vector.get_num_rows(), vector.get_num_columns());
        let mut vec1 = MatPolyOverZ::new(vector.get_num_rows(), vector.get_num_columns());

        for row in 0..vector.get_num_rows() {
            for col in 0..vector.get_num_columns() {
                let entry: PolyOverZ = unsafe { vector.get_entry_unchecked(row, col) };
                let mut entry0 = PolyOverZ::default();
                let mut entry1 = PolyOverZ::default();

                for i in 0..self.phi {
                    let coeff = unsafe { entry.get_coeff_unchecked(i) };
                    // 2: r_0 <- r^+ mod (2 * 𝛾_2)
                    let mut coeff0 = mod_pm(&coeff, 2 * self.gamma_2);
                    let coeff1;
                    // 3: if r^+ - r_0 = q - 1 then
                    if &coeff - &coeff0 == self.modulus.get_q() - 1 {
                        // 4: r_1 <- 0
                        coeff1 = Z::ZERO;
                        // 5: r_0 <- r_0 - 1
                        coeff0 -= 1;
                    }
                    // 6: else r_1 <- (r^+ - r_0) / (2 * 𝛾_2)
                    else {
                        coeff1 = (coeff - &coeff0).div_floor(2 * self.gamma_2);
                    }

                    // insert values into polynomials
                    unsafe { entry0.set_coeff_unchecked(i, coeff0) };
                    unsafe { entry1.set_coeff_unchecked(i, coeff1) };
                }
                // insert entry into vector
                unsafe { vec0.set_entry_unchecked(row, col, entry0) };
                unsafe { vec1.set_entry_unchecked(row, col, entry1) };
            }
        }

        (vec1, vec0)
    }

    /// Samples a polynomial with a specific Hamming weight from a seed.
    ///
    /// This generates the challenge polynomial `c` used during signing and verification.
    /// It ensures that exactly `tau` coefficients are set to either `1` or `-1`,
    /// and all other coefficients are `0`.
    ///
    /// Parameters:
    /// - `seed`: A 32-byte seed used to deterministically generate the polynomial.
    ///
    /// Returns a [`PolyOverZ`] representing the challenge polynomial.
    pub fn modified_sample_in_ball(&self, seed: [u8; 32]) -> PolyOverZ {
        let mut rng = SmallRng::from_seed(seed);
        let mut poly = PolyOverZ::default();

        for _ in 0..self.tau {
            // choose position of {-1,1} value
            let mut position = rng.random_range(0..self.phi);
            // sample positions until a previously never set position is found to ensure hw(poly) = tau in the end
            while unsafe { poly.get_coeff_unchecked(position) } != 0 {
                position = rng.random_range(0..self.phi);
            }
            let bit = rng.random_bool(0.5);
            if bit {
                unsafe { poly.set_coeff_unchecked(position, 1) };
            } else {
                unsafe { poly.set_coeff_unchecked(position, -1) };
            }
        }

        poly
    }

    /// Computes a boolean hint matrix used to compress the signature.
    ///
    /// The hint indicates whether adding the signature noise `z` to the signer's
    /// secret state `r` causes the high bits of the resulting polynomial to change
    /// compared to the high bits of `r` alone.
    ///
    /// Parameters:
    /// - `z_vector`: The noise vector `z` (or related shift).
    /// - `r_vector`: The original state vector.
    ///
    /// Returns a [`MatPolyOverZ`] containing `1` where the high bits differ, and `0` otherwise.
    pub fn make_hint(
        &self,
        z_vector: &MatPolynomialRingZq,
        r_vector: &MatPolynomialRingZq,
    ) -> MatPolyOverZ {
        assert_eq!(z_vector.get_num_rows(), r_vector.get_num_rows());
        assert_eq!(z_vector.get_num_columns(), r_vector.get_num_columns());
        assert_eq!(z_vector.get_mod(), r_vector.get_mod());

        // 1: r_1 <- HighBits(r)
        let (vec_r_1, _) = self.decompose(r_vector);
        // 2: v_1 <- HighBits(r + z)
        let (vec_v_1, _) = self.decompose(&(r_vector + z_vector));

        let mut hint = MatPolyOverZ::new(vec_r_1.get_num_rows(), vec_r_1.get_num_columns());

        for row in 0..vec_r_1.get_num_rows() {
            for col in 0..vec_r_1.get_num_columns() {
                let v_1_entry: PolyOverZ = unsafe { vec_v_1.get_entry_unchecked(row, col) };
                let r_1_entry: PolyOverZ = unsafe { vec_r_1.get_entry_unchecked(row, col) };
                let mut hint_poly = PolyOverZ::default();

                for i in 0..self.phi {
                    let v_1_coeff = unsafe { v_1_entry.get_coeff_unchecked(i) };
                    let r_1_coeff = unsafe { r_1_entry.get_coeff_unchecked(i) };

                    // 3: return [[ r_1 != v_1 ]]
                    if r_1_coeff != v_1_coeff {
                        unsafe {
                            hint_poly.set_coeff_unchecked(i, 1);
                        };
                    }
                }
                // insert entry into vector
                unsafe { hint.set_entry_unchecked(row, col, hint_poly) };
            }
        }

        hint
    }

    /// Reconstructs the high bits of a polynomial using a previously generated hint.
    ///
    ///
    /// During verification, the verifier only has an approximation of the signer's state.
    /// This function uses the hint matrix to correctly recover the exact high bits
    /// that the signer originally committed to.
    ///
    /// Parameters:
    /// - `h_vector`: The boolean hint matrix included in the signature.
    /// - `r_vector`: The verifier's approximated state matrix.
    ///
    /// Returns the reconstructed high bits as a [`MatPolyOverZ`].
    pub fn use_hint(
        &self,
        h_vector: &MatPolyOverZ,
        r_vector: &MatPolynomialRingZq,
    ) -> MatPolyOverZ {
        assert_eq!(h_vector.get_num_rows(), r_vector.get_num_rows());
        assert_eq!(h_vector.get_num_columns(), r_vector.get_num_columns());

        // 1: m <- (q - 1)/(2 * 𝛾_2)
        let m: Z = (self.modulus.get_q() - Z::ONE).div_floor(2 * self.gamma_2);

        // 2: (r_1, r_0) <- Decompose(r)
        let (vec_r_1, vec_r_0) = self.decompose(r_vector);
        let mut out = MatPolyOverZ::new(r_vector.get_num_rows(), r_vector.get_num_columns());

        for row in 0..r_vector.get_num_rows() {
            for col in 0..r_vector.get_num_columns() {
                let entry_r_0 = unsafe { vec_r_0.get_entry_unchecked(row, col) };
                let mut entry_r_1 = unsafe { vec_r_1.get_entry_unchecked(row, col) };
                let entry_h = unsafe { h_vector.get_entry_unchecked(row, col) };

                for i in 0..self.phi {
                    let r_0_coeff = unsafe { entry_r_0.get_coeff_unchecked(i) };
                    let r_1_coeff = unsafe { entry_r_1.get_coeff_unchecked(i) };
                    let h_coeff = unsafe { entry_h.get_coeff_unchecked(i) };

                    // 3: if h = 1 and r_0 > 0 return (r_1 + 1) mod m
                    if h_coeff == 1 && r_0_coeff > 0 {
                        unsafe { entry_r_1.set_coeff_unchecked(i, (r_1_coeff + 1) % &m) };
                    } else if h_coeff == 1 && r_0_coeff <= 0 {
                        unsafe { entry_r_1.set_coeff_unchecked(i, (r_1_coeff - 1) % &m) };
                    }
                }

                // insert r_1 into the vector
                unsafe { out.set_entry_unchecked(row, col, entry_r_1) };
            }
        }

        out
    }
}

/// Calculates the Hamming weight of a [`MatPolyOverZ`].
///
/// The Hamming weight is defined as the total number of non-zero coefficients
/// across all polynomials in the matrix.
///
/// Parameters:
/// - `matrix`: The hint matrix to evaluate.
///
/// Returns the total count of non-zero coefficients as a [`u64`].
fn hamming_weight(matrix: &MatPolyOverZ) -> u64 {
    let mut count = 0;

    let entries = matrix.get_entries_rowwise();
    for entry in entries {
        for i in 0..=entry.get_degree() {
            if 0 != unsafe { entry.get_coeff_unchecked(i) } {
                count += 1;
            }
        }
    }

    count
}

/// Computes the modulo of a value centered around `0`.
///
/// While standard modulo maps values to the positive range `[0, q-1]`,
/// this function computes the centered modulo, mapping the value to the
/// centered range `(-ceil(q/2), floor(q/2)]`.
///
/// Parameters:
/// - `value`: The integer value to reduce.
/// - `q`: The modulus boundary.
///
/// Returns the centered modulo result as a [`Z`] instance.
fn mod_pm(value: &Z, q: impl Into<Z>) -> Z {
    let q: Z = q.into();

    let r = value % &q;
    let half_q = q.div_floor(2);

    // shift into the centered range
    if r > half_q { r - q } else { r }
}

impl SignatureScheme for MLDSA {
    type SecretKey = (
        MatPolynomialRingZq,
        [u8; 32],
        MatPolyOverZ,
        MatPolyOverZ,
        MatPolyOverZ,
    );
    type PublicKey = (MatPolynomialRingZq, MatPolyOverZ);
    type Signature = ([u8; 32], MatPolyOverZ, MatPolyOverZ);

    /// Generates a `(pk, sk)` pair by following these steps:
    /// - A <- R_q^{k x ell}
    /// - s_1 <- U([-eta, eta])^ell
    /// - s_2 <- U([-eta, eta])^k
    /// - t = A * s_1 + s_2
    /// - (t_1, t_0) = [`MLDSA::power2round`] (t)
    /// - tr = H(A || t_1)
    ///
    /// Then, `pk = (A, t_1)` and `sk = (A, tr, s_1, s_2, t_0)` are returned.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::{SignatureScheme, MLDSA};
    /// let mut ml_dsa = MLDSA::ml_dsa_44();
    ///
    /// let (pk, sk) = ml_dsa.key_gen();
    /// ```
    fn key_gen(&mut self) -> (Self::PublicKey, Self::SecretKey) {
        // 3: A <- R_q^{k x ell}
        let mat_a = MatPolynomialRingZq::sample_uniform(self.k, self.ell, &self.modulus);

        // 4: s_1 <- R_q^ell
        let vec_s_1 = MatPolyOverZ::sample_uniform(
            self.ell,
            1,
            self.modulus.get_degree() - 1,
            -self.eta,
            self.eta + 1,
        )
        .unwrap();
        // 4: s_2 <- R_q^k
        let vec_s_2 = MatPolyOverZ::sample_uniform(
            self.k,
            1,
            self.modulus.get_degree() - 1,
            -self.eta,
            self.eta + 1,
        )
        .unwrap();

        // 5: t = A * s_1 + s_2
        let vec_t = &mat_a * &vec_s_1 + &vec_s_2;

        // 6: (t_1, t_0) <- Power2Round(t)
        let (vec_t_1, vec_t_0) = self.power2round(vec_t);

        // 9: tr <- H(pk, 64)
        let hash = Sha256::digest(format!("{mat_a} {vec_t_1}")); // ignore pruning to 64 bits
        let hash = hash.iter().copied().collect::<Vec<u8>>();
        let tr: [u8; 32] = hash.try_into().unwrap();

        // 8: pk <- pkEncode(A, t_1)
        let pk = (mat_a.clone(), vec_t_1);
        // 10: sk <- skEncode(A, K, tr, s_1, s_2, t_0)
        let sk = (mat_a, tr, vec_s_1, vec_s_2, vec_t_0); // we omit K, which just carries some randomness from KeyGen to Sign

        (pk, sk)
    }

    /// Signs a message `m` with the provided secret key `sk` by following these steps:
    /// - mu = H(tr || m)
    /// - Loop:
    ///   - y <- U([-gamma_1 + 1, gamma_1])^ell
    ///   - w = A * y
    ///   - w_1 = HighBits(w)   // HighBits returns only the first part of [`MLDSA::decompose`]
    ///   - c_tilde = H(mu || w_1)
    ///   - c = [`MLDSA::modified_sample_in_ball`] (c_tilde)
    ///   - z = y + c * s_1
    ///   - r_0 = LowBits(w - c * s_2)  // // LowBits returns only the second part of [`MLDSA::decompose`]
    ///   - If ||z||_infty >= gamma_1 - tau * eta or ||r_0||_infty >= gamma_2 - tau * eta, then restart loop
    ///   - h = [`MLDSA::make_hint`] (-c * t_0, w - c * s_2 + c * t_0)
    ///   - If ||c * t_0||_infty >= gamma_2 or HammingWeight(h) > omega, then restart loop
    ///     - Return (c_tilde, z, h)
    ///
    /// Parameters:
    /// - `m`: specifies the message string that should be signed
    /// - `sk`: specifies the secret key `sk = (A, tr, s_1, s_2, t_0)`
    /// - `_pk`: specifies the public key (unused in this signing implementation)
    ///
    /// Returns a signature `(c_tilde, z, h)`.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::{SignatureScheme, MLDSA};
    /// let mut ml_dsa = MLDSA::ml_dsa_44();
    /// let (pk, sk) = ml_dsa.key_gen();
    ///
    /// let sig = ml_dsa.sign(String::from("test message"), &sk, &pk);
    /// ```
    fn sign(&mut self, m: String, sk: &Self::SecretKey, _pk: &Self::PublicKey) -> Self::Signature {
        // 6: 𝜇 ← H(BytesToBits(tr)||M', 64)
        let mu = Sha256::digest(format!(
            "{} {m}",
            sk.1.iter().map(|b| b.to_string()).collect::<String>()
        )); // ingore pruning to 64 bits
        let mu = mu.iter().map(|b| b.to_string()).collect::<String>();

        loop {
            // 11: y \in R_q^ell <- ExpandMask(r'', kappa)
            let vec_y = MatPolyOverZ::sample_uniform(
                self.ell,
                1,
                self.phi,
                -self.gamma_1 + 1,
                self.gamma_1,
            )
            .unwrap();
            // 12: w <- A * y
            let vec_w = &sk.0 * &vec_y;

            // 13: w_1 <- HighBits(w)
            let (vec_w_1, _) = self.decompose(&vec_w);

            // 15: c~ <- H(𝜇 || w1Encode(w_1), 𝜆/4)
            let hash = Sha256::digest(format!("{mu} {vec_w_1}")); // ignore pruning to 𝜆/4 bits
            let hash = hash.iter().copied().collect::<Vec<u8>>();
            let c_tilde: [u8; 32] = hash.try_into().unwrap();

            // 16: c \in R_q <- SampleInBall(c~)
            let c = self.modified_sample_in_ball(c_tilde);
            // 20: z <- y + 𝑐 * s_1
            let vec_z = vec_y + &c * &sk.2;
            // 21: r_0 <- LowBits(w - 𝑐 * s_2)
            let (_, vec_r_0) = self.decompose(&(&vec_w - &c * &sk.3));

            // 23: if ||z||∞ >= 𝛾_1 - 𝛽 or ||r0||∞ >= 𝛾_2 − 𝛽 then (z, h) <- ⊥ else
            if vec_z.norm_infty().unwrap() < self.gamma_1 - self.tau * self.eta
                && vec_r_0.norm_infty().unwrap() < self.gamma_2 - self.tau * self.eta
            {
                // 26: h <- MakeHint(- c * t_0, w − c * s_2 + c * t_0)
                let vec_h = self.make_hint(
                    &(MatPolynomialRingZq::from((-1 * &c * &sk.4, &self.modulus))),
                    &(vec_w - &c * &sk.3 + &c * &sk.4),
                );

                // 28: if ||c * t_0||∞ >= 𝛾_2 or the number of 1’s in h is greater than 𝜔, then (z, h) ← ⊥
                if (c * &sk.4).norm_infty().unwrap() < self.gamma_2
                    && hamming_weight(&vec_h) <= self.omega
                {
                    // 33: 𝜎 <- sigEncode(c, z mod q, h)
                    // 34: return 𝜎
                    return (c_tilde, vec_z, vec_h);
                }
            }
        }
    }

    /// Verifies the provided `sigma` using the public key `pk` by following these steps:
    /// - tr = H(A || t_1)
    /// - mu = H(tr || m)
    /// - c = [`MLDSA::modified_sample_in_ball`] (c_tilde)
    /// - w_approx = A * z - c * t_1 * 2^d
    /// - w_1' = [`MLDSA::use_hint`] (h, w_approx)
    /// - c_tilde' = H(mu || w_1')
    /// - Returns true if ||z||_infty < gamma_1 - tau * eta and c_tilde == c_tilde'
    ///
    /// Parameters:
    /// - `m`: specifies the original message string that was signed
    /// - `sigma`: specifies the signature `sigma = (c_tilde, z, h)`
    /// - `pk`: specifies the public key `pk = (A, t_1)`
    ///
    /// Returns `true` if the signature is valid, and `false` otherwise.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::{SignatureScheme, MLDSA};
    /// let mut ml_dsa = MLDSA::ml_dsa_44();
    /// let (pk, sk) = ml_dsa.key_gen();
    /// let msg = String::from("test message");
    /// let sig = ml_dsa.sign(msg.clone(), &sk, &pk);
    ///
    /// let is_valid = ml_dsa.vfy(msg, &sig, &pk);
    /// assert!(is_valid);
    /// ```
    fn vfy(&self, m: String, sigma: &Self::Signature, pk: &Self::PublicKey) -> bool {
        // 6: tr <- H(pk, 64)
        let hash = Sha256::digest(format!("{} {}", pk.0, pk.1)); // ignore pruning to 64 bits
        let hash = hash.iter().copied().collect::<Vec<u8>>();
        let tr: [u8; 32] = hash.try_into().unwrap();

        // 7: 𝜇 ← H(BytesToBits(tr)||M', 64)
        let mu = Sha256::digest(format!(
            "{} {m}",
            tr.iter().map(|b| b.to_string()).collect::<String>()
        )); // ingore pruning to 64 bits
        let mu = mu.iter().map(|b| b.to_string()).collect::<String>();

        // 8: c \in R_q <- SampleInBall(c~)
        let c = self.modified_sample_in_ball(sigma.0);

        // 9: w_Approx <- A * z - c * t_1 * 2^d
        let vec_w_approx = &pk.0 * &sigma.1 - c * &pk.1; // ignore multiplying by 2^d

        // 10: w_1' <- UseHint(h, w_Approx)
        let vec_w_1 = self.use_hint(&sigma.2, &vec_w_approx);

        // c~ <- H(𝜇 || w1Encode(w_1), 𝜆/4)
        let hash = Sha256::digest(format!("{mu} {vec_w_1}")); // ignore pruning to 𝜆/4 bits
        let hash = hash.iter().copied().collect::<Vec<u8>>();
        let c_tilde: [u8; 32] = hash.try_into().unwrap();

        // 13: return [[ ||z||∞ < 𝛾_1 − 𝛽]] and [[c = c']]
        if sigma.1.norm_infty().unwrap() < self.gamma_1 - self.tau * self.eta && sigma.0 == c_tilde
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod test_mldsa {
    use crate::signature::{MLDSA, SignatureScheme};
    use qfall_math::{
        integer::PolyOverZ,
        traits::{MatrixGetEntry, MatrixSetEntry},
    };

    /// Ensures that [`MLDSA`] is correct for all ML-DSA specifications by
    /// checking if generated signatures are valid.
    #[test]
    fn correctness() {
        let ml_dsas = [MLDSA::ml_dsa_44(), MLDSA::ml_dsa_65(), MLDSA::ml_dsa_87()];
        for mut ml_dsa in ml_dsas {
            let messages = [
                String::from(""),
                String::from("abc"),
                String::from("123"),
                String::from("Hello world!"),
                String::from("some longer string which doesn't need to make any sense"),
            ];

            for message in messages {
                let (pk, sk) = ml_dsa.key_gen();
                let signature = ml_dsa.sign(message.clone(), &sk, &pk);

                assert!(ml_dsa.vfy(message, &signature, &pk));
            }
        }
    }

    /// Ensures that [`MLDSA`] is correct for all ML-DSA specifications by
    /// checking if tampered signatures are invalid.
    #[test]
    fn tampered_invalid() {
        let poly = PolyOverZ::from(1);
        let ml_dsas = [MLDSA::ml_dsa_44(), MLDSA::ml_dsa_65(), MLDSA::ml_dsa_87()];
        for mut ml_dsa in ml_dsas {
            let message = String::from("abc");

            let (pk, sk) = ml_dsa.key_gen();
            let mut signature = ml_dsa.sign(message.clone(), &sk, &pk);

            // invalidate signature
            unsafe {
                signature
                    .1
                    .set_entry_unchecked(0, 0, signature.1.get_entry_unchecked(0, 0) + &poly)
            };

            assert!(!ml_dsa.vfy(message, &signature, &pk));
        }
    }

    /// Ensures that [`MLDSA`] is correct for all ML-DSA specifications by
    /// checking if signatures exceeding the norm bound of `z` are invalid.
    #[test]
    fn length_invalid() {
        let ml_dsas = [MLDSA::ml_dsa_44(), MLDSA::ml_dsa_65(), MLDSA::ml_dsa_87()];
        for mut ml_dsa in ml_dsas {
            let message = String::from("abc");
            let poly = PolyOverZ::from(ml_dsa.gamma_1 - ml_dsa.tau * ml_dsa.eta);

            let (pk, sk) = ml_dsa.key_gen();
            let mut signature = ml_dsa.sign(message.clone(), &sk, &pk);

            // set `z` too long to be valid
            unsafe { signature.1.set_entry_unchecked(0, 0, &poly) };

            assert!(!ml_dsa.vfy(message, &signature, &pk));
        }
    }
}
