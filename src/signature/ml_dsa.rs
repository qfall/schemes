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
    integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq, Zq},
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
    pub omega: i64,                       // max # of 1’s in the hint h
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

    /// Splits a single coefficient `r` into its high-order and low-order part
    /// according to Power2Round in FIPS 204 (Algorithm 35) s.t. `r = (r - r_0) + r_0`.
    ///
    /// Note: This implementation returns the literal difference `r - r_0`, i.e. `r_1 * 2^d`,
    /// rather than explicitly dividing by `2^d`.
    ///
    /// Parameters:
    /// - `r`: specifies the coefficient to split
    ///
    /// Returns a tuple `(r - r_0, r_0)` of type [`Z`], where `r_0 = r mod± 2^d` is the
    /// least absolute residue of `r` modulo `2^d` and `r - r_0` is a multiple of `2^d`.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::integer::Z;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44(); // 2^d = 8192
    ///
    /// let (r_1, r_0) = ml_dsa.power2round_coeff(Z::from(12345));
    ///
    /// assert_eq!(Z::from(16384), r_1);
    /// assert_eq!(Z::from(-4039), r_0);
    /// ```
    ///
    /// # Panics ...
    /// - if `self.power2_of_d <= 1`.
    pub fn power2round_coeff(&self, r: Z) -> (Z, Z) {
        // 2: r_0 <- r^+ mod 2^d
        let r_0 = Zq::from((&r, &self.power2_of_d)).get_representative_least_absolute_residue();
        // 3: implicit: r_1 = (r^+ − r_0)/2^d
        let r_1 = r - &r_0; // We omit dividing by 2^d
        (r_1, r_0)
    }

    /// Extracts the higher-order and lower-order bits of the elements of a vector.
    ///
    /// This is used during key generation to split the public key vector `t` into
    /// a high-order part `t_1` (which is published) and a low-order part `t_0` (kept secret)
    /// s.t. `t_1 * 2^d + t_0 = t mod q`.
    ///
    /// Note: This implementation stores the literal difference `t - t_0` rather than
    /// explicitly dividing by `2^d`.
    ///
    /// Parameters:
    /// - `vector`: The vector of polynomials to be split.
    ///
    /// Returns a tuple `(vec1, vec0)`, each of type [`MatPolyOverZ`], representing the high bits and low bits respectively.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::integer_mod_q::MatPolynomialRingZq;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    /// let vec_t = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
    ///
    /// let (vec_t_1, vec_t_0) = ml_dsa.power2round(vec_t);
    /// ```
    ///
    /// # Panics ...
    /// - if `self.power2_of_d <= 1`.
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

                    let (coeff1, coeff0) = self.power2round_coeff(coeff);

                    unsafe { entry0.set_coeff_unchecked(i, coeff0) };
                    unsafe { entry1.set_coeff_unchecked(i, coeff1) };
                }

                unsafe { vec0.set_entry_unchecked(row, col, entry0) };
                unsafe { vec1.set_entry_unchecked(row, col, entry1) };
            }
        }

        (vec1, vec0)
    }

    /// Decomposes a single coefficient `r` into its high bits `r_1` and low bits `r_0`
    /// according to Decompose in FIPS 204 (Algorithm 36) s.t. `r_1 * (2 * 𝛾_2) + r_0 = r mod q`.
    /// It handles the edge case `r - r_0 = q - 1` by setting `r_1 = 0` and decrementing `r_0`.
    ///
    /// Parameters:
    /// - `r`: specifies the coefficient to decompose, expected to be in `[0, q)`
    ///
    /// Returns a tuple `(r_1, r_0)` of type [`Z`], where `r_1` is in `[0, (q - 1) / (2 * 𝛾_2))`
    /// and `r_0` is centered around `0` with `|r_0| <= 𝛾_2`.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::integer::Z;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44(); // 2 * 𝛾_2 = 190464
    ///
    /// let (r_1, r_0) = ml_dsa.decompose_coeff(Z::from(200000));
    ///
    /// assert_eq!(Z::ONE, r_1);
    /// assert_eq!(Z::from(9536), r_0);
    /// ```
    ///
    /// # Panics ...
    /// - if `2 * self.gamma_2 <= 1`.
    pub fn decompose_coeff(&self, r: Z) -> (Z, Z) {
        // 2: r_0 <- r^+ mod (2 * 𝛾_2)
        let mut r_0 = Zq::from((&r, 2 * self.gamma_2)).get_representative_least_absolute_residue();
        // 3: if r^+ - r_0 = q - 1 then
        if &r - &r_0 == self.modulus.get_q() - 1 {
            // 4: r_1 <- 0, 5: r_0 <- r_0 - 1
            r_0 -= 1;
            (Z::ZERO, r_0)
        }
        // 6: else r_1 <- (r^+ - r_0) / (2 * 𝛾_2)
        else {
            ((r - &r_0).div_floor(2 * self.gamma_2), r_0)
        }
    }

    /// Decomposes a vector into higher-order and lower-order bits modulo `q`.
    ///
    /// This function separates a polynomial into its high bits `r_1` and low bits `r_0`
    /// based on the `gamma_2` parameter s.t. `r_1 * (2 * 𝛾_2) + r_0 = r mod q`.
    /// It specifically handles the `q - 1` edge case
    /// to ensure values wrap correctly around the finite field boundary.
    ///
    /// Note: Coefficients in `vec0` are defined w.r.t. the modulus centered around `0` rather than the usual field `[0, q-1]`.
    ///
    /// Parameters:
    /// - `vector`: The vector of polynomials to decompose.
    ///
    /// Returns a tuple `(vec1, vec0)`, each of type [`MatPolyOverZ`], representing the high bits and low bits respectively.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::integer_mod_q::MatPolynomialRingZq;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    /// let vec_r = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
    ///
    /// let (vec_r_1, vec_r_0) = ml_dsa.decompose(&vec_r);
    /// ```
    ///
    /// # Panics ...
    /// - if `2 * self.gamma_2 <= 1`.
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
                    let (coeff1, coeff0) = self.decompose_coeff(coeff);

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
    /// In contrast to `SampleInBall` in FIPS 204 (Algorithm 29), which derives positions and signs
    /// from `SHAKE256` via an inside-out Fisher-Yates shuffle, this function seeds a [`SmallRng`] and
    /// resamples uniform positions until `tau` distinct ones are set. Hence, it yields the same
    /// distribution, but different concrete outputs for a given seed.
    ///
    /// Parameters:
    /// - `seed`: A 32-byte seed used to deterministically generate the polynomial.
    ///
    /// Returns a [`PolyOverZ`] representing the challenge polynomial.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    ///
    /// let c = ml_dsa.modified_sample_in_ball([0u8; 32]);
    ///
    /// assert_eq!(c, ml_dsa.modified_sample_in_ball([0u8; 32]));
    /// ```
    ///
    /// # Panics ...
    /// - if `self.phi <= 0`. If `self.tau > self.phi`, this function does not terminate,
    ///   as it cannot find `tau` distinct positions.
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

    /// Computes the hint bit for a single coefficient according to MakeHint
    /// in FIPS 204 (Algorithm 39), i.e. checks whether adding `z` to `r` changes the high bits of `r`.
    ///
    /// Parameters:
    /// - `r`: specifies the original coefficient, expected to be in `[0, q)`
    /// - `r_plus_z`: specifies the coefficient `(r + z) mod q`, expected to be in `[0, q)`
    ///
    /// Returns `true` if the high bits of `r` and `r + z` differ, and `false` otherwise.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::integer::Z;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    ///
    /// // 95000 has high bits 0, 95500 has high bits 1
    /// assert!(ml_dsa.make_hint_coeff(Z::from(95000), Z::from(95500)));
    /// // 100 and 200 share high bits 0
    /// assert!(!ml_dsa.make_hint_coeff(Z::from(100), Z::from(200)));
    /// ```
    ///
    /// # Panics ...
    /// - if `2 * self.gamma_2 <= 1`.
    pub fn make_hint_coeff(&self, r: Z, r_plus_z: Z) -> bool {
        // 1: r_1 <- HighBits(r)
        let (r_1, _) = self.decompose_coeff(r);
        // 2: v_1 <- HighBits(r + z)
        let (v_1, _) = self.decompose_coeff(r_plus_z);
        // 3: return [[ r_1 != v_1 ]]
        r_1 != v_1
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
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::{integer::MatPolyOverZ, integer_mod_q::MatPolynomialRingZq};
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    /// let vec_r = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
    /// let vec_z = MatPolynomialRingZq::from((MatPolyOverZ::new(ml_dsa.k, 1), &ml_dsa.modulus));
    ///
    /// let hint = ml_dsa.make_hint(&vec_z, &vec_r);
    ///
    /// assert_eq!(hint, MatPolyOverZ::new(ml_dsa.k, 1));
    /// ```
    ///
    /// # Panics ...
    /// - if `2 * self.gamma_2 <= 1`.
    pub fn make_hint(
        &self,
        z_vector: &MatPolynomialRingZq,
        r_vector: &MatPolynomialRingZq,
    ) -> MatPolyOverZ {
        assert_eq!(z_vector.get_num_rows(), r_vector.get_num_rows());
        assert_eq!(z_vector.get_num_columns(), r_vector.get_num_columns());
        assert_eq!(z_vector.get_mod(), r_vector.get_mod());

        let vec_r_plus_z = r_vector + z_vector;
        let mut hint = MatPolyOverZ::new(r_vector.get_num_rows(), r_vector.get_num_columns());

        for row in 0..r_vector.get_num_rows() {
            for col in 0..r_vector.get_num_columns() {
                let r_entry: PolyOverZ = unsafe { r_vector.get_entry_unchecked(row, col) };
                let r_plus_z_entry: PolyOverZ =
                    unsafe { vec_r_plus_z.get_entry_unchecked(row, col) };
                let mut hint_poly = PolyOverZ::default();

                for i in 0..self.phi {
                    let r_coeff = unsafe { r_entry.get_coeff_unchecked(i) };
                    let r_plus_z_coeff = unsafe { r_plus_z_entry.get_coeff_unchecked(i) };

                    if self.make_hint_coeff(r_coeff, r_plus_z_coeff) {
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

    /// Recovers the high bits of a single coefficient using its hint bit
    /// according to UseHint in FIPS 204 (Algorithm 40).
    ///
    /// Parameters:
    /// - `h`: specifies the hint bit, where `1` indicates that the high bits need correction
    ///   and any other value leaves them unchanged
    /// - `r`: specifies the coefficient whose high bits are recovered, expected to be in `[0, q)`
    /// - `m`: specifies the number of possible high-bit values, i.e. `(q - 1) / (2 * 𝛾_2)`
    ///
    /// Returns the corrected high bits of `r` as a [`Z`] in `[0, m)`.
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::integer::Z;
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    /// let m = Z::from(44); // (q - 1) / (2 * 𝛾_2)
    ///
    /// // MakeHint(500, 95000) = 1, and UseHint recovers HighBits(95500) = 1 from 95000 alone
    /// let high_bits = ml_dsa.use_hint_coeff(Z::ONE, Z::from(95000), &m);
    ///
    /// assert_eq!(Z::ONE, high_bits);
    /// ```
    ///
    /// # Panics ...
    /// - if `2 * self.gamma_2 <= 1`.
    /// - if `m` is `0` and `h = 1`.
    pub fn use_hint_coeff(&self, h: Z, r: Z, m: &Z) -> Z {
        // 2: (r_1, r_0) <- Decompose(r)
        let (r_1, r_0) = self.decompose_coeff(r);
        // 3: if h = 1 and r_0 > 0 return (r_1 + 1) mod m
        if h == 1 && r_0 > 0 {
            (r_1 + 1) % m
        }
        // 4: if h = 1 and r_0 <= 0 return (r_1 - 1) mod m
        else if h == 1 && r_0 <= 0 {
            (r_1 - 1) % m
        } else {
            r_1
        }
    }

    /// Reconstructs the high bits of a polynomial using a previously generated hint.
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
    ///
    /// # Examples
    /// ```
    /// use qfall_schemes::signature::MLDSA;
    /// use qfall_math::{integer::MatPolyOverZ, integer_mod_q::MatPolynomialRingZq};
    ///
    /// let ml_dsa = MLDSA::ml_dsa_44();
    /// let vec_r = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
    /// let vec_z = MatPolyOverZ::sample_uniform(ml_dsa.k, 1, ml_dsa.phi - 1, -1000, 1001).unwrap();
    /// let vec_z = MatPolynomialRingZq::from((vec_z, &ml_dsa.modulus));
    ///
    /// let hint = ml_dsa.make_hint(&vec_z, &vec_r);
    /// let high_bits = ml_dsa.use_hint(&hint, &vec_r);
    ///
    /// // the hint recovers HighBits(r + z) from r alone
    /// assert_eq!(high_bits, ml_dsa.decompose(&(&vec_r + &vec_z)).0);
    /// ```
    ///
    /// # Panics ...
    /// - if `2 * self.gamma_2 <= 1`.
    /// - if `m` is `0` and `h = 1`.
    pub fn use_hint(
        &self,
        h_vector: &MatPolyOverZ,
        r_vector: &MatPolynomialRingZq,
    ) -> MatPolyOverZ {
        assert_eq!(h_vector.get_num_rows(), r_vector.get_num_rows());
        assert_eq!(h_vector.get_num_columns(), r_vector.get_num_columns());

        // 1: m <- (q - 1)/(2 * 𝛾_2)
        let m: Z = (self.modulus.get_q() - Z::ONE).div_floor(2 * self.gamma_2);

        let mut out = MatPolyOverZ::new(r_vector.get_num_rows(), r_vector.get_num_columns());

        for row in 0..r_vector.get_num_rows() {
            for col in 0..r_vector.get_num_columns() {
                let entry_r: PolyOverZ = unsafe { r_vector.get_entry_unchecked(row, col) };
                let entry_h: PolyOverZ = unsafe { h_vector.get_entry_unchecked(row, col) };
                let mut entry_out = PolyOverZ::default();

                for i in 0..self.phi {
                    let r_coeff = unsafe { entry_r.get_coeff_unchecked(i) };
                    let h_coeff = unsafe { entry_h.get_coeff_unchecked(i) };

                    unsafe {
                        entry_out.set_coeff_unchecked(i, self.use_hint_coeff(h_coeff, r_coeff, &m))
                    };
                }

                unsafe { out.set_entry_unchecked(row, col, entry_out) };
            }
        }

        out
    }
}

impl SignatureScheme for MLDSA {
    // (A, tr, s_1, s_2, t_0)
    type SecretKey = (
        MatPolynomialRingZq,
        [u8; 32],
        MatPolyOverZ,
        MatPolyOverZ,
        MatPolyOverZ,
    );

    // (A, t_1)
    type PublicKey = (MatPolynomialRingZq, MatPolyOverZ);

    // (c_tilde, z, h)
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
                    && vec_h.hamming_weight() <= self.omega
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

#[cfg(test)]
mod test_helpers {
    use crate::signature::MLDSA;
    use qfall_math::{
        integer::{MatPolyOverZ, PolyOverZ, Z},
        integer_mod_q::MatPolynomialRingZq,
        traits::{GetCoefficient, MatrixGetEntry, MatrixSetEntry},
    };

    /// Returns all [MLDSA] parameter sets.
    fn all_parameter_sets() -> [MLDSA; 3] {
        [MLDSA::ml_dsa_44(), MLDSA::ml_dsa_65(), MLDSA::ml_dsa_87()]
    }

    /// Returns the i-th coefficient of the polynomial.
    fn coeff(poly: &PolyOverZ, i: i64) -> Z {
        poly.get_coeff(i).unwrap()
    }

    /// Checks [`MLDSA::power2round_coeff`] on known values.
    #[test]
    fn power2round_coeff_known_values() {
        let ml_dsa = MLDSA::ml_dsa_44(); // 2^d = 8192

        assert_eq!((Z::ZERO, Z::ZERO), ml_dsa.power2round_coeff(Z::ZERO));
        assert_eq!(
            (Z::from(16384), Z::from(-4039)),
            ml_dsa.power2round_coeff(Z::from(12345))
        );
        assert_eq!(
            (Z::from(8192), Z::MINUS_ONE),
            ml_dsa.power2round_coeff(Z::from(8191))
        );
        assert_eq!(
            (Z::ZERO, Z::from(100)),
            ml_dsa.power2round_coeff(Z::from(100))
        );
    }

    /// Checks [`MLDSA::decompose_coeff`] on known values, including the `q - 1` edge case.
    #[test]
    fn decompose_coeff_known_values() {
        let ml_dsa = MLDSA::ml_dsa_44(); // 2 * 𝛾_2 = 190464, q = 8380417

        assert_eq!((Z::ZERO, Z::ZERO), ml_dsa.decompose_coeff(Z::ZERO));
        assert_eq!(
            (Z::ONE, Z::from(9536)),
            ml_dsa.decompose_coeff(Z::from(200000))
        );
        assert_eq!(
            (Z::ONE, Z::from(-94964)),
            ml_dsa.decompose_coeff(Z::from(95500))
        );
        assert_eq!(
            (Z::ZERO, Z::MINUS_ONE),
            ml_dsa.decompose_coeff(Z::from(8380416))
        );
    }

    /// Ensures that [`MLDSA::make_hint_coeff`] flags exactly the coefficients
    /// whose high bits change.
    #[test]
    fn make_hint_coeff_known_values() {
        let ml_dsa = MLDSA::ml_dsa_44();

        assert!(!ml_dsa.make_hint_coeff(Z::from(100), Z::from(100)));
        assert!(!ml_dsa.make_hint_coeff(Z::from(100), Z::from(200)));
        assert!(ml_dsa.make_hint_coeff(Z::from(95000), Z::from(95500)));
        // q - 1 has high bits 0, as does 0
        assert!(!ml_dsa.make_hint_coeff(Z::from(8380416), Z::ZERO));
    }

    /// Checks [`MLDSA::use_hint_coeff`] on known values, including wrap-arounds modulo `m`.
    #[test]
    fn use_hint_coeff_known_values() {
        let ml_dsa = MLDSA::ml_dsa_44();
        let m = Z::from(44);

        // h = 0 returns HighBits(r)
        assert_eq!(Z::ONE, ml_dsa.use_hint_coeff(Z::ZERO, Z::from(200000), &m));
        // h = 1, r_0 > 0 increments
        assert_eq!(Z::ONE, ml_dsa.use_hint_coeff(Z::ONE, Z::from(95000), &m));
        // h = 1, r_0 > 0 and r_1 = m - 1 wraps around to 0
        assert_eq!(Z::ZERO, ml_dsa.use_hint_coeff(Z::ONE, Z::from(8190052), &m));
        // h = 1, r_0 <= 0 and r_1 = 0 wraps around to m - 1
        assert_eq!(Z::from(43), ml_dsa.use_hint_coeff(Z::ONE, Z::ZERO, &m));
    }

    /// Ensures that `use_hint_coeff(make_hint_coeff(r, r + z), r) = HighBits(r + z)`
    /// for all `|z| <= 𝛾_2` on a grid of coefficients.
    #[test]
    fn hint_coeff_roundtrip() {
        let ml_dsa = MLDSA::ml_dsa_44();
        let q = ml_dsa.modulus.get_q();
        let m = (q.clone() - Z::ONE).div_floor(2 * ml_dsa.gamma_2);

        for r in (0..8380417_i64).step_by(99991) {
            for z in [-ml_dsa.gamma_2, -1, 0, 1, ml_dsa.gamma_2] {
                let r_plus_z = Z::from((r + z).rem_euclid(8380417));
                let h = ml_dsa.make_hint_coeff(Z::from(r), r_plus_z.clone());
                let h = if h { Z::ONE } else { Z::ZERO };

                assert_eq!(
                    ml_dsa.decompose_coeff(r_plus_z).0,
                    ml_dsa.use_hint_coeff(h, Z::from(r), &m)
                );
            }
        }
    }

    /// Ensures that `t_1 + t_0 = t`, `|t_0| <= 2^{d-1}`, and `2^d | t_1`.
    #[test]
    fn power2round_reconstructs() {
        for ml_dsa in all_parameter_sets() {
            let vec_t = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
            let (vec_t_1, vec_t_0) = ml_dsa.power2round(vec_t.clone());
            let half = ml_dsa.power2_of_d.div_floor(2);

            for row in 0..ml_dsa.k {
                let t: PolyOverZ = vec_t.get_entry(row, 0).unwrap();
                let t_1: PolyOverZ = vec_t_1.get_entry(row, 0).unwrap();
                let t_0: PolyOverZ = vec_t_0.get_entry(row, 0).unwrap();

                for i in 0..ml_dsa.phi {
                    let (c, c_1, c_0) = (coeff(&t, i), coeff(&t_1, i), coeff(&t_0, i));

                    assert_eq!(c, &c_1 + &c_0);
                    assert!(c_0.abs() <= half);
                    assert_eq!(c_1 % &ml_dsa.power2_of_d, Z::ZERO);
                }
            }
        }
    }

    /// Ensures that `r_1 * 2 * gamma_2 + r_0 = r mod q`, `|r_0| <= gamma_2`,
    /// and `0 <= r_1 < (q - 1) / (2 * gamma_2)`.
    #[test]
    fn decompose_reconstructs() {
        for ml_dsa in all_parameter_sets() {
            let q = ml_dsa.modulus.get_q();
            let alpha = Z::from(2 * ml_dsa.gamma_2);
            let m = Z::from(&q - 1).div_floor(2 * ml_dsa.gamma_2);

            let vec_r = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
            let (vec_r_1, vec_r_0) = ml_dsa.decompose(&vec_r);

            for row in 0..ml_dsa.k {
                let r: PolyOverZ = vec_r.get_entry(row, 0).unwrap();
                let r_1: PolyOverZ = vec_r_1.get_entry(row, 0).unwrap();
                let r_0: PolyOverZ = vec_r_0.get_entry(row, 0).unwrap();

                for i in 0..ml_dsa.phi {
                    let (c, c_1, c_0) = (coeff(&r, i), coeff(&r_1, i), coeff(&r_0, i));

                    assert_eq!((&c_1 * &alpha + &c_0 - &c) % &q, Z::ZERO);
                    assert!(c_0.abs() <= ml_dsa.gamma_2);
                    assert!(Z::ZERO <= c_1 && c_1 < m);
                }
            }
        }
    }

    /// Ensures that the edge case `r = q - 1` is decomposed into `r_1 = 0` and `r_0 = -1`.
    #[test]
    fn decompose_edge_case() {
        let ml_dsa = MLDSA::ml_dsa_44();
        let mut vec_r = MatPolyOverZ::new(1, 1);
        vec_r.set_entry(0, 0, &PolyOverZ::from(8380416)).unwrap();
        let vec_r = MatPolynomialRingZq::from((vec_r, &ml_dsa.modulus));

        let (vec_r_1, vec_r_0) = ml_dsa.decompose(&vec_r);
        let r_1: PolyOverZ = vec_r_1.get_entry(0, 0).unwrap();
        let r_0: PolyOverZ = vec_r_0.get_entry(0, 0).unwrap();

        assert_eq!(coeff(&r_1, 0), Z::ZERO);
        assert_eq!(coeff(&r_0, 0), Z::MINUS_ONE);
    }

    /// Ensures that the challenge is deterministic in the seed, has exactly `tau`
    /// non-zero coefficients, and all coefficients are in `{-1, 0, 1}`.
    #[test]
    fn sample_in_ball_properties() {
        for ml_dsa in all_parameter_sets() {
            let c = ml_dsa.modified_sample_in_ball([7u8; 32]);

            assert_eq!(c, ml_dsa.modified_sample_in_ball([7u8; 32]));
            assert_ne!(c, ml_dsa.modified_sample_in_ball([8u8; 32]));
            assert!(c.get_degree() < ml_dsa.phi);

            let mut weight = 0;
            for i in 0..ml_dsa.phi {
                let value = coeff(&c, i);
                assert!(value == Z::ZERO || value == Z::ONE || value == Z::MINUS_ONE);
                if value != Z::ZERO {
                    weight += 1;
                }
            }
            assert_eq!(weight, ml_dsa.tau);
        }
    }

    /// Ensures that a zero shift yields an all-zero hint and that
    /// using this hint returns `HighBits(r)`.
    #[test]
    fn zero_hint() {
        for ml_dsa in all_parameter_sets() {
            let vec_r = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
            let zero = MatPolynomialRingZq::from((MatPolyOverZ::new(ml_dsa.k, 1), &ml_dsa.modulus));

            let hint = ml_dsa.make_hint(&zero, &vec_r);

            assert_eq!(hint, MatPolyOverZ::new(ml_dsa.k, 1));
            assert_eq!(ml_dsa.use_hint(&hint, &vec_r), ml_dsa.decompose(&vec_r).0);
        }
    }

    /// Ensures `UseHint(MakeHint(z, r), r) = HighBits(r + z)` for `||z||_∞ <= gamma_2`.
    #[test]
    fn hint_roundtrip() {
        for ml_dsa in all_parameter_sets() {
            for _ in 0..5 {
                let vec_r = MatPolynomialRingZq::sample_uniform(ml_dsa.k, 1, &ml_dsa.modulus);
                let vec_z = MatPolyOverZ::sample_uniform(
                    ml_dsa.k,
                    1,
                    ml_dsa.phi - 1,
                    -ml_dsa.gamma_2,
                    ml_dsa.gamma_2 + 1,
                )
                .unwrap();
                let vec_z = MatPolynomialRingZq::from((vec_z, &ml_dsa.modulus));

                let hint = ml_dsa.make_hint(&vec_z, &vec_r);

                assert_eq!(
                    ml_dsa.use_hint(&hint, &vec_r),
                    ml_dsa.decompose(&(&vec_r + &vec_z)).0
                );
            }
        }
    }
}
