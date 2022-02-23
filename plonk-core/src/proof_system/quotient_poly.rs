// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{
    commitment::HomomorphicCommitment,
    error::Error,
    proof_system::{
        ecc::{CurveAddition, FixedBaseScalarMul},
        logic::Logic,
        range::Range,
        widget::GateConstraint,
        ProverKey,
    },
};
use ark_ec::TEModelParameters;
use ark_ff::{FftField, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain,
    UVPolynomial,
};

use super::{
    ecc::{CAVals, FBSMVals},
    linearisation_poly::CustomEvaluations,
    logic::LogicVals,
    range::RangeVals,
    CustomValues, WitnessValues,
};

/// Computes the Quotient [`DensePolynomial`] given the [`EvaluationDomain`], a
/// [`ProverKey`], and some other info.
pub fn compute<F, P, PC>(
    domain: &GeneralEvaluationDomain<F>,
    prover_key: &ProverKey<F, PC>,
    z_poly: &DensePolynomial<F>,
    z_2_poly: &DensePolynomial<F>,
    w_l_poly: &DensePolynomial<F>,
    w_r_poly: &DensePolynomial<F>,
    w_o_poly: &DensePolynomial<F>,
    w_4_poly: &DensePolynomial<F>,
    public_inputs_poly: &DensePolynomial<F>,
    f_poly: &DensePolynomial<F>,
    t_poly: &DensePolynomial<F>,
    h_1_poly: &DensePolynomial<F>,
    h_2_poly: &DensePolynomial<F>,
    alpha: &F,
    beta: &F,
    gamma: &F,
    delta: &F,
    epsilon: &F,
    zeta: &F,
    range_challenge: &F,
    logic_challenge: &F,
    fixed_base_challenge: &F,
    var_base_challenge: &F,
    lookup_challenge: &F,
) -> Result<DensePolynomial<F>, Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    PC: HomomorphicCommitment<F>,
{
    let domain_4n = GeneralEvaluationDomain::<F>::new(4 * domain.size())
        .ok_or(Error::InvalidEvalDomainSize {
        log_size_of_group: (4 * domain.size()).trailing_zeros(),
        adicity:
            <<F as FftField>::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
    })?;

    let mut z_eval_4n = domain_4n.coset_fft(z_poly);
    z_eval_4n.push(z_eval_4n[0]);
    z_eval_4n.push(z_eval_4n[1]);
    z_eval_4n.push(z_eval_4n[2]);
    z_eval_4n.push(z_eval_4n[3]);

    let mut wl_eval_4n = domain_4n.coset_fft(w_l_poly);
    wl_eval_4n.push(wl_eval_4n[0]);
    wl_eval_4n.push(wl_eval_4n[1]);
    wl_eval_4n.push(wl_eval_4n[2]);
    wl_eval_4n.push(wl_eval_4n[3]);

    let mut z2_eval_4n = domain_4n.coset_fft(z_2_poly);
    z2_eval_4n.push(z2_eval_4n[0]);
    z2_eval_4n.push(z2_eval_4n[1]);
    z2_eval_4n.push(z2_eval_4n[2]);
    z2_eval_4n.push(z2_eval_4n[3]);

    let mut wr_eval_4n = domain_4n.coset_fft(w_r_poly);
    wr_eval_4n.push(wr_eval_4n[0]);
    wr_eval_4n.push(wr_eval_4n[1]);
    wr_eval_4n.push(wr_eval_4n[2]);
    wr_eval_4n.push(wr_eval_4n[3]);

    let wo_eval_4n = domain_4n.coset_fft(w_o_poly);

    let mut w4_eval_4n = domain_4n.coset_fft(w_4_poly);
    w4_eval_4n.push(w4_eval_4n[0]);
    w4_eval_4n.push(w4_eval_4n[1]);
    w4_eval_4n.push(w4_eval_4n[2]);
    w4_eval_4n.push(w4_eval_4n[3]);

    let f_eval_4n = domain_4n.coset_fft(f_poly);

    let mut t_eval_4n = domain_4n.coset_fft(t_poly);
    t_eval_4n.push(t_eval_4n[0]);
    t_eval_4n.push(t_eval_4n[1]);
    t_eval_4n.push(t_eval_4n[2]);
    t_eval_4n.push(t_eval_4n[3]);

    let mut h1_eval_4n = domain_4n.coset_fft(h_1_poly);
    h1_eval_4n.push(h1_eval_4n[0]);
    h1_eval_4n.push(h1_eval_4n[1]);
    h1_eval_4n.push(h1_eval_4n[2]);
    h1_eval_4n.push(h1_eval_4n[3]);

    let mut h2_eval_4n = domain_4n.coset_fft(h_2_poly);
    h2_eval_4n.push(h2_eval_4n[0]);
    h2_eval_4n.push(h2_eval_4n[1]);
    h2_eval_4n.push(h2_eval_4n[2]);
    h2_eval_4n.push(h2_eval_4n[3]);

    let gate_constraints = compute_gate_constraint_satisfiability::<F, P, PC>(
        domain,
        *range_challenge,
        *logic_challenge,
        *fixed_base_challenge,
        *var_base_challenge,
        *lookup_challenge,
        prover_key,
        &wl_eval_4n,
        &wr_eval_4n,
        &wo_eval_4n,
        &w4_eval_4n,
        public_inputs_poly,
        &f_eval_4n,
        zeta,
    )?;

    let permutation = compute_permutation_checks::<F, PC>(
        domain,
        prover_key,
        &wl_eval_4n,
        &wr_eval_4n,
        &wo_eval_4n,
        &w4_eval_4n,
        &z_eval_4n,
        &z2_eval_4n,
        &t_eval_4n,
        &h1_eval_4n,
        &h2_eval_4n,
        *alpha,
        *beta,
        *gamma,
        *delta,
        *epsilon,
    )?;

    let quotient = (0..domain_4n.size())
        .map(|i| {
            let numerator = gate_constraints[i] + permutation[i];
            let denominator = prover_key.v_h_coset_4n()[i];
            numerator * denominator.inverse().unwrap()
        })
        .collect::<Vec<_>>();

    Ok(DensePolynomial::from_coefficients_vec(
        domain_4n.coset_ifft(&quotient),
    ))
}

/// Computes contribution to the quotient polynomial that ensures
/// the gate constraints are satisfied.
fn compute_gate_constraint_satisfiability<F, P, PC>(
    domain: &GeneralEvaluationDomain<F>,
    range_challenge: F,
    logic_challenge: F,
    fixed_base_challenge: F,
    var_base_challenge: F,
    lookup_challenge: F,
    prover_key: &ProverKey<F>,
    wl_eval_4n: &[F],
    wr_eval_4n: &[F],
    wo_eval_4n: &[F],
    w4_eval_4n: &[F],
    pi_poly: &DensePolynomial<F>,
    f_eval_4n: &[F],
    zeta: &F,
) -> Result<Vec<F>, Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    PC: HomomorphicCommitment<F>,
{
    let domain_4n = GeneralEvaluationDomain::<F>::new(4 * domain.size())
        .ok_or(Error::InvalidEvalDomainSize {
        log_size_of_group: (4 * domain.size()).trailing_zeros(),
        adicity:
            <<F as FftField>::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
    })?;
    let pi_eval_4n = domain_4n.coset_fft(pi_poly);

    // TODO Eliminate contribution of unused gates
    Ok((0..domain_4n.size())
        .map(|i| {
            let wit_vals = WitnessValues {
                a_val: wl_eval_4n[i],
                b_val: wr_eval_4n[i],
                c_val: wo_eval_4n[i],
                d_val: w4_eval_4n[i],
            };

            let custom_vals = CustomEvaluations {
                vals: vec![
                    ("a_next_eval".to_string(), wl_eval_4n[i + 4]),
                    ("b_next_eval".to_string(), wr_eval_4n[i + 4]),
                    ("d_next_eval".to_string(), w4_eval_4n[i + 4]),
                    ("q_l_eval".to_string(), prover_key.arithmetic.q_l.1[i]),
                    ("q_r_eval".to_string(), prover_key.arithmetic.q_r.1[i]),
                    ("q_c_eval".to_string(), prover_key.arithmetic.q_c.1[i]),
                ],
            };

            let arithmetic =
                prover_key.arithmetic.compute_quotient_i(i, wit_vals);

            let range = Range::quotient_term(
                prover_key.range_selector.1[i],
                range_challenge,
                wit_vals,
                RangeVals::from_evaluations(&custom_vals),
            );

            let logic = Logic::quotient_term(
                prover_key.logic_selector.1[i],
                logic_challenge,
                wit_vals,
                LogicVals::from_evaluations(&custom_vals),
            );

            let fixed_base_scalar_mul =
                FixedBaseScalarMul::<_, P>::quotient_term(
                    prover_key.fixed_group_add_selector.1[i],
                    fixed_base_challenge,
                    wit_vals,
                    FBSMVals::from_evaluations(&custom_vals),
                );

            let curve_addition = CurveAddition::<_, P>::quotient_term(
                prover_key.variable_group_add_selector.1[i],
                var_base_challenge,
                wit_vals,
                CAVals::from_evaluations(&custom_vals),
            );

            /*
            let f = f_eval_8n[i];

            let lookup = prover_key.lookup.compute_quotient_i(
                i,
                values.left,
                values.right,
                values.output,
                values.fourth,
                f,
                *zeta,
                lookup_challenge,
            );
            */

            (arithmetic + pi_eval_4n[i])
                + range
                + logic
                + fixed_base_scalar_mul
                + curve_addition
            // + lookup
        })
        .collect())
}

/// Computes the permutation contribution to the quotient polynomial over
/// `domain`.
fn compute_permutation_checks<F, PC>(
    domain: &GeneralEvaluationDomain<F>,
    prover_key: &ProverKey<F, PC>,
    wl_eval_4n: &[F],
    wr_eval_4n: &[F],
    wo_eval_4n: &[F],
    w4_eval_4n: &[F],
    z_eval_4n: &[F],
    z_2_eval_4n: &[F],
    t_eval_4n: &[F],
    h_1_eval_4n: &[F],
    h_2_eval_4n: &[F],
    alpha: F,
    beta: F,
    gamma: F,
    delta: F,
    epsilon: F,
) -> Result<Vec<F>, Error>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    let domain_4n = GeneralEvaluationDomain::<F>::new(4 * domain.size())
        .ok_or(Error::InvalidEvalDomainSize {
        log_size_of_group: (4 * domain.size()).trailing_zeros(),
        adicity:
            <<F as FftField>::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
    })?;
    let l1_poly_alpha =
        compute_first_lagrange_poly_scaled(domain, alpha.square());
    let l1_alpha_sq_evals = domain_4n.coset_fft(&l1_poly_alpha.coeffs);
    let alpha_five = (alpha.square() + alpha.square()) + alpha;
    let l1_alpha_five_evals = domain_4n.coset_fft(&l1_poly_alpha.coeffs);

    Ok((0..domain_4n.size())
        .map(|i| {
            prover_key.permutation.compute_quotient_i(
                i,
                wl_eval_4n[i],
                wr_eval_4n[i],
                wo_eval_4n[i],
                w4_eval_4n[i],
                z_eval_4n[i],
                z_eval_4n[i + 4],
                z_2_eval_4n[i],
                z_2_eval_4n[i + 4],
                t_eval_4n[i],
                t_eval_4n[i + 4],
                h_1_eval_4n[i],
                h_1_eval_4n[i + 4],
                h_2_eval_4n[i],
                alpha,
                l1_alpha_sq_evals[i],
                l1_alpha_five_evals[i],
                beta,
                gamma,
                delta,
                epsilon,
            )
        })
        .collect())
}

/// Computes the first lagrange polynomial with the given `scale` over `domain`.
fn compute_first_lagrange_poly_scaled<F>(
    domain: &GeneralEvaluationDomain<F>,
    scale: F,
) -> DensePolynomial<F>
where
    F: FftField,
{
    let mut x_evals = vec![F::zero(); domain.size()];
    x_evals[0] = scale;
    domain.ifft_in_place(&mut x_evals);
    DensePolynomial::from_coefficients_vec(x_evals)
}
