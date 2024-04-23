//! PLONK Example
use ark_bls12_381::Bls12_381;
use ark_ec::{PairingEngine, TEModelParameters};
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_ff::{FftField, PrimeField};

use core::marker::PhantomData;
use plonk::commitment::{HomomorphicCommitment, KZG10};
use plonk::prelude::*;
use rand_core::OsRng;

/// Benchmark Circuit
#[derive(derivative::Derivative)]
#[derivative(Debug, Default)]
pub struct BenchCircuit<F, P> {
    /// Circuit Size
    size: usize,

    /// Field and parameters
    _phantom: PhantomData<(F, P)>,
}

impl<F, P> BenchCircuit<F, P> {
    /// Builds a new circuit with a constraint count of `2^degree`.
    #[inline]
    pub fn new(degree: usize) -> Self {
        Self {
            size: 1 << degree,
            _phantom: PhantomData::<(F, P)>,
        }
    }
}

impl<F, P> Circuit<F, P> for BenchCircuit<F, P>
where
    F: FftField + PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    #[inline]
    fn gadget(
        &mut self,
        composer: &mut StandardComposer<F, P>,
    ) -> Result<(), Error> {
        composer.add_dummy_lookup_table();
        while composer.circuit_bound() < self.size - 1 {
            composer.add_dummy_constraints();
        }
        Ok(())
    }

    #[inline]
    fn padded_circuit_size(&self) -> usize {
        self.size
    }
}

fn constraint_system_benchmark<F, P, HC>()
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
    HC: HomomorphicCommitment<F>,
{
    // let deg = vec![16, 17, 18, 19];
    let deg = vec![17];
    let rep = 3;
    let label = b"ark".as_slice();
    let pp = HC::setup(1 << deg.iter().max().unwrap(), None, &mut OsRng)
        .expect("Unable to sample public parameters.");

    for degree in deg {
        println!("\nRunning prover for degree: {}", degree);
        let mut circuit = BenchCircuit::<F, P>::new(degree);
        let (pk_p, _) = circuit
            .compile::<HC>(&pp)
            .expect("Unable to compile circuit.");
        for _ in 0..rep {
            circuit.gen_proof::<HC>(&pp, pk_p.clone(), &label).unwrap();
        }
    }
}

fn main() {
    type F = <Bls12_381 as PairingEngine>::Fr;
    type P = EdwardsParameters;
    type HC = KZG10<Bls12_381>;

    constraint_system_benchmark::<F, P, HC>();
    println!("KZG10 benchmarks complete.");
}
