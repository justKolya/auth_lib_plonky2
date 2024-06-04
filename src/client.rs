use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use sha2::{Digest, Sha256};
use crate::user_id::UserId;

type ProofType = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

pub struct Client {
    proof: ProofType,
}

impl Client {

    pub fn new(user_id: &UserId, token: u32) -> Client {
        Client {
            proof: Self::generate_proof(user_id, token),
        }
    }

    pub fn sha256_hash(userid: &UserId) -> [u8; 32] {
        let message = format!("{}{}", <UserId as Clone>::clone(&userid).get_userid_name(), <UserId as Clone>::clone(&userid).get_userid_id());
        let mut hasher = Sha256::new();
        hasher.update(message);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn hash_to_polynomial(hash: [u8; 32]) -> [u32; 8] {
        let mut polynomial = [0u32; 8];

        for i in 0..8 {
            let offset = i * 4;
            polynomial[i] = u32::from_be_bytes([
                hash[offset],
                hash[offset + 1],
                hash[offset + 2],
                hash[offset + 3],
            ]);
        }

        polynomial
    }
    pub fn generate_proof(user_id: &UserId, token: u32) -> ProofType {
        let hash = Self::sha256_hash(&user_id);
        let arith = Self::hash_to_polynomial(hash);
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let x = builder.add_virtual_target();
        let t = builder.constant(F::from_canonical_u32(token));
        let k = builder.constant(F::from_canonical_u32(arith[0]));
        let k0 = builder.add(t, k);
        let k1 = builder.mul_const(F::from_canonical_u32(arith[1]), x);
        let s1 = builder.add(k0, k1);
        let x2 = builder.mul(x, x);
        let k2 = builder.mul_const(F::from_canonical_u32(arith[2]), x2);
        let s2 = builder.add(s1, k2);
        let x3 = builder.mul(x2, x);
        let k3 = builder.mul_const(F::from_canonical_u32(arith[3]), x3);
        let s3 = builder.add(s2,k3);
        let x4 = builder.mul(x3, x);
        let k4 = builder.mul_const(F::from_canonical_u32(arith[4]), x4);
        let s4 = builder.add(s3,k4);
        let x5 = builder.mul(x4, x);
        let k5 = builder.mul_const(F::from_canonical_u32(arith[5]), x5);
        let s5 = builder.add(s4,k5);
        let x6 = builder.mul(x5, x);
        let k6 = builder.mul_const(F::from_canonical_u32(arith[6]), x6);
        let s6 = builder.add(s5,k6);
        let x7 = builder.mul(x6, x);
        let k7 = builder.mul_const(F::from_canonical_u32(arith[7]), x7);
        let s7 = builder.add(s6,k7);
        
        builder.register_public_input(x);
        builder.register_public_input(s7);
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u32(token));
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        proof
    }
    pub fn get_proof(self) -> ProofType{
        self.proof
    }
}