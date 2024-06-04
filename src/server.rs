use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use crate::client::Client;
use crate::user_id::UserId;
use sha2::{Digest, Sha256};

type DataType = CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>;

pub struct Server {
    token: u32,
    data: DataType,
}

impl Server {
    pub fn new(user_id: &UserId) -> Server {
        let token = Self::generate_token();
        Server {
            token,
            data: Self::registration(user_id, token),
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
    pub fn registration(user_id: &UserId, server_token: u32) -> DataType{
        let hash = Self::sha256_hash(&user_id);
        let arith = Self::hash_to_polynomial(hash);

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_target();
        let t = builder.constant(F::from_canonical_u32(server_token));
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
        pw.set_target(x, F::from_canonical_u32(server_token));
        let data = builder.build::<C>();
        data
    }
    fn generate_token() -> u32 {
        let token = rand::random::<u32>();
        token
    }

    pub fn verify_proof(&self, client: Client) -> Result<()> {
        let data = Self::get_data(&self);
        let proof = client.get_proof();
        data.verify(proof)
    }
    pub fn get_token(&self) -> u32{
        self.token
    }
    pub fn get_data(&self) -> &DataType{
        &self.data
    }
}