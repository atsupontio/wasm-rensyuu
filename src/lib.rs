use wasm_bindgen::prelude::*;

use std::fmt::Write;
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}


pub fn hexdump_option(bytes: &[u8], max: usize) -> Vec<Option<u8>> {

    let mut sum = Vec::new();

    // println!("{} bytes:", bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        // b: &u8 の値を2桁の16進数で表示する
        let a = Some(*b);
        sum.push(a);

    }

    println!("bytes len {:?}", bytes.len());

    let count = max - bytes.len();
    for i in 0..count {
        sum.push(Some(000))
    }

    sum
}

pub fn hexdump(bytes: &[u8], max: usize) -> Vec<u8> {

    let mut sum = Vec::new();

    // println!("{} bytes:", bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        // b: &u8 の値を2桁の16進数で表示する
        let a = *b;
        sum.push(a);

    }

    let count = max - bytes.len();
    for i in 0..count {
        sum.push(000)
    }

    sum
}




use ark_crypto_primitives::crh::{TwoToOneCRH, injective_map::{PedersenCRHCompressor, TECompressor, constraints::{PedersenCRHCompressorGadget, TECompressorGadget}}, pedersen};
use ark_ec::bls12::Bls12;
use ark_ed_on_bls12_381::{EdwardsProjective, constraints::EdwardsVar};

use ark_bls12_381::{Fr, Bls12_381};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}; 
use ark_crypto_primitives::crh::constraints::{TwoToOneCRHGadget};
use ark_r1cs_std::{alloc::AllocVar};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::eq::EqGadget;
use ark_serialize::*;
use ark_groth16::ProvingKey;
use ark_bls12_381::Parameters;

// pub mod encode_hex;
// pub mod hash2;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 128;
}

use once_cell::sync::Lazy;
pub static PARAMETER: Lazy<Parameter> = Lazy::new(|| setup());

pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
pub type Image = <TwoToOneHash as TwoToOneCRH>::Output;

pub type ImageVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
pub type ConstraintF = ark_ed_on_bls12_381::Fq;
pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;
pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

const NUM_ID: usize = 40; // 35
const NUM_SECRET: usize = 6; // 4
const NUM_NONCR: usize = 6; // 4
const NUM_NAMR_BIRTH: usize = 40; // 32
const NUM_HASH: usize = 92;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone)]
pub struct HashDemo {
    pub id: Vec<Option<u8>>,
    pub secret: Vec<Option<u8>>,
    pub nonce: Vec<Option<u8>>,
    pub hashed_name_birth: Vec<Option<u8>>,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
    pub image: Option<Image>,
}

pub struct Parameter {
    parameter: ProvingKey<Bls12<Parameters>>,
}

impl Parameter {
    fn set_parameter(param: ProvingKey<Bls12<Parameters>>) -> Self {
        let param = Self { parameter: param};
        param
    }

    fn get_parameter(&self) -> ProvingKey<Bls12<Parameters>> {
        self.parameter.clone()
    }
}


impl ConstraintSynthesizer<Fr> for HashDemo { 
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {

        let image = ImageVar::new_input(ark_relations::ns!(cs, "image_var"), || self.image.ok_or(SynthesisError::AssignmentMissing))?;

        let two_to_one_crh_params =
        TwoToOneHashParamsVar::new_constant(ark_relations::ns!(cs, "parameters"), &self.two_to_one_crh_params)?;


        let mut left_bytes = vec![];
        for byte in 0..NUM_ID {
            left_bytes.push(UInt8::new_input(ark_relations::ns!(cs, "left preimage"), || self.id[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }
        for byte in 0..NUM_SECRET {
            left_bytes.push(UInt8::new_witness(ark_relations::ns!(cs, "left preimage"), || self.secret[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }
        let mut right_bytes = vec![];
        for byte in 0..NUM_NONCR {
            right_bytes.push(UInt8::new_witness(ark_relations::ns!(cs, "left preimage"), || self.nonce[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }
        for byte in 0..NUM_NAMR_BIRTH {
            right_bytes.push(UInt8::new_input(ark_relations::ns!(cs, "left preimage"), || self.hashed_name_birth[byte].ok_or(SynthesisError::AssignmentMissing)).unwrap());
        }

        let hash_result_var = TwoToOneHashGadget::evaluate(&two_to_one_crh_params, &left_bytes, &right_bytes).unwrap();

        hash_result_var.enforce_equal(&image)?;

        Ok(())
    }
}

/// return (param, vkey)
pub fn setup() -> Parameter {
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_groth16::generate_random_parameters;

    let mut rng = StdRng::seed_from_u64(0u64);

    // params to create hash
    let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    let pre_circuit = HashDemo {
        id: vec![None; NUM_ID],
        secret: vec![None; NUM_SECRET],
        nonce: vec![None; NUM_NONCR],
        hashed_name_birth: vec![None; NUM_NAMR_BIRTH],
        two_to_one_crh_params: params.clone(),
        image: None,
    };

    let param = generate_random_parameters::<Bls12_381, _, _>(pre_circuit.clone(), &mut rng).unwrap();
    let param_return = self::Parameter::set_parameter(param.clone());

    let mut vk_vec = Vec::new();
    param.vk.serialize(&mut vk_vec).unwrap();
    // let vkey_hex = format!("{}{}", "0x", encode_hex::encode_hex(&vk_vec));
    // let vkey_hex = encode_hex(&vk_vec);


    param_return
}

/// return (param, vkey)
#[wasm_bindgen]
#[cfg(feature = "console_error_panic_hook")]
pub fn get_vkey() -> String {
    // use ark_std::rand::{rngs::StdRng, SeedableRng};
    // use ark_groth16::generate_random_parameters;

    // let mut rng = StdRng::seed_from_u64(0u64);

    // // params to create hash
    // let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // let pre_circuit = HashDemo {
    //     id: vec![None; NUM_ID],
    //     secret: vec![None; NUM_SECRET],
    //     nonce: vec![None; NUM_NONCR],
    //     hashed_name_birth: vec![None; NUM_NAMR_BIRTH],
    //     two_to_one_crh_params: params.clone(),
    //     image: None,
    // };

    // let param = generate_random_parameters::<Bls12_381, _, _>(pre_circuit.clone(), &mut rng).unwrap();

    let param = &*PARAMETER;
    let param_return = param.get_parameter();

    let mut vk_vec = Vec::new();
    param_return.vk.serialize(&mut vk_vec).unwrap();
    // let vkey_hex = format!("{}{}", "0x", encode_hex::encode_hex(&vk_vec));
    let vkey_hex = encode_hex(&vk_vec);

    vkey_hex

}

fn create_input(id: &str, secret: &str, nonce: &str, name: &str, birth: &str) -> (Vec<Option<u8>>, Vec<Option<u8>>, Vec<Option<u8>>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // id
    // base58 decode id
    let new_id = base58::FromBase58::from_base58(id).unwrap();
    let new_id2 = encode_hex(new_id.as_slice());
    println!("new_id: {:?}", new_id2);
    // byte
    let mut id_bytes = hex::decode(&new_id2).unwrap();
    id_bytes.drain(0..=0);
    id_bytes.drain(id_bytes.len() - 2 ..= id_bytes.len() - 1);
    // option byte(0 padding)
    let id_option_bytes = hexdump_option(&id_bytes, NUM_ID);
    println!("id_bytes: {:?}", &id_bytes);
    // byte(0 padding)
    let id_bytes_fix = hexdump(&id_bytes, NUM_ID);

    let secret_bytes = hex::decode(&secret).unwrap();
    println!("secret: {:?}", secret_bytes);
    let secret_option_bytes = hexdump_option(&secret_bytes, NUM_SECRET);
    let secret_bytes_fix = hexdump(&secret_bytes, NUM_SECRET);

    let nonce_bytes = hex::decode(&nonce).unwrap();
    println!("nonce:{:?}", nonce_bytes);
    let nonce_option_bytes = hexdump_option(&nonce_bytes, NUM_NONCR);
    let nonce_bytes_fix = hexdump(&nonce_bytes, NUM_NONCR);

    let new_name = base58::FromBase58::from_base58(name).unwrap();
    let new_name2 = encode_hex(new_name.as_slice());
    println!("new_name: {:?}", new_name2);
    let name_bytes = hex::decode(&new_name2).unwrap();
    println!("name_bytes: {:?}", name_bytes);


    let birth_bytes = hex::decode(&birth).unwrap();
    println!("secret: {:?}", birth_bytes);


    return (id_option_bytes, secret_option_bytes, nonce_option_bytes, id_bytes_fix, secret_bytes_fix, nonce_bytes_fix, name_bytes, birth_bytes);
}

/// return (proof, hex_hash_name_birth, hex_CID)
#[wasm_bindgen]
pub fn create_proof(id: &str, secret: &str, nonce: &str, name: &str, birth: &str) -> String {
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_groth16::{create_random_proof, ProvingKey};
    
    // all outputs are padded by 0
    let (
        id_option_bytes,
        secret_option_bytes,
        mut nonce_option_bytes,
        mut id_bytes,
        mut secret_bytes,
        mut nonce_bytes,
        mut name_bytes,
        mut birth_bytes
    ) = create_input(id, secret, nonce, name, birth);

    // create name_birth hash
    // byte array to create hash
    name_bytes.append(&mut birth_bytes);

    // create name and birthday hash
    let mut name_birth_right = Vec::new();

    if name_bytes.len() % 2 == 0 {
        let len = name_bytes.len() / 2;
        name_birth_right = name_bytes.split_off(len);
    } else {
        name_bytes.push(000);
        let len = name_bytes.len() / 2;
        name_birth_right = name_bytes.split_off(len);
    }


    /* -----------------name_birth hash -------------------------- */

    let mut rng = StdRng::seed_from_u64(0u64);
    // params to create hash
    let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // hash!
    let hashed_name_birth = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, &name_bytes.as_slice(), &name_birth_right.as_slice()).unwrap();
    // serialize
    let mut result_vec = Vec::new();
    hashed_name_birth.serialize(&mut result_vec).unwrap();

    // copy serialized hash number
    let mut result2 = result_vec.clone();

    // name and birthday hash by option byte array(0 padding)
    let result_bytes_option = hexdump_option(&result2, NUM_NAMR_BIRTH);// size 40
    // padding 0
    let result_bytes = hexdump(&result2, NUM_NAMR_BIRTH);// size 40
    let hex_name_birth_hash = hex::encode(result_bytes);

    /* --------------end name_birth hash ---------------------------- */


    /* ---------------------- hash CID ---------------------------- */

    let mut preimage = id_bytes.clone(); // size 40

    // create byte array for hash
    preimage.append(&mut secret_bytes); // size 40 + 6
    preimage.append(&mut nonce_bytes); // size 46 + 6
    preimage.append(&mut result2); // size 52 + 40

    let mut right_half = Vec::new();

    let len = preimage.len() / 2;
    right_half = preimage.split_off(len);

    let left = preimage;
    let right = right_half;

    // hash result
    let primitive_result = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, left.as_slice(), right.as_slice()).unwrap();
    let mut image_vec = Vec::new();
    primitive_result.serialize(&mut image_vec).unwrap();
    // hex hash result
    let hex_result = encode_hex(&image_vec);
    println!("result: {:?}", hex_result);

    /* ----------------------- end hash CID ------------------------ */

    let circuit = HashDemo {
        id: id_option_bytes,
        secret: secret_option_bytes,
        nonce: nonce_option_bytes,
        hashed_name_birth: result_bytes_option,
        two_to_one_crh_params: params.clone(),
        image: Some(primitive_result),
    };

    let param_static = &*PARAMETER;

    let param = param_static.get_parameter();
    
    // proof
    let proof = create_random_proof(circuit.clone(), &param, &mut rng).unwrap();

    let mut proof_vec = Vec::new();
    proof.serialize(&mut proof_vec).unwrap();

    let proof_hex = encode_hex(&proof_vec);

    // (proof_hex, hex_name_birth_hash, hex_result)
    proof_hex
}

#[wasm_bindgen]
pub fn get_hash_name_birth(name: &str, birth: &str) -> String {

    use ark_std::rand::{rngs::StdRng, SeedableRng};

    let new_name = base58::FromBase58::from_base58(name).unwrap();
    let new_name2 = encode_hex(new_name.as_slice());
    
    let mut name_bytes = hex::decode(&new_name2).unwrap();
    

    let mut birth_bytes = hex::decode(&birth).unwrap();
    

    // create name_birth hash
    // byte array to create hash
    name_bytes.append(&mut birth_bytes);

    // create name and birthday hash
    let mut name_birth_right = Vec::new();

    if name_bytes.len() % 2 == 0 {
        let len = name_bytes.len() / 2;
        name_birth_right = name_bytes.split_off(len);
    } else {
        name_bytes.push(000);
        let len = name_bytes.len() / 2;
        name_birth_right = name_bytes.split_off(len);
    }


    let mut rng = StdRng::seed_from_u64(0u64);
    // params to create hash
    let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // hash!
    let hashed_name_birth = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, &name_bytes.as_slice(), &name_birth_right.as_slice()).unwrap();
    // serialize
    let mut result_vec = Vec::new();
    hashed_name_birth.serialize(&mut result_vec).unwrap();

    // copy serialized hash number
    let mut result2 = result_vec.clone();

    // name and birthday hash by option byte array(0 padding)
    let result_bytes_option = hexdump_option(&result2, NUM_NAMR_BIRTH);// size 40
    // padding 0
    let result_bytes = hexdump(&result2, NUM_NAMR_BIRTH);// size 40
    let hex_name_birth_hash = hex::encode(result_bytes);

    hex_name_birth_hash
}

#[wasm_bindgen]
pub fn get_CID(id: &str, secret: &str, nonce: &str, name: &str, birth: &str) -> String {
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    // all outputs are padded by 0
    let (
        id_option_bytes,
        secret_option_bytes,
        mut nonce_option_bytes,
        mut id_bytes,
        mut secret_bytes,
        mut nonce_bytes,
        mut name_bytes,
        mut birth_bytes
    ) = create_input(id, secret, nonce, name, birth);

    // create name_birth hash
    // byte array to create hash
    name_bytes.append(&mut birth_bytes);

    // create name and birthday hash
    let mut name_birth_right = Vec::new();

    if name_bytes.len() % 2 == 0 {
        let len = name_bytes.len() / 2;
        name_birth_right = name_bytes.split_off(len);
    } else {
        name_bytes.push(000);
        let len = name_bytes.len() / 2;
        name_birth_right = name_bytes.split_off(len);
    }


    let mut rng = StdRng::seed_from_u64(0u64);
    // params to create hash
    let params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // hash!
    let hashed_name_birth = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, &name_bytes.as_slice(), &name_birth_right.as_slice()).unwrap();
    // serialize
    let mut result_vec = Vec::new();
    hashed_name_birth.serialize(&mut result_vec).unwrap();

    // copy serialized hash number
    let mut result2 = result_vec.clone();

    let mut preimage = id_bytes.clone(); // size 40

    // create byte array for hash
    preimage.append(&mut secret_bytes); // size 40 + 6
    preimage.append(&mut nonce_bytes); // size 46 + 6
    preimage.append(&mut result2); // size 52 + 40

    let mut right_half = Vec::new();

    let len = preimage.len() / 2;
    right_half = preimage.split_off(len);

    let left = preimage;
    let right = right_half;

    // hash result
    let primitive_result = <TwoToOneHash as TwoToOneCRH>::evaluate(&params, left.as_slice(), right.as_slice()).unwrap();
    let mut image_vec = Vec::new();
    primitive_result.serialize(&mut image_vec).unwrap();
    // hex hash result
    let hex_result = encode_hex(&image_vec);
    hex_result
}