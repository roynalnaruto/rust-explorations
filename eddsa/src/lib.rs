use std::ops::MulAssign;

use algebra_core::{
    curves::ProjectiveCurve,
    fields::Field
};
use algebra::{
    {to_bytes, ToBytes},
    edwards_bls12::{EdwardsProjective, Fr}
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

#[derive(Copy, Debug)]
pub struct SecretKey {
    key: Fr,
    lower_hash: [u8; 32],
    upper_hash: [u8; 32],
}

impl SecretKey {
    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut random_bytes = [0u8; 32];
        let mut hasher = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower_hash: [u8; 32] = [0u8; 32];
        let mut upper_hash: [u8; 32] = [0u8; 32];

        let key = loop {
            rng.fill_bytes(&mut random_bytes);
            if let Some(sk) = Fr::from_random_bytes(&random_bytes)
                .and_then(|x| {
                    Some(x)
                }) {
                break sk;
            }
        };

        hasher.input(to_bytes![key].unwrap());
        hash.copy_from_slice(hasher.result().as_slice());
        lower_hash.copy_from_slice(&hash[0..32]);
        upper_hash.copy_from_slice(&hash[32..64]);

        // Only consider the low 250 bits
        // since MODULUS is 251 bits.
        // Is there any function that gets Fr mod r?
        // in that case can send all bytes
        lower_hash[31] &= 0b0000_0011;

        SecretKey {
            key: key,
            lower_hash: lower_hash,
            upper_hash: upper_hash
        }
    }
}

impl From<Fr> for SecretKey {
    fn from(key: Fr) -> Self {
        let mut hasher = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower_hash: [u8; 32] = [0u8; 32];
        let mut upper_hash: [u8; 32] = [0u8; 32];

        hasher.input(to_bytes![key].unwrap());
        hash.copy_from_slice(hasher.result().as_slice());
        lower_hash.copy_from_slice(&hash[0..32]);
        upper_hash.copy_from_slice(&hash[32..64]);

        // Only consider the low 250 bits
        // since MODULUS is 251 bits.
        // Is there any function that gets Fr mod r?
        // in that case can send all bytes
        lower_hash[31] &= 0b0000_0011;

        SecretKey {
            key: key,
            lower_hash: lower_hash,
            upper_hash: upper_hash
        }
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Debug)]
pub struct PublicKey {
    point: EdwardsProjective
}

impl PublicKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let mut hasher: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        hasher.input(&to_bytes![signature.R].unwrap());
        hasher.input(&to_bytes![self.point].unwrap());
        hasher.input(msg);
        hash.copy_from_slice(hasher.result().as_slice());
        hash[31] &= 0b0000_0011;

        // h = H(R, pub_key, msg)
        let h = Fr::from_random_bytes(&hash[0..32]).unwrap();

        // lhs = s*G
        let mut lhs: EdwardsProjective = EdwardsProjective::prime_subgroup_generator();
        lhs.mul_assign(signature.s);

        // rhs = R + h*pub_key
        let mut pub_key = self.point;
        pub_key.mul_assign(h);
        let rhs: EdwardsProjective = signature.R + pub_key;

        lhs.eq(&rhs)
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let mut lower_hash_bytes: [u8; 32] = [0u8; 32];
        lower_hash_bytes.copy_from_slice(&sk.lower_hash);

        let s = Fr::from_random_bytes(&lower_hash_bytes).unwrap();
        let mut pk = EdwardsProjective::prime_subgroup_generator();
        pk.mul_assign(s);

        PublicKey { point: pk }
    }
}

#[derive(Debug)]
pub struct Signature {
    R: EdwardsProjective,
    s: Fr
}

#[derive(Debug)]
pub struct Keypair {
    secret_key: SecretKey,
    public_key: PublicKey
}

impl Keypair {
    fn new<R: CryptoRng + RngCore>(mut rng: &mut R) -> Self {
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from(&sk);

        Keypair {
            secret_key: sk,
            public_key: pk
        }
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let mut hasher: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        hasher.input(&self.secret_key.upper_hash);
        hasher.input(msg);
        hash.copy_from_slice(hasher.result().as_slice());
        hash[31] &= 0b0000_0011;

        // r = H(upper(H(priv_key)), msg)
        // R = r*G
        let r = Fr::from_random_bytes(&hash[0..32]).unwrap();
        let mut R = EdwardsProjective::prime_subgroup_generator();
        R.mul_assign(r);

        hasher = Sha512::new();
        hash = [0u8; 64];
        hasher.input(&to_bytes![R].unwrap());
        hasher.input(&to_bytes![self.public_key.point].unwrap());
        hasher.input(msg);
        hash.copy_from_slice(hasher.result().as_slice());
        hash[31] &= 0b0000_0011;

        // h = H(R, pub_key, msg)
        // s = r + h*lower(H(priv_key))
        let h = Fr::from_random_bytes(&hash[0..32]).unwrap();
        let lower = Fr::from_random_bytes(&self.secret_key.lower_hash).unwrap();
        let s = r + (h * lower);

        Signature { R: R, s: s }
    }
}

impl From<&SecretKey> for Keypair {
    fn from(sk: &SecretKey) -> Self {
        let pk = PublicKey::from(sk);

        Keypair {
            secret_key: sk.clone(),
            public_key: pk
        }
    }
}

#[cfg(test)]
mod secret_key {
    use super::*;

    #[test]
    fn test_new() {
        let mut rng = rand::thread_rng();
        let _sk = SecretKey::new(&mut rng);
    }
}

#[cfg(test)]
mod public_key {
    use super::*;

    #[test]
    fn test_from() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::new(&mut rng);
        let _pk = PublicKey::from(&sk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let mut rng = rand::thread_rng();
        let _keypair = Keypair::new(&mut rng);
    }

    #[test]
    fn test_from() {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::new(&mut rng);
        let _keypair = Keypair::from(&sk);
    }

    #[test]
    fn test_sign() {
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new(&mut rng);
        let msg = b"hello";

        let _signature = keypair.sign(msg);
    }

    #[test]
    fn test_verify() {
        let mut rng = rand::thread_rng();
        let keypair = Keypair::new(&mut rng);
        let incorrect_keypair = Keypair::new(&mut rng);

        let msg = b"hello";
        let incorrect_msg = b"Hello";

        let signature = keypair.sign(msg);
        let incorrect_signature = incorrect_keypair.sign(msg);

        let valid = keypair.public_key.verify(msg, &signature);
        let invalid = keypair.public_key.verify(msg, &incorrect_signature);
        let invalid_also = keypair.public_key.verify(incorrect_msg, &signature);
        let invalid_again = incorrect_keypair.public_key.verify(msg, &signature);
        let but_valid_now = incorrect_keypair.public_key.verify(msg, &incorrect_signature);

        assert!(valid == true);
        assert!(invalid == false);
        assert!(invalid_also == false);
        assert!(invalid_again == false);
        assert!(but_valid_now == true);
    }
}
