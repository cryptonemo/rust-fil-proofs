use std::sync::Arc;

use anyhow::Result;
use bellperson::groth16;
use paired::bls12_381::Bls12;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::post::fallback;

use crate::parameters::{window_post_public_params, winning_post_public_params};
use crate::types::*;
use crate::{MerkleTreeTrait, PoStConfig};

type Bls12GrothParams = groth16::MappedParameters<Bls12>;
pub type Bls12VerifyingKey = groth16::VerifyingKey<Bls12>;

pub use filecoin_proofs_v2::caches::{
    cache_lookup, get_stacked_params, get_stacked_verifying_key, lookup_groth_params,
    lookup_verifying_key,
};

pub fn get_post_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12GrothParams>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::groth_params::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_groth_params(
                format!(
                    "WINNING_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                parameters_generator,
            )?)
        }
        PoStType::Window => {
            let post_public_params = window_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::groth_params::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_groth_params(
                format!(
                    "Window_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                parameters_generator,
            )?)
        }
    }
}

pub fn get_post_verifying_key<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12VerifyingKey>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let vk_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::verifying_key::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_verifying_key(
                format!(
                    "WINNING_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                vk_generator,
            )?)
        }
        PoStType::Window => {
            let post_public_params = window_post_public_params::<Tree>(post_config)?;

            let vk_generator = || {
                <fallback::FallbackPoStCompound<Tree> as CompoundProof<
                    fallback::FallbackPoSt<Tree>,
                    fallback::FallbackPoStCircuit<Tree>,
                >>::verifying_key::<rand::rngs::OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_verifying_key(
                format!(
                    "WINDOW_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                vk_generator,
            )?)
        }
    }
}
