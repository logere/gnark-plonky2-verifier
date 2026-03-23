use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2x::backend::circuit::PlonkParameters;
use serde::Deserialize;
use serde::Serialize;
use starkyx::math::goldilocks::cubic::GoldilocksCubicParameters;
use starkyx::plonky2::stark::config::CurtaPoseidonGoldilocksConfig;

use crate::plonky2_config::PoseidonBN254GoldilocksConfig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Groth16WrapperParameters;

impl PlonkParameters<2> for Groth16WrapperParameters {
    type Field = GoldilocksField;

    type CubicParams = GoldilocksCubicParameters;

    type Config = PoseidonBN254GoldilocksConfig;

    type CurtaConfig = CurtaPoseidonGoldilocksConfig;
}
