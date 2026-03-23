use std::ops::AddAssign;
use std::ops::MulAssign;

use ff::Field;

use crate::fr_bn254::FrBn254;
use crate::poseidon_bn254_constants::C_CONSTANTS;
use crate::poseidon_bn254_constants::M_MATRIX;
use crate::poseidon_bn254_constants::P_MATRIX;
use crate::poseidon_bn254_constants::S_CONSTANTS;

pub const RATE: usize = 3;
pub const WIDTH: usize = 4;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;
pub const GOLDILOCKS_ELEMENTS: usize = 3;

pub type PoseidonState = [FrBn254; WIDTH];

pub fn permution(state: &mut PoseidonState) {
    ark(state, 0);
    full_rounds(state, true);
    partial_rounds(state);
    full_rounds(state, false);
}

fn ark(state: &mut PoseidonState, it: usize) {
    for i in 0..WIDTH {
        state[i].add_assign(&C_CONSTANTS[it + i]);
    }
}

fn exp5(mut x: FrBn254) -> FrBn254 {
    let aux = x;
    x = x.square();
    x = x.square();
    x.mul_assign(&aux);
    x
}

fn exp5_state(state: &mut PoseidonState) {
    for state_element in state.iter_mut().take(WIDTH) {
        *state_element = exp5(*state_element);
    }
}

fn full_rounds(state: &mut PoseidonState, first: bool) {
    for i in 0..FULL_ROUNDS / 2 - 1 {
        exp5_state(state);
        if first {
            ark(state, (i + 1) * WIDTH);
        } else {
            ark(
                state,
                (FULL_ROUNDS / 2 + 1) * WIDTH + PARTIAL_ROUNDS + i * WIDTH,
            );
        }
        mix(state, &M_MATRIX);
    }

    exp5_state(state);
    if first {
        ark(state, (FULL_ROUNDS / 2) * WIDTH);
        mix(state, &P_MATRIX);
    } else {
        mix(state, &M_MATRIX);
    }
}

fn partial_rounds(state: &mut PoseidonState) {
    for i in 0..PARTIAL_ROUNDS {
        state[0] = exp5(state[0]);
        state[0].add_assign(&C_CONSTANTS[(FULL_ROUNDS / 2 + 1) * WIDTH + i]);

        let mut mul;
        let mut new_state0 = FrBn254::ZERO;
        for j in 0..WIDTH {
            mul = FrBn254::ZERO;
            mul.add_assign(&S_CONSTANTS[(WIDTH * 2 - 1) * i + j]);
            mul.mul_assign(&state[j]);
            new_state0.add_assign(&mul);
        }

        for k in 1..WIDTH {
            mul = FrBn254::ZERO;
            mul.add_assign(&state[0]);
            mul.mul_assign(&S_CONSTANTS[(WIDTH * 2 - 1) * i + WIDTH + k - 1]);
            state[k].add_assign(&mul);
        }

        state[0] = new_state0;
    }
}

fn mix(state: &mut PoseidonState, constant_matrix: &[Vec<FrBn254>]) {
    let mut result: PoseidonState = [FrBn254::ZERO; WIDTH];

    let mut mul;
    for (i, result_element) in result.iter_mut().enumerate().take(WIDTH) {
        for j in 0..WIDTH {
            mul = FrBn254::ZERO;
            mul.add_assign(&constant_matrix[j][i]);
            mul.mul_assign(&state[j]);
            result_element.add_assign(&mul);
        }
    }

    state[..WIDTH].copy_from_slice(&result[..WIDTH]);
}
