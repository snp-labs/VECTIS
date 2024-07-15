# Batch ccSNARK

This is implementation of the batch ccSNARK protocol

## Directory Structure

| Directory            | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `src/`               | Contains the source code for the batch ccSNARK protocol        |
| ┣`crypto/`           | Contains the cryptographic primitives used in the protocol     |
| ┃┣`commitmemt/`      | Batch commitment scheme                                        |
| ┃┃┣`pedersen/`       | Pedersen commitment scheme                                     |
| ┃┃┃┣`constraints.rs` | Gadget for the Pedersen commitment                             |
| ┃┃┃┗`mod.rs`         | Implementation of the Pedersen commitment scheme               |
| ┃┃┣`constraints.rs`  | Trait of the batch commitment gadget                           |
| ┃┃┗`mod.rs`          | Trait of the batch commitment scheme                           |
| ┣`gro/`              | Implementation of the ccGrooth16 (LegoSNARK with Batch Commit) |
| ┣`solidity/`         | Implementation of useful utils to format data                  |

## ccGro16 with Public Inputs

$$
A \cdot B = \alpha \cdot \beta + C \cdot \delta + (PI + D) \cdot \gamma
$$

- All public inputs must be challenges

## Batch Commitment Scheme

### Steps

**Circuit**

- All the aggregated values must be at the front of the committed witness

**Prover**

1. Use `CCGroth16::<E>::commit` to commit the proof-dependent commitment
2. Use `Pedersen::<C>::batch_commit` to calculate the commitments
3. Use `Pedersen::<C>::challenge` to retrieve the challenge for aggregation.

**Verifier**

1. Use `Pedersen::<C>::challenge` to retrieve the challenge for aggregation.
2. Use `Pedersen::<C>::aggregate` to aggregate the commitments.
3. Update the proof-dependent commitment by adding the aggregation of the commitments.

```rust
// Aggregate inputs
let transposed = public_inputs.transpose();
let slices = cfg_iter!(transposed).map(|x| &x[..]).collect::<Vec<_>>();
let (aggregation_fr, initial) = Pedersen::<E::G1>::scalar_aggregate(&slices, tau, None);
// Aggregate commitments
let (aggregation_g1, _) = Pedersen::<C>::aggregate(&commitments, tau, Some(initial));
// Update proof dependent commitment
let aggregation = aggregation_g1 + vk.ck.batch_g1[0].into_group() * aggregation_fr[0];
proof.d = (proof.d.into_group() + aggregation).into_affine();
```
