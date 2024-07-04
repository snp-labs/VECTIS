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

## Batch Commitment Gadget

- All the aggregated values must be at the front of the committed witness

### Steps

**Prover**

1. Use `Pedersen::<C>::batch_commit` to calculate the commitments and the proof-dependent commitment.
2. Use `Pedersen::<C>::challenge` to retrieve the challenge for aggregation.

**Verifier**

1. Use `Pedersen::<C>::challenge` to retrieve the challenge for aggregation.
2. Use `Pedersen::<C>::aggregate` to aggregate the commitments.
3. Update the proof-dependent commitment by adding the aggregation of the commitments.

```rust
// Aggregate commitments
let aggregation = Pedersen::<C>::aggregate(&commitments, tau);
// Update proof dependent commitment
proof.d = (proof.d.into_group() + aggregation.into_group()).into_affine();
```
