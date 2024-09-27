# pallet-randomness-beacon

This pallet bridges to a randomness beacon via a relayer. It constructs a **forkless** chain of verifiable randomness following NIST's proposed randomness beacon specification.

## How it works

The pallet starts at a genesis block (not necessarily network genesis). 
An untrusted relayer component interpolates signatures and pushes them to the beacon.
The beacon verifies the signature and encodes it into storage.
Assume it is using Sha512.
It does this in a way that builds a hash-chain, where each entry looks like:

https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8213-draft.pdf

```json
{
    "header": {
        "block_number": number,
        "hash(prev_sig)": string,
        "metadata": "todo",
    },
    "body": {
        "sig": string,
        "proof": string
    }
}
```

Where the metadata field is defined following the randomness beacon standard proposed by NIST. Thus, the metadata contains the following 21 fields:

When adding a new pulse:
1) get public keys in signature group from each batch PoK
2) 