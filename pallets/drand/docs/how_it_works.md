# How it Works

This document describes how the drand bridge pallet works.

## Overview

Drand's quicknet periodically outputs pulses of verifiable randomness every 3 seconds. There are various API's which provide access to the beacon, with this pallet simply using the main `https://drand.cloudflare.com` URI. This pallet runs an offchain worker, which executes each time a node imports a new (*not* finalized) block. 

### Assumption and Limitations

1. Verifiying pulses is only possible for solochains. As the verification function requires the arkworks host functions to be added to the node service, which is not currently the case for the Polkadot node.
The `pallet_drand::QuicknetVerifier::verify` function, used to verify the drand randomness, depends on arkworks and is far more performant when run natively than in wasm. Without this native support, the validators would take too long to run this verification in the PVF and likely discard the blocks that contain drand pulses.

2. Drand config isn't verified before storing it, any value with a valid format will be stored.

3. Because of the two previous limitations (the first one only affecting parachains), the pallet is not secure.
*After closing https://github.com/ideal-lab5/pallet-drand/issues/3, this limitation will be removed. Though it will required to trust at least one OCW*

3. Currently OCWs are at the will of the client’s “major sync oracle”, which means OCWs will not execute if the node is undergoing a “major sync” event. [ref]

4. It only supports drand’s quicknet, and so there is some trust placed in drand that they will retain liveness and that the league of entropy is not compromised. 

## Reading Pulses

The pallet attempts to read a fresh pulse of randomness from drand with each new block that is imported. We provide a 2 second window in which the OCW awaits a response from drand (this time must be less than the time allotted for block authorship). The OCW attempts to deserialize the response body to a struct. If valid, an unsigned transaction is constructed with the new struct being the payload. If possible the runtime then verifies the new pulse before adding it to storage.

<!-- TODO: update this image for unsigned txs https://github.com/ideal-lab5/pallet-drand/issues/10 -->
![](./drand_ocw.png)

## Storing Pulses

Pulses are stored in a storage map.

## Verifying Pulses

> Drand's Quicknet functions as a distributed, MPC protocol that produces and gossips threshold BLS signatures. In this flavor of drand, short signatures are used where the signature is in the $\mathbb{G}_1$ group and public keys are in $\mathbb{G}_2$. 

The default implementation of the `Verifier` trait is `pallet_drand::QuicknetVerifier::verify`. In this function, to verify pulses from drand, we check the equality of the pairings: $e(-sig, g2) == e(m, pk)$  where $m = H(message = Sha256(round))$, $sig$ is the round signature, $g_2$ is a generator of the $\mathbb{G}_2$ group, and $pk$ in the public key associated with the beacon.

<!-- TODO: improve this https://github.com/ideal-lab5/pallet-drand/issues/11 -->
**NOTE: this verification is only avaliable onchain for solochains (see [Assumptions and Limitations](#assumption-and-limitations)). Offchain verification can be done using the [drand libs](https://github.com/drand)**