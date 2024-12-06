# How it Works

This document describes how the drand bridge pallet works.

## Overview

Drand's quicknet periodically outputs pulses of verifiable randomness every 3 seconds. There are various API's which provide access to the beacon, you can find the full list [here](https://drand.love/docs/http-api-reference), we've found that the best performing endpoint for us is `https://drand.cloudflare.com/`. This pallet runs an offchain worker, which executes each time a node imports a new (*not* finalized) block. 

### Assumptions and Limitations

1. Drand config isn't verified before storing it, any value with a valid format will be stored.
*After closing https://github.com/ideal-lab5/idn-sdk/issues/3, this limitation will be removed. Though it will required to trust at least one OCW*

2. Currently OCWs are at the will of the client’s “major sync oracle”, which means OCWs will not execute if the node is undergoing a “major sync” event. [ref]

3. It only supports Drand’s Quicknet, and so there is some trust placed in Drand that they will retain liveness and that the League of Entropy is not compromised. 

## Reading Pulses

The pallet attempts to read a fresh pulse of randomness from drand with each new block that is imported. We provide a 2 second window in which the OCW awaits a response from drand (this time must be less than the time allotted for block authorship). The OCW attempts to deserialize the response body to a struct. If valid, an unsigned transaction is constructed with the new struct being the payload. If possible the runtime then verifies the new pulse before adding it to storage.

<!-- TODO: update this image for unsigned txs https://github.com/ideal-lab5/idn-sdk/issues/10 -->
![](./drand_ocw.png)

## Storing Pulses

Pulses are stored in a storage map.

## Verifying Pulses

> Drand's Quicknet functions as a distributed, MPC protocol that produces and gossips threshold BLS signatures. In this flavor of drand, short signatures are used where the signature is in the $\mathbb{G}_1$ group and public keys are in $\mathbb{G}_2$. 

The default implementation of the `Verifier` trait is `pallet_drand::verifier::QuicknetVerifier::verify`. In this function, to verify pulses from drand, we check the equality of the pairings: $e(-sig, g2) == e(m, pk)$  where $m = H(message = Sha256(round))$, $sig$ is the round signature, $g_2$ is a generator of the $\mathbb{G}_2$ group, and $pk$ in the public key associated with the beacon.

<!-- TODO: improve this https://github.com/ideal-lab5/idn-sdk/issues/11 -->
**Offchain verification can be done using the [drand libs](https://github.com/drand)**