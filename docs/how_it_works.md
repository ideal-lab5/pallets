# How it Works

## Overview
* note: the offchain worker triggers on every block import,regardless of finality....

Drand's quicknet periodically outputs pulses of verifiable randomness every 3 seconds. There are various API's which provide access to the beacon, with this pallet simply using the main `api.drand.sh` URI.

### Assumption and Limitations

## Reading Pulses

## Storing Pulses

## Verifying Pulses

To verify pulses from drand, we check the equality: 

$e(-sig, g2) == e(m, pk)$ 

where $m = H(message = Sha256(round))$
