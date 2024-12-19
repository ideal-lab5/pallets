use serde::{Serialize, Deserialize};
use prost::Message;

/// PublicRandResponse holds a signature which is the random value. It can be
/// verified thanks to the distributed public key of the nodes that have ran the
/// DKG protocol and is unbiasable. The randomness can be verified using the BLS
/// verification routine with the message "round || previous_rand".
#[derive(Clone, PartialEq, ::prost::Message, Serialize, Deserialize)]
pub struct PublicRandResponse {
    #[prost(uint64, tag = "1")]
    pub round: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub previous_signature: ::prost::alloc::vec::Vec<u8>,
    /// randomness is simply there to demonstrate - it is the hash of the
    /// signature. It should be computed locally.
    #[prost(bytes = "vec", tag = "4")]
    pub randomness: ::prost::alloc::vec::Vec<u8>,
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    pub fn test_can_decode_from_protobuf() {
        // the raw protobuf
        let raw: &[u8] = &[
            8, 162, 137, 211, 6, 18, 48, 185, 221, 218, 68, 77, 81, 100, 251, 137, 212, 193, 81,
            179, 17, 75, 63, 195, 103, 96, 229, 177, 201, 12, 230, 182, 121, 140, 64, 170, 48, 150,
            100, 132, 59, 67, 144, 149, 91, 25, 16, 249, 239, 30, 72, 80, 220, 75, 62, 34, 32, 205,
            97, 57, 139, 58, 167, 189, 197, 191, 34, 180, 150, 130, 10, 60, 41, 137, 196, 136, 119,
            10, 99, 96, 123, 168, 0, 11, 42, 10, 53, 198, 63,
        ];

        let res = crate::drand::PublicRandResponse::decode(raw);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.round, 13943970);

    }
}
