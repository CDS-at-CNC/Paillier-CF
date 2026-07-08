pub mod net_protocol;

// Réexports à plat pour éviter le double préfixe net_protocol::net_protocol::*
// Les binaires (server.rs, client.rs) peuvent ainsi écrire :
//   use paillier_crypto::net_protocol::BandwidthMeter;
pub use net_protocol::{
    // Encodage BigUint / tuples
    encode_biguint, decode_biguint,
    encode_cffst, decode_cffst,
    encode_cfsnd, decode_cfsnd,
    // Framing socket
    send_msg, recv_msg,
    // Messages haut niveau
    MsgPubKey, MsgFtBundle, MsgDualBundle, MsgTriplets, MsgAgg, MsgPosValues,
    // Helpers instrumentés
    send_tracked, recv_tracked,
    // Mesure bande passante
    BandwidthMeter, PhaseMetric,
};