pub mod key_storage;
pub mod key_registry;

// Réexportations key_storage
pub use key_storage::{
    PublicKeyJson, SecretKeyJson, KeyPairJson,
    biguint_to_hex, hex_to_biguint,
    public_key_to_json, secret_key_to_json, keypair_to_json,
    json_to_public_key, json_to_secret_key, json_to_keypair,
    save_keypair_json, save_public_key_json, save_secret_key_json,
    load_keypair_json, load_public_key_json, load_secret_key_json,
    key_file_exists, ensure_keys_directory,
};

// Réexportations key_registry
pub use key_registry::{KeyRegistry, RegistryError};