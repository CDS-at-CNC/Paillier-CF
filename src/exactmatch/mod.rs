pub mod exactmatch;

pub use exactmatch::CfFst;
pub use exactmatch::CfSnd;
pub use exactmatch::SparseTable;
pub use exactmatch::FtBundle;
pub use exactmatch::AggResult;
pub use exactmatch::ExactMatchResult;
pub use exactmatch::HASH_BITS;
pub use exactmatch::TABLE_SIZE;
pub use exactmatch::simple_hash;
pub use exactmatch::find_email_column;
pub use exactmatch::load_ids_from_csv;
pub use exactmatch::phase0_keygen;
pub use exactmatch::phase1_build_table;
pub use exactmatch::phase2_prepare_ft;
pub use exactmatch::phase3_server_compute;
pub use exactmatch::phase4_decrypt_and_count;
pub use exactmatch::phase3_server_aggregate;
pub use exactmatch::phase4_decrypt_aggregate;

// ── Variante EXACT-MATCH (bucket + comparaison exacte) — en réserve, non utilisée ──
pub use exactmatch::BUCKET_BITS;
pub use exactmatch::BUCKET_DOMAIN;
pub use exactmatch::identity_value;
pub use exactmatch::BucketTable;
pub use exactmatch::EncBundle;
pub use exactmatch::phase1_build_bucket_table;
pub use exactmatch::phase2_prepare_enc_bundle;
pub use exactmatch::phase3_server_blind_diff;
pub use exactmatch::phase4_decrypt_exact_count;
