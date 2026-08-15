// Autor: Athan Espinoza

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_passphrase_length: i32,
    pub min_passphrase_entropy_bits: i32,
    pub passphrase_rotation_days: Option<i32>,
    pub generator_default_length: i32,
    pub generator_charset_rules: Value,
    pub max_clipboard_clear_minutes: Option<i32>,
    pub max_auto_lock_minutes: Option<i32>,
}
