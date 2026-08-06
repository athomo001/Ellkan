// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct MfaPolicy {
    pub require_mfa: bool,
    pub allowed_methods: Vec<String>,
    pub grace_period_days: i32,
    pub require_mfa_since: Option<OffsetDateTime>,
}

/// Credential TOTP de login (F-14) — distinto del TOTP local de F-38 (nunca
/// toca el servidor) y del embebido de F-08 (contenido cifrado end-to-end).
/// `secret_ciphertext`/`secret_nonce` están cifrados con la clave maestra de
/// servidor (`AppState.secrets_key`), nunca con una clave del usuario.
#[derive(Debug, Clone)]
pub struct TotpCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
    pub confirmed_at: Option<OffsetDateTime>,
}

/// Fila de `mfa_challenges` pendiente — `session_hash` se compara en tiempo
/// constante en Rust (`secreto_coincide`), nunca vía igualdad de SQL.
#[derive(Debug, Clone)]
pub struct MfaChallengeRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_hash: Vec<u8>,
}

/// Resultado de evaluar la política de MFA para un login (F-14) — decidido
/// después de que F-02 (dispositivo conocido) ya se resolvió.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionMfa {
    /// La política no exige MFA, o el usuario está dentro del período de
    /// gracia — la sesión se emite completa de inmediato.
    NoRequerido,
    /// El usuario ya tiene un credential TOTP confirmado — se emite un
    /// desafío y la sesión queda parcial hasta verificarlo.
    DebeVerificar,
    /// La política exige MFA y el usuario no tiene ningún credential
    /// confirmado (usuario nuevo, o gracia vencida) — la sesión queda
    /// parcial sin desafío todavía; el propio cliente debe configurar un
    /// segundo factor antes de poder operar.
    DebeConfigurar,
}
