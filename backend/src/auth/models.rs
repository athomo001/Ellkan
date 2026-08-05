// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub security_stamp: Uuid,
    /// F-14: determina si un usuario ya existía cuando la política de MFA
    /// se activó (elegible para el período de gracia) o se registró después
    /// (sin gracia, configura MFA en el propio flujo de alta).
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct UserKeysRow {
    pub public_key_x25519: Vec<u8>,
    pub public_key_ed25519: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NuevoUsuario<'a> {
    pub email: &'a str,
    pub display_name: &'a str,
    pub public_key_x25519: &'a [u8],
    pub public_key_ed25519: &'a [u8],
    pub encrypted_private_key_blob: &'a [u8],
    pub private_key_nonce: &'a [u8],
    pub kdf_salt: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
}

/// Resultado de `AuthService::verify` — puede resolver en sesión completa,
/// un desafío de dispositivo pendiente (F-02), o (una vez el dispositivo ya
/// es conocido) el estado de MFA que corresponda (F-14): verificar un
/// código contra un desafío ya emitido, o configurar un segundo factor por
/// primera vez si la política lo exige y todavía no existe ninguno.
#[derive(Debug, Clone)]
pub enum ResultadoVerify {
    SesionCompleta(Session),
    PendienteDispositivo { device_challenge_id: Uuid },
    PendienteMfa { session_id: Uuid },
    RequiereConfigurarMfa { session_id: Uuid },
}

/// Fila de `device_challenges` pendiente — el service compara `code_hash` en
/// tiempo constante (nunca en SQL) y usa el resto para dar de alta el
/// dispositivo y emitir la sesión.
#[derive(Debug, Clone)]
pub struct DeviceChallengeRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_token_hash: Vec<u8>,
    pub code_hash: Vec<u8>,
}
