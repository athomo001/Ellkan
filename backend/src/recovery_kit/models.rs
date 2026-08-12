// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

/// `sealed_identity_material` = `sellar_bytes(kit_public_key, x25519_priv || ed25519_priv)`
/// — mismo convenio de 64 bytes que `account_recovery::Escrow`, sellado
/// contra la pública del kit en vez de contra la pública organizacional.
/// Opaco para el servidor: sin la privada del kit (que nunca lo toca), estos
/// bytes no sirven de nada.
#[derive(Debug, Clone)]
pub struct RecoveryKit {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kit_public_key_x25519: Vec<u8>,
    pub sealed_identity_material: Vec<u8>,
    /// `true` tras un reset exitoso vía este kit — el kit ya se usó/expuso,
    /// se fuerza reemplazo en el próximo login (`GET /me/recovery-kit`).
    pub must_rotate: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetodoMfa {
    Totp,
    Email,
}

impl MetodoMfa {
    pub fn as_str(self) -> &'static str {
        match self {
            MetodoMfa::Totp => "totp",
            MetodoMfa::Email => "email",
        }
    }
}

/// Fila de `recovery_reset_tokens` — `token_hash` se compara en tiempo
/// constante (`secreto_coincide`), nunca vía igualdad de SQL directa sobre
/// un valor recibido del cliente.
#[derive(Debug, Clone)]
pub struct ResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub email_code_hash: Option<Vec<u8>>,
    pub email_code_expires_at: Option<OffsetDateTime>,
}
