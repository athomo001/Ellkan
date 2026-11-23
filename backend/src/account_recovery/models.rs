// Autor: Athan Espinoza

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AccountRecoveryPolicy {
    pub required: bool,
    pub grace_period_days: i32,
    pub default_approval_threshold: i32,
}

/// QA-09: quién guarda la privada de una clave organizacional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custodia {
    /// Anterior a QA-09: cifrada con `ELLKAN_SECRETS_KEY`. Sólo sigue
    /// sirviendo a los escrows que todavía no se re-sellaron.
    Servidor,
    /// Generada en el navegador de un admin y sellada para cada custodio
    /// (`org_recovery_key_envelopes`): el servidor no puede abrirla.
    Cliente,
}

impl Custodia {
    pub fn as_str(self) -> &'static str {
        match self {
            Custodia::Servidor => "server",
            Custodia::Cliente => "client",
        }
    }

    pub fn desde_db(valor: &str) -> Self {
        if valor == "client" { Custodia::Cliente } else { Custodia::Servidor }
    }
}

#[derive(Debug, Clone)]
pub struct OrgRecoveryKey {
    pub id: i32,
    pub public_key_x25519: Vec<u8>,
    /// Sólo en una clave del servidor no purgada.
    pub encrypted_private_key: Option<Vec<u8>>,
    pub private_key_nonce: Option<Vec<u8>>,
    pub custodia: Custodia,
    pub created_at: OffsetDateTime,
}

/// Un admin de organización con claves que todavía no tiene su copia de la
/// privada vigente.
#[derive(Debug, Clone)]
pub struct CustodioPendiente {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub public_key_x25519: Vec<u8>,
}

/// Lo que necesita el navegador de un custodio para re-sellar una solicitud
/// que ya juntó el umbral.
#[derive(Debug, Clone)]
pub struct MaterialParaCustodio {
    pub sealed_private_key_for_org: Vec<u8>,
    pub requester_public_key_x25519: Vec<u8>,
    pub org_recovery_key_id: i32,
    pub sobre: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Escrow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub sealed_private_key_for_org: Vec<u8>,
    pub org_recovery_key_id: i32,
    pub approval_threshold: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub id: Uuid,
    pub escrow_id: Uuid,
    pub requested_by: Option<Uuid>,
    pub status: String,
    pub approvals: Value,
    pub requester_public_key_x25519: Vec<u8>,
    pub sealed_private_key_for_requester: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
    /// Hash SHA-256 del código enviado al email de la cuenta (sólo mientras
    /// la solicitud está `unconfirmed`).
    pub confirmation_code_hash: Option<Vec<u8>>,
    /// Hash SHA-256 del token que recibe el solicitante al confirmar.
    pub requester_token_hash: Option<Vec<u8>>,
    pub expires_at: OffsetDateTime,
}

impl RecoveryRequest {
    pub fn vencida(&self) -> bool {
        self.expires_at <= OffsetDateTime::now_utc()
    }
}

/// Sólo para `GET /admin/account-recovery/requests` — el admin no tiene
/// forma de descubrir un `request_id` de otro modo (el id sólo lo conoce
/// quien creó la solicitud), así que esta vista trae el email objetivo.
#[derive(Debug, Clone)]
pub struct SolicitudPendiente {
    pub id: Uuid,
    pub target_email: String,
    pub status: String,
    pub approvals: Value,
    pub approval_threshold: i32,
    pub created_at: OffsetDateTime,
}
