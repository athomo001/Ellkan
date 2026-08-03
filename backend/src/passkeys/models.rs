// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey as WebauthnPasskey;

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub passkey_data: WebauthnPasskey,
    pub prf_wrapped_private_key: Option<Vec<u8>>,
    pub last_used_at: Option<OffsetDateTime>,
}

/// Los dos tipos de ceremonia — se persisten en columnas separadas por
/// `(user_id, kind)`, nunca se mezclan entre sí.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoCeremonia {
    Registro,
    Autenticacion,
}

impl TipoCeremonia {
    pub fn as_db_str(self) -> &'static str {
        match self {
            TipoCeremonia::Registro => "register",
            TipoCeremonia::Autenticacion => "authenticate",
        }
    }
}
