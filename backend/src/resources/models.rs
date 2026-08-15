// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Resource {
    pub id: Uuid,
    pub resource_type_id: Uuid,
    pub metadata_ciphertext: Vec<u8>,
    pub metadata_nonce: Vec<u8>,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    /// F-30/F-07: expuesto en `RecursoResponse` para el refresco inteligente
    /// por foco de pestaña (`huboCambios`) y como valor de `If-Match` al
    /// editar (F-07, concurrencia optimista).
    pub updated_at: OffsetDateTime,
    /// `user_key` (default, F-05/F-06 básico) | `shared_key` (F-06
    /// completo) — los dos tipos son compartibles (F-11/2026-08-11), sólo
    /// cambia qué clave envuelve la metadata.
    pub metadata_key_type: String,
    pub metadata_key_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct SecretEnvelope {
    pub sealed_dek: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}

/// F-07: destinatario actual de un recurso (tiene su propio
/// `secret_envelope`) — lo que el cliente necesita para re-sellar la DEK
/// nueva al editar, sin que el servidor toque nada en claro.
#[derive(Debug, Clone)]
pub struct Destinatario {
    pub user_id: Uuid,
    pub public_key_x25519: Vec<u8>,
}

/// Envelope ya sellado client-side para un destinatario — input de
/// `ResourceRepository::actualizar` (F-07).
#[derive(Debug, Clone)]
pub struct EnvelopeInput {
    pub user_id: Uuid,
    pub sealed_dek: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}

/// Hallazgo real de uso 2026-08-10: no había forma de ver ni administrar
/// quién tiene acceso a un recurso más allá de agregar un destinatario
/// nuevo — `GET/{DELETE,PUT} /resources/{id}/permissions*` lo cubre.
#[derive(Debug, Clone)]
pub struct PermisoGrantee {
    pub grantee_type: String,
    pub grantee_id: Uuid,
    pub level: String,
    /// Email (usuario) o nombre (grupo) — sólo para mostrar en la UI, nunca
    /// dato sensible: los nombres de grupo son texto plano (organizacional,
    /// no zero-knowledge) y el email de un usuario ya es público dentro de
    /// la org (se usa para buscar destinatarios al compartir).
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NivelPermiso {
    Read,
    Update,
    Owner,
}

impl NivelPermiso {
    pub fn as_db_str(self) -> &'static str {
        match self {
            NivelPermiso::Read => "read",
            NivelPermiso::Update => "update",
            NivelPermiso::Owner => "owner",
        }
    }
}
