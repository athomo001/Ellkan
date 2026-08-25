// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NuevoExternalShare {
    pub created_by: Uuid,
    pub ciphertext: Vec<u8>,
    pub password_protected: bool,
    pub password_salt: Option<Vec<u8>>,
    pub max_views: i32,
    pub expires_at: OffsetDateTime,
}

/// Fila completa de `external_shares` — uso interno de
/// Repository/Service, nunca cruza tal cual a un DTO (`ciphertext` sólo se
/// expone en el único caso de acceso exitoso, vía `ResultadoAcceso::Ok`).
#[derive(Debug, Clone)]
pub struct FilaExternalShare {
    pub id: Uuid,
    pub created_by: Uuid,
    pub max_views: i32,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub burned_at: Option<OffsetDateTime>,
}

/// Resultado de dominio de `GET /external-shares/{id}` — el Controller
/// colapsa todo lo que no sea `Ok` a `404` (mismo criterio anti-enumeración
/// que el resto de la API: no hay forma de distinguir "no existe" de "ya
/// se quemó" de "expiró" desde afuera).
#[derive(Debug, Clone)]
pub enum ResultadoAcceso {
    Ok {
        ciphertext: Vec<u8>,
        password_protected: bool,
        password_salt: Option<Vec<u8>>,
        quemado_ahora: bool,
    },
    NoEncontrado,
    Revocado,
    Quemado,
    Expirado,
}

/// Fila de `GET /external-shares` (listado propio, F-26 UI de gestión) —
/// nunca incluye `ciphertext`: es sólo lo que el creador necesita para
/// decidir si revocar algo, no una forma alternativa de leer el contenido.
#[derive(Debug, Clone)]
pub struct FilaExternalShareResumen {
    pub id: Uuid,
    pub password_protected: bool,
    pub max_views: i32,
    pub view_count: i32,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub burned_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ExternalSharePolicy {
    pub enabled: bool,
    pub max_expiration_hours: i32,
    pub require_password: bool,
    /// A diferencia de `enabled`/`require_password`, estos dos NO son una
    /// barrera técnica real para `allow_file` — el archivo .7z se genera
    /// 100% client-side, nunca toca el servidor, así que no hay ningún
    /// request que rechazar. Es una política de qué botón ofrece la UI,
    /// documentado así en `ExternalShareService::crear` y en el frontend.
    pub allow_link: bool,
    pub allow_file: bool,
}
