// Autor: Athan Espinoza

//! F-47 C (pendiente #49): login con correo **o** nombre de usuario.
//!
//! Los pasos públicos del login (`prelogin`, `key-material`, `challenge`,
//! `verify`) reciben lo que la persona tipeó. Si no tiene `@`, se busca como
//! nombre de usuario y se traduce al correo para el resto del flujo, que no
//! cambia.
//!
//! **Nunca se le devuelve el correo a quien entró por nombre de usuario**
//! antes de autenticarse (sería un oráculo usuario → correo). En su lugar,
//! `prelogin` y `key-material` devuelven el `user_id`, que es el AAD de los
//! blobs nuevos de clave privada. Para un identificador sin cuenta, un id
//! falso estable (HKDF con la clave del servidor) con la misma forma que uno
//! real (UUIDv7), así la respuesta no dice si la cuenta existe.

use uuid::Uuid;

use crate::error::{DomainError, RepoError};
use ellkan_crypto::secretos::ClaveSecreta32;

/// Lo que el resto del login necesita saber del identificador tipeado.
pub struct Identificado {
    /// Correo con el que sigue el flujo (el tipeado si no hay cuenta).
    pub email: String,
    /// `true` si se entró por nombre de usuario: el correo no se devuelve.
    pub por_usuario: bool,
    /// Real si hay cuenta; si no, falso y estable.
    pub user_id: Uuid,
}

impl Identificado {
    /// El `email` que se puede devolver en una respuesta pública: el real
    /// sólo si es lo mismo que la persona tipeó (entró por correo).
    pub fn email_visible(&self, real: String, tipeado: &str) -> String {
        if self.por_usuario { tipeado.trim().to_lowercase() } else { real }
    }
}

/// Id falso estable para un identificador sin cuenta, con forma de UUIDv7
/// (marca de tiempo dentro del rango en que existen las cuentas reales).
fn id_falso(secrets_key: &ClaveSecreta32, identificador: &str) -> Uuid {
    use secrecy::ExposeSecret;
    let mut info = b"ellkan:v1:id-falso:".to_vec();
    info.extend_from_slice(identificador.trim().to_lowercase().as_bytes());
    let bloque = ellkan_crypto::derivacion::derivar_clave_desde_secreto(secrets_key.expose_secret(), &info);
    let b = bloque.expose_secret();
    // 2026-07-23 (primer commit) + hasta ~120 días: fijo, nunca depende de «ahora».
    const BASE_MS: u64 = 1_784_764_800_000;
    const RANGO_MS: u64 = 120 * 24 * 3_600_000;
    let ms = BASE_MS + u64::from_be_bytes(b[..8].try_into().expect("8 bytes")) % RANGO_MS;
    let mut aleatorio = [0u8; 10];
    aleatorio.copy_from_slice(&b[8..18]);
    uuid::Builder::from_unix_timestamp_millis(ms, &aleatorio).into_uuid()
}

pub async fn identificar(pool: &sqlx::PgPool, secrets_key: &ClaveSecreta32, identificador: &str) -> Result<Identificado, DomainError> {
    let limpio = identificador.trim();
    let por_usuario = !limpio.contains('@');
    let fila = if por_usuario {
        sqlx::query!(
            r#"select id, email from users
                where username = lower($1) and active and deleted_at is null and email_verified_at is not null"#,
            limpio
        )
        .fetch_optional(pool)
        .await
        .map(|f| f.map(|f| (f.id, f.email)))
    } else {
        sqlx::query!(
            r#"select id, email from users
                where lower(email) = lower($1) and active and deleted_at is null and email_verified_at is not null"#,
            limpio
        )
        .fetch_optional(pool)
        .await
        .map(|f| f.map(|f| (f.id, f.email)))
    }
    .map_err(|e| DomainError::Interno(RepoError::Database(e)))?;
    Ok(match fila {
        Some((id, email)) => Identificado { email, por_usuario, user_id: id },
        None => Identificado { email: limpio.to_string(), por_usuario, user_id: id_falso(secrets_key, limpio) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_id_falso_es_estable_y_parece_un_uuidv7() {
        let clave = ClaveSecreta32::new(Box::new([7u8; 32]));
        let a = id_falso(&clave, "Fantasma");
        assert_eq!(a, id_falso(&clave, "fantasma "), "estable e insensible a mayúsculas");
        assert_ne!(a, id_falso(&clave, "otro"));
        assert_eq!(a.get_version_num(), 7);
    }
}
