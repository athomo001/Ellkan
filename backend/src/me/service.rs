// Autor: Athan Espinoza

//! Service de preferencias propias (F-30/F-31/F-39) — nunca importa `axum`.
//! `clipboard_clear_minutes`/`auto_lock_minutes` quedan acotados por el
//! techo opcional que un admin haya fijado en `password_policy`
//! (`max_clipboard_clear_minutes`/`max_auto_lock_minutes`, sección
//! `/me/preferences` de `03-api-contrato.md`) — un usuario puede pedir un
//! valor más laxo que el techo, pero nunca uno más permisivo que la
//! política de la organización.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::repository::{AuthChallengeRepository, UserRepository};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::password_policy::repository::PasswordPolicyRepository;

use super::models::{Avatar, NuevaClavePrivada, Perfil, Preferencias};
use super::repository::{AvatarRepository, ClavePrivadaRepository, PerfilRepository, PreferenciasRepository};

pub struct PreferenciasService<'a, P, Q> {
    pub preferencias: &'a P,
    pub password_policy: &'a Q,
}

impl<'a, P, Q> PreferenciasService<'a, P, Q>
where
    P: PreferenciasRepository,
    Q: PasswordPolicyRepository,
{
    pub async fn obtener(&self, user_id: Uuid) -> Result<Preferencias, DomainError> {
        Ok(self.preferencias.obtener(user_id).await?)
    }

    pub async fn actualizar(&self, user_id: Uuid, nueva: Preferencias) -> Result<Preferencias, DomainError> {
        if nueva.locale != "en" && nueva.locale != "es" {
            return Err(DomainError::ValidacionInvalida("locale debe ser 'en' o 'es'".into()));
        }
        if nueva.theme != "light" && nueva.theme != "dark" {
            return Err(DomainError::ValidacionInvalida("theme debe ser 'light' u 'oscuro'".into()));
        }
        if nueva.clipboard_clear_minutes < 0 {
            return Err(DomainError::ValidacionInvalida("clipboard_clear_minutes no puede ser negativo".into()));
        }
        if nueva.auto_lock_minutes.is_some_and(|m| m <= 0) {
            return Err(DomainError::ValidacionInvalida(
                "auto_lock_minutes debe ser positivo si se fija (null = sin auto-bloqueo)".into(),
            ));
        }

        let politica = self.password_policy.obtener().await?;
        if let Some(techo) = politica.max_clipboard_clear_minutes
            && nueva.clipboard_clear_minutes > techo
        {
            return Err(DomainError::ValidacionInvalida(format!(
                "clipboard_clear_minutes no puede superar el techo de la organización ({techo})"
            )));
        }
        if let Some(techo) = politica.max_auto_lock_minutes
            && nueva.auto_lock_minutes.is_none_or(|m| m > techo)
        {
            return Err(DomainError::ValidacionInvalida(format!(
                "auto_lock_minutes no puede superar el techo de la organización ({techo}), ni quedar sin fijar si el admin exige uno"
            )));
        }

        self.preferencias.actualizar(user_id, &nueva).await?;
        Ok(nueva)
    }
}

pub struct PerfilService<'a, R> {
    pub perfil: &'a R,
}

impl<'a, R> PerfilService<'a, R>
where
    R: PerfilRepository,
{
    pub async fn obtener(&self, user_id: Uuid) -> Result<Perfil, DomainError> {
        Ok(self.perfil.obtener(user_id).await?)
    }

    /// Pendiente #133: primer par de claves de una cuenta creada por SSO.
    /// 409 si la cuenta ya tiene claves.
    ///
    /// ELK-01 (#147, a2): además de una sesión válida exige que la haya
    /// emitido el callback SSO hace menos de `MINUTOS_SESION_SSO_PARA_ENROLAR`.
    /// Una sesión obtenida por cualquier otro camino (p. ej. una firma contra
    /// una clave de relleno, el ataque original) no alcanza.
    pub async fn enrolar_claves(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        claves: &super::models::ClavesIniciales,
        eventos: &EmisorDeEventos,
    ) -> Result<(), DomainError> {
        if !self.perfil.sesion_sso_reciente(session_id, user_id, MINUTOS_SESION_SSO_PARA_ENROLAR).await? {
            return Err(DomainError::PermissionDenied);
        }
        if !self.perfil.enrolar_claves(user_id, claves).await? {
            return Err(DomainError::Conflict);
        }
        let _ = eventos.send(DomainEvent::Auditoria(EventoAuditoria::nuevo(AuditEventType::UserKeysEnrolled, Some(user_id))));
        Ok(())
    }
}

/// ELK-01 (#147, a2): ventana para enrolar tras el login SSO. Alcanza para
/// configurar el segundo factor si la política lo pide; si se pasa, se vuelve
/// a entrar por SSO.
pub const MINUTOS_SESION_SSO_PARA_ENROLAR: i32 = 30;

/// Formatos aceptados para el avatar — mismo criterio que cualquier otra
/// validación de la app (rechazo explícito, nunca silencioso).
const CONTENT_TYPES_AVATAR: &[&str] = &["image/png", "image/jpeg", "image/webp"];
/// 2 MB decodificados — no hay redimensionado server-side, el límite sólo
/// evita blobs desproporcionados (una foto de cámara moderna sin comprimir
/// entra holgada).
const AVATAR_MAX_BYTES: usize = 2 * 1024 * 1024;

pub struct AvatarService<'a, R> {
    pub avatar: &'a R,
}

impl<'a, R> AvatarService<'a, R>
where
    R: AvatarRepository,
{
    pub async fn obtener(&self, user_id: Uuid) -> Result<Option<Avatar>, DomainError> {
        Ok(self.avatar.obtener(user_id).await?)
    }

    pub async fn actualizar(&self, user_id: Uuid, avatar: Avatar) -> Result<(), DomainError> {
        if !CONTENT_TYPES_AVATAR.contains(&avatar.content_type.as_str()) {
            return Err(DomainError::ValidacionInvalida(format!("content_type debe ser uno de {CONTENT_TYPES_AVATAR:?}")));
        }
        if avatar.bytes.is_empty() || avatar.bytes.len() > AVATAR_MAX_BYTES {
            return Err(DomainError::ValidacionInvalida(format!(
                "el avatar debe pesar entre 1 byte y {AVATAR_MAX_BYTES} bytes"
            )));
        }
        self.avatar.actualizar(user_id, &avatar).await?;
        Ok(())
    }

    pub async fn eliminar(&self, user_id: Uuid) -> Result<(), DomainError> {
        Ok(self.avatar.eliminar(user_id).await?)
    }
}

/// Tamaños fijos por el propio esquema criptográfico (`clave_privada.rs`/
/// `aead.rs`) — no se valida acá "es una clave privada real" (el servidor
/// nunca puede saberlo, es zero-knowledge), sólo que las longitudes tengan
/// sentido antes de escribir en `user_keys`.
const NONCE_LEN: usize = 24;
const KDF_SALT_LEN: usize = 16;
const BLOB_LEN_MIN: usize = 16;
const BLOB_LEN_MAX: usize = 1024;

/// QA-06: lo que el cliente manda para probar que tiene la identidad de la
/// cuenta al reemplazar el blob sellado.
pub struct PruebaDePosesion {
    /// Nonce emitido por `POST /auth/challenge` para esta cuenta.
    pub challenge: Vec<u8>,
    /// Firma Ed25519 de `mensaje_reemplazo_clave_privada(challenge, blob…)`.
    pub firma: Vec<u8>,
}

/// QA-06: blob nuevo cuya prueba de posesión ya se verificó para `user_id`.
/// Sólo lo construye `verificar_posesion`, y es lo único que acepta
/// `CambiarPassphraseService::actualizar`: ningún camino puede reemplazar la
/// clave privada sellada sin pasar por la verificación.
pub struct ReemplazoVerificado {
    user_id: Uuid,
    nueva: NuevaClavePrivada,
}

impl ReemplazoVerificado {
    /// Para los repositorios que no implementan `ClavePrivadaRepository`
    /// (la bóveda local del escritorio). Construirlo sigue exigiendo pasar
    /// por `verificar_posesion`.
    pub fn en_partes(self) -> (Uuid, NuevaClavePrivada) {
        (self.user_id, self.nueva)
    }
}

/// QA-06: valida las longitudes, consume el challenge (un solo uso, con TTL)
/// y verifica la firma con `user_keys.public_key_ed25519`. Cualquier fallo
/// de la prueba devuelve el mismo 403, sin distinguir cuál fue.
pub async fn verificar_posesion<U, C>(
    usuarios: &U,
    challenges: &C,
    user_id: Uuid,
    nueva: NuevaClavePrivada,
    prueba: &PruebaDePosesion,
) -> Result<ReemplazoVerificado, DomainError>
where
    U: UserRepository,
    C: AuthChallengeRepository,
{
    validar_nueva_clave_privada(&nueva)?;
    if !challenges.consumir_challenge(user_id, &prueba.challenge).await? {
        return Err(DomainError::PermissionDenied);
    }
    let keys = usuarios.buscar_keys(user_id).await?.ok_or(DomainError::PermissionDenied)?;
    let valida = ellkan_crypto::clave_privada::verificar_reemplazo_clave_privada(
        &keys.public_key_ed25519,
        &prueba.firma,
        &prueba.challenge,
        &ellkan_crypto::clave_privada::Reemplazo {
            blob: &nueva.encrypted_private_key_blob,
            nonce: &nueva.private_key_nonce,
            salt: &nueva.kdf_salt,
            parametros: &nueva.kdf_params,
            auth_key: &nueva.auth_key,
        },
    );
    if !valida {
        return Err(DomainError::PermissionDenied);
    }
    Ok(ReemplazoVerificado { user_id, nueva })
}

pub struct CambiarPassphraseService<'a, R> {
    pub claves: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<'a, R> CambiarPassphraseService<'a, R>
where
    R: ClavePrivadaRepository,
{
    pub async fn actualizar(&self, verificado: ReemplazoVerificado) -> Result<(), DomainError> {
        let ReemplazoVerificado { user_id, nueva } = verificado;

        self.claves.actualizar(user_id, &nueva).await?;

        let _ = self
            .eventos
            .send(DomainEvent::Auditoria(EventoAuditoria::nuevo(AuditEventType::PassphraseChanged, Some(user_id))));

        Ok(())
    }

    /// QA-03: ver `me::handlers::mejorar_kdf`. `Conflict` si la cuenta ya
    /// tiene verificador: la mejora es de una sola vez, no un cambio de
    /// passphrase que se saltea el cierre de sesiones.
    pub async fn mejorar_kdf(&self, verificado: ReemplazoVerificado) -> Result<(), DomainError> {
        let ReemplazoVerificado { user_id, nueva } = verificado;
        if !self.claves.mejorar_sello_legado(user_id, &nueva).await? {
            return Err(DomainError::Conflict);
        }
        Ok(())
    }
}

/// Validación de longitudes del blob nuevo; corre dentro de
/// `verificar_posesion`, antes de consumir nada.
fn validar_nueva_clave_privada(nueva: &NuevaClavePrivada) -> Result<(), DomainError> {
    if !nueva.kdf_params.aceptables_para_sellar() {
        return Err(DomainError::ValidacionInvalida("kdf_params por debajo del mínimo o fuera de rango".into()));
    }
    if nueva.auth_key.len() != crate::validacion::LARGO_AUTH_KEY {
        return Err(DomainError::ValidacionInvalida("auth_key debe medir 32 bytes".into()));
    }
    if nueva.private_key_nonce.len() != NONCE_LEN {
        return Err(DomainError::ValidacionInvalida(format!("private_key_nonce debe tener {NONCE_LEN} bytes")));
    }
    if nueva.kdf_salt.len() != KDF_SALT_LEN {
        return Err(DomainError::ValidacionInvalida(format!("kdf_salt debe tener {KDF_SALT_LEN} bytes")));
    }
    if !(BLOB_LEN_MIN..=BLOB_LEN_MAX).contains(&nueva.encrypted_private_key_blob.len()) {
        return Err(DomainError::ValidacionInvalida(format!(
            "encrypted_private_key_blob debe medir entre {BLOB_LEN_MIN} y {BLOB_LEN_MAX} bytes"
        )));
    }
    Ok(())
}
