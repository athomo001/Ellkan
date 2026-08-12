// Autor: Athan Espinoza

//! Service de MFA (F-14/F-34) — nunca importa `axum`. El secreto TOTP de
//! login vive cifrado en la base con la clave maestra de servidor
//! (`AppState.secrets_key`), nunca con una clave del usuario — a diferencia
//! del resto del vault, este servidor sí necesita poder leerlo para
//! verificar el código.

use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::comparacion::secreto_coincide;
use ellkan_crypto::secretos::ClaveSecreta32;
use ellkan_crypto::totp;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::repository::{KnownDeviceRepository, SessionRepository};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{DecisionMfa, MfaPolicy, TotpCredential};
use super::repository::{MfaChallengeRepository, MfaPolicyRepository, TotpCredentialRepository};

/// TTL de un desafío MFA recién emitido — reutilizada por `auth::service` al
/// crearlo (F-02 ya resuelto, F-14 recién empieza) y acá al validarlo.
pub const TTL_CHALLENGE_SEGUNDOS: i64 = 300;

/// SHA-256 del `sessions.id` que originó el desafío — nunca el ID en claro
/// (F-34). Compartido entre `AuthService` (al emitir) y `MfaService` (al
/// verificar) para que ambos lados calculen exactamente el mismo hash.
pub fn hash_de_sesion(session_id: Uuid) -> Vec<u8> {
    Sha256::digest(session_id.as_bytes()).to_vec()
}

/// Decide qué le corresponde a un login ya pasado F-02 (dispositivo
/// conocido) — función pura, sin I/O, para poder testearla sin Postgres.
pub fn decidir(politica: &MfaPolicy, tiene_confirmado: bool, user_created_at: OffsetDateTime) -> DecisionMfa {
    if !politica.require_mfa {
        return DecisionMfa::NoRequerido;
    }
    // Método `email` (2026-08-11): no hay nada que "configurar" — el email
    // ya está verificado desde F-24, cada login pendiente manda un código
    // nuevo. Nunca `DebeConfigurar`, el período de gracia tampoco aplica
    // (no depende de ningún credential previo).
    if politica.allowed_methods.first().map(String::as_str) == Some("email") {
        return DecisionMfa::DebeVerificar;
    }
    if tiene_confirmado {
        return DecisionMfa::DebeVerificar;
    }

    // Sin credential confirmado: ¿todavía está en el período de gracia?
    // Un usuario que se registró después de que la política ya estaba
    // activa no tiene gracia (F-14) — sólo aplica a quien ya existía al
    // momento de la activación.
    match politica.require_mfa_since {
        Some(desde) if user_created_at < desde => {
            let vence = desde + time::Duration::days(politica.grace_period_days as i64);
            if OffsetDateTime::now_utc() < vence {
                DecisionMfa::NoRequerido
            } else {
                DecisionMfa::DebeConfigurar
            }
        }
        _ => DecisionMfa::DebeConfigurar,
    }
}

/// `pub(crate)`: `recovery_kit::service` también necesita descifrar el
/// secreto TOTP para verificarlo durante un reset por kit (sin sesión ni
/// desafío de por medio, a diferencia del resto de este módulo) — único
/// motivo por el que esto deja de ser privado.
pub(crate) fn descifrar_secreto(clave: &ClaveSecreta32, credential: &TotpCredential) -> Result<Vec<u8>, DomainError> {
    // El nonce siempre tiene 24 bytes: la única fuente de esta columna es
    // `aead::cifrar` en `iniciar_setup_totp`, nunca un valor externo — un
    // largo distinto sería un bug de escritura, no una entrada inválida.
    let nonce: [u8; 24] = credential
        .secret_nonce
        .clone()
        .try_into()
        .expect("secret_nonce siempre tiene 24 bytes, escrito sólo por iniciar_setup_totp");
    let envoltura = Envoltura { nonce, ciphertext: credential.secret_ciphertext.clone() };
    aead::descifrar(clave, &envoltura, credential.user_id.as_bytes())
        .map_err(|_| DomainError::InvalidCredentials)
}

pub struct MfaService<'a, P, T, C, S, D> {
    pub policy: &'a P,
    pub totp: &'a T,
    pub challenges: &'a C,
    pub sesiones: &'a S,
    pub dispositivos: &'a D,
    pub secrets_key: &'a ClaveSecreta32,
    pub eventos: EmisorDeEventos,
}

impl<'a, P, T, C, S, D> MfaService<'a, P, T, C, S, D>
where
    P: MfaPolicyRepository,
    T: TotpCredentialRepository,
    C: MfaChallengeRepository,
    S: SessionRepository,
    D: KnownDeviceRepository,
{
    pub async fn obtener_politica(&self) -> Result<MfaPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    /// `PUT /admin/mfa-policy` — F-14. `allowed_methods` admite `totp` y
    /// `email` (2026-08-11) — nunca los dos juntos: el admin elige UN método
    /// activo (o ninguno), no una lista de opciones entre las que el usuario
    /// elige en el login. `webauthn` sigue declarado en el modelo de datos
    /// para más adelante, pero `POST /auth/mfa/verify` todavía no tiene un
    /// branch que lo verifique, así que aceptarlo acá dejaría a un usuario
    /// sin ningún camino real para completar el login.
    pub async fn actualizar_politica(
        &self,
        actor_id: Uuid,
        require_mfa: bool,
        allowed_methods: Vec<String>,
        grace_period_days: i32,
    ) -> Result<MfaPolicy, DomainError> {
        if allowed_methods.iter().any(|m| m != "totp" && m != "email") {
            return Err(DomainError::ValidacionInvalida(
                "allowed_methods sólo admite 'totp' o 'email' — 'webauthn' como segundo factor todavía no está implementado".into(),
            ));
        }
        if allowed_methods.len() > 1 {
            return Err(DomainError::ValidacionInvalida(
                "allowed_methods admite un único método activo a la vez".into(),
            ));
        }
        if grace_period_days < 0 {
            return Err(DomainError::ValidacionInvalida("grace_period_days no puede ser negativo".into()));
        }

        let actual = self.policy.obtener().await?;
        let require_mfa_since = match (actual.require_mfa, require_mfa) {
            (false, true) => Some(OffsetDateTime::now_utc()),
            (true, false) => None,
            _ => actual.require_mfa_since,
        };

        let nueva = MfaPolicy { require_mfa, allowed_methods, grace_period_days, require_mfa_since };
        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::MfaPolicyUpdated, Some(actor_id)).con_metadata(serde_json::json!({
                "require_mfa": nueva.require_mfa,
                "allowed_methods": nueva.allowed_methods,
                "grace_period_days": nueva.grace_period_days,
            })),
        ));

        Ok(nueva)
    }

    /// `POST /me/mfa/totp/setup` — genera un secreto nuevo y lo guarda sin
    /// confirmar. Devuelve el secreto en claro **una sola vez** (para el QR);
    /// nunca vuelve a exponerse tras esta llamada.
    pub async fn iniciar_setup_totp(&self, user_id: Uuid) -> Result<[u8; ellkan_crypto::totp::SECRETO_LEN], DomainError> {
        self.totp.limpiar_pendientes(user_id).await?;

        let secreto = totp::generar_secreto_totp();
        // XChaCha20-Poly1305 cifrando (no descifrando) no tiene ningún caso
        // de error real — el `Result` de `cifrar` existe por simetría con
        // `descifrar`, que sí puede fallar por tag inválido.
        let envoltura = aead::cifrar(self.secrets_key, &secreto, user_id.as_bytes())
            .expect("cifrar con XChaCha20-Poly1305 no falla");

        self.totp
            .crear_pendiente(user_id, &envoltura.ciphertext, &envoltura.nonce)
            .await?;

        Ok(secreto)
    }

    /// `POST /me/mfa/totp/confirm` — cierra el setup con el primer código
    /// válido. Si `session_id_actual` corresponde a una sesión parcial
    /// todavía sin verificar (flujo "configura tu MFA ahora"), también la
    /// marca completa: confirmar el TOTP nuevo *es* la prueba del segundo
    /// factor para esa sesión concreta.
    pub async fn confirmar_setup_totp(
        &self,
        user_id: Uuid,
        codigo: u32,
        session_id_actual: Uuid,
        device_token_hash: Option<&[u8]>,
    ) -> Result<(), DomainError> {
        let pendiente = self.totp.buscar_pendiente(user_id).await?.ok_or(DomainError::NotFound)?;
        let mut secreto = descifrar_secreto(self.secrets_key, &pendiente)?;

        let ahora = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let valido = totp::verificar_totp(&secreto, codigo, ahora);
        secreto.zeroize();
        if !valido {
            return Err(DomainError::InvalidCredentials);
        }

        self.totp.revocar_confirmados_de(user_id).await?;
        self.totp.confirmar(pendiente.id).await?;
        self.sesiones.marcar_mfa_verificada(session_id_actual).await?;
        if let Some(hash) = device_token_hash {
            self.dispositivos.marcar_mfa_confirmado(user_id, hash).await?;
        }

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::MfaEnrolled, Some(user_id)).con_sujeto("user", user_id),
        ));

        Ok(())
    }

    /// `POST /auth/mfa/verify` — F-14/F-34. Busca, entre los desafíos
    /// pendientes del usuario, el que corresponde a `session_id_actual`
    /// (comparación en tiempo constante), y sólo entonces valida el código.
    pub async fn verificar_login(
        &self,
        user_id: Uuid,
        session_id_actual: Uuid,
        codigo: u32,
        device_token_hash: Option<&[u8]>,
    ) -> Result<(), DomainError> {
        let resultado = self.verificar_login_interno(user_id, session_id_actual, codigo, device_token_hash).await;

        if resultado.is_err() {
            let _ = self.eventos.send(DomainEvent::Auditoria(EventoAuditoria::nuevo(
                AuditEventType::AuthMfaFailed,
                Some(user_id),
            )));
        }

        resultado
    }

    async fn verificar_login_interno(
        &self,
        user_id: Uuid,
        session_id_actual: Uuid,
        codigo: u32,
        device_token_hash: Option<&[u8]>,
    ) -> Result<(), DomainError> {
        let hash_actual = hash_de_sesion(session_id_actual);
        let pendientes = self.challenges.listar_pendientes(user_id).await?;
        let desafio = pendientes
            .iter()
            .find(|d| secreto_coincide(&d.session_hash, &hash_actual))
            .ok_or(DomainError::InvalidCredentials)?;

        // `code_hash` presente = desafío de método `email` (2026-08-11):
        // comparación por hash, igual que `device_challenges`. Ausente =
        // `totp`, el código vive en la app del usuario y se verifica con el
        // algoritmo RFC 6238 contra el credential confirmado.
        match &desafio.code_hash {
            Some(hash_esperado) => {
                let codigo_str = format!("{codigo:06}");
                let hash_recibido = Sha256::digest(codigo_str.as_bytes()).to_vec();
                if !secreto_coincide(hash_esperado, &hash_recibido) {
                    return Err(DomainError::InvalidCredentials);
                }
            }
            None => {
                let credential = self.totp.buscar_confirmado(user_id).await?.ok_or(DomainError::InvalidCredentials)?;
                let mut secreto = descifrar_secreto(self.secrets_key, &credential)?;
                let ahora = OffsetDateTime::now_utc().unix_timestamp() as u64;
                let valido = totp::verificar_totp(&secreto, codigo, ahora);
                secreto.zeroize();
                if !valido {
                    return Err(DomainError::InvalidCredentials);
                }
            }
        }

        self.challenges.consumir(desafio.id).await?;
        self.sesiones.marcar_mfa_verificada(session_id_actual).await?;
        // 2026-08-13: recordar MFA en este dispositivo — próximo login desde
        // acá salta el desafío (ver `AuthService::resolver_tras_f02`).
        if let Some(hash) = device_token_hash {
            self.dispositivos.marcar_mfa_confirmado(user_id, hash).await?;
        }

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AuthLoginSucceeded, Some(user_id))
                .con_sujeto("user", user_id),
        ));

        Ok(())
    }
}
