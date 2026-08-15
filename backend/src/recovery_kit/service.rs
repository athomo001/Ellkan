// Autor: Athan Espinoza

//! Service de recovery kit — nunca importa `axum`. A diferencia de
//! `account_recovery` (F-16), acá el servidor nunca desella nada: todo el
//! material queda opaco de punta a punta, el cliente hace el unseal/reseal
//! con la privada del kit que sólo él tiene.

use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use ellkan_crypto::aleatoriedad::bytes_aleatorios;
use ellkan_crypto::comparacion::secreto_coincide;
use ellkan_crypto::totp;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::repository::UserRepository;
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::me::models::NuevaClavePrivada;
use crate::me::repository::ClavePrivadaRepository;
use crate::me::service::CambiarPassphraseService;
use crate::mfa::repository::TotpCredentialRepository;

use super::models::{MetodoMfa, RecoveryKit};
use super::repository::{RecoveryKitRepository, ResetTokenRepository};

/// Vencimiento del link de reset — más corto que las 24h de
/// `email_verification_challenges` (F-24): esto es una operación de mayor
/// riesgo (termina en una cuenta completamente recuperada).
const TTL_RESET_TOKEN_SEGUNDOS: i64 = 3600;
/// Mismo TTL que el MFA por correo de login (`mfa::service::TTL_CHALLENGE_SEGUNDOS`),
/// por consistencia — es el mismo tipo de código, sólo que en otro flujo.
const TTL_EMAIL_CODE_SEGUNDOS: i64 = crate::mfa::service::TTL_CHALLENGE_SEGUNDOS;

fn hash_de_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Código de un solo uso de 6 dígitos — mismo generador que `auth::service`
/// (CSPRNG, nunca `thread_rng`), copiado acá porque esa función es privada
/// de su módulo (mismo criterio de duplicación ya establecido entre
/// `auth::service`/`mfa::service` para este tipo de helper chico).
fn generar_codigo_email() -> String {
    let bytes: [u8; 4] = bytes_aleatorios();
    let n = u32::from_be_bytes(bytes) % 1_000_000;
    format!("{n:06}")
}

fn hash_de_codigo(codigo: &str) -> Vec<u8> {
    Sha256::digest(codigo.as_bytes()).to_vec()
}

pub struct RecoveryKitService<'a, K, T, U, TC, C> {
    pub kits: &'a K,
    pub tokens: &'a T,
    pub usuarios: &'a U,
    pub totp: &'a TC,
    pub claves: &'a C,
    pub secrets_key: &'a ellkan_crypto::secretos::ClaveSecreta32,
    pub eventos: EmisorDeEventos,
}

impl<'a, K, T, U, TC, C> RecoveryKitService<'a, K, T, U, TC, C>
where
    K: RecoveryKitRepository,
    T: ResetTokenRepository,
    U: UserRepository,
    TC: TotpCredentialRepository,
    C: ClavePrivadaRepository,
{
    /// `PUT /me/recovery-kit` — sirve tanto para la generación inicial
    /// (onboarding) como para regenerar desde ajustes: el `on conflict` del
    /// repository pisa el kit anterior atómicamente, nunca queda un rastro
    /// del valor viejo que el servidor pueda re-servir.
    pub async fn generar_o_regenerar(
        &self,
        user_id: Uuid,
        kit_public_key_x25519: Vec<u8>,
        sealed_identity_material: Vec<u8>,
    ) -> Result<RecoveryKit, DomainError> {
        if kit_public_key_x25519.len() != 32 {
            return Err(DomainError::ValidacionInvalida("kit_public_key_x25519 debe ser de 32 bytes".into()));
        }

        let kit = self.kits.upsert(user_id, &kit_public_key_x25519, &sealed_identity_material).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RecoveryKitGenerated, Some(user_id)).con_sujeto("user", user_id),
        ));

        Ok(kit)
    }

    /// `GET /me/recovery-kit` — nunca expone el contenido del kit, sólo
    /// metadata de estado (ver requisito duro del diseño: re-mostrar el
    /// original degradaría el modelo a ser equivalente a F-16).
    pub async fn estado(&self, user_id: Uuid) -> Result<Option<RecoveryKit>, DomainError> {
        Ok(self.kits.buscar_por_usuario(user_id).await?)
    }

    /// `POST /recovery-kit/reset` — sin sesión, a propósito. Anti-enumeración
    /// idéntica a `AccountRecoveryService::crear_solicitud`: un email sin
    /// cuenta y un email sin kit configurado devuelven el mismo resultado.
    pub async fn solicitar_reset(&self, email: &str) -> Result<(), DomainError> {
        let user = self.usuarios.buscar_por_email(email).await?.ok_or(DomainError::NotFound)?;
        self.kits.buscar_por_usuario(user.id).await?.ok_or(DomainError::NotFound)?;

        let token_bytes: [u8; 32] = bytes_aleatorios();
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(TTL_RESET_TOKEN_SEGUNDOS);
        self.tokens.crear(user.id, &hash_de_token(&token), expires_at).await?;

        let _ = self.eventos.send(DomainEvent::RecoveryKitResetRequested { user_id: user.id, email: email.to_string(), token });
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RecoveryKitResetRequested, None).con_sujeto("user", user.id),
        ));

        Ok(())
    }

    /// `GET /recovery-kit/reset/{token}` — el cliente necesita el material
    /// sellado para desellarlo localmente con la privada del kit, y saber
    /// qué segundo factor le corresponde antes de pedirlo.
    pub async fn verificar_token(&self, token: &str) -> Result<(Vec<u8>, MetodoMfa, String), DomainError> {
        let fila = self.tokens.buscar_vigente_por_hash(&hash_de_token(token)).await?.ok_or(DomainError::NotFound)?;
        let kit = self.kits.buscar_por_usuario(fila.user_id).await?.ok_or(DomainError::NotFound)?;

        let metodo = if self.totp.buscar_confirmado(fila.user_id).await?.is_some() {
            MetodoMfa::Totp
        } else {
            MetodoMfa::Email
        };

        // El cliente necesita el email como AAD para re-envolver la clave
        // privada con la passphrase nueva (`sellar_clave_privada`) — si
        // llegó acá vía el link directo, nunca completó el paso 'email' de
        // la UI y no lo tendría de otro modo.
        let (email, _nombre) = self.usuarios.email_y_nombre(fila.user_id).await?.ok_or(DomainError::NotFound)?;

        Ok((kit.sealed_identity_material, metodo, email))
    }

    /// `POST /recovery-kit/reset/{token}/email-code` — sólo tiene sentido si
    /// el usuario no tiene TOTP confirmado; re-valida server-side (nunca
    /// confía en lo que el cliente ya decidió al llamar `verificar_token`).
    pub async fn enviar_codigo_email(&self, token: &str) -> Result<(), DomainError> {
        let fila = self.tokens.buscar_vigente_por_hash(&hash_de_token(token)).await?.ok_or(DomainError::NotFound)?;
        if self.totp.buscar_confirmado(fila.user_id).await?.is_some() {
            return Err(DomainError::ValidacionInvalida("este usuario verifica con TOTP, no con código por email".into()));
        }

        let (email, _nombre) = self.usuarios.email_y_nombre(fila.user_id).await?.ok_or(DomainError::NotFound)?;
        let codigo = generar_codigo_email();
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(TTL_EMAIL_CODE_SEGUNDOS);
        self.tokens.guardar_codigo_email(fila.id, &hash_de_codigo(&codigo), expires_at).await?;

        let _ = self.eventos.send(DomainEvent::RecoveryKitResetEmailCode { user_id: fila.user_id, email, codigo });

        Ok(())
    }

    /// `POST /recovery-kit/reset/{token}/complete` — el cliente ya desselló
    /// localmente el material con la privada de su kit y fijó una
    /// passphrase nueva; acá se verifica el segundo factor (TOTP si el
    /// usuario tiene uno confirmado, sin importar la política MFA de login
    /// de la organización; email si no), se persiste la passphrase nueva
    /// (reusando `CambiarPassphraseService` — mata todas las sesiones), y se
    /// marca el kit usado para forzar su reemplazo en el próximo login.
    pub async fn completar_reset(
        &self,
        token: &str,
        mfa_code: &str,
        nueva: NuevaClavePrivada,
    ) -> Result<(), DomainError> {
        let fila = self.tokens.buscar_vigente_por_hash(&hash_de_token(token)).await?.ok_or(DomainError::NotFound)?;

        let mfa_valido = match self.totp.buscar_confirmado(fila.user_id).await? {
            Some(credential) => {
                let codigo: u32 = mfa_code.trim().parse().map_err(|_| DomainError::InvalidCredentials)?;
                let mut secreto = crate::mfa::service::descifrar_secreto(self.secrets_key, &credential)?;
                let ahora = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
                let paso = totp::verificar_totp_paso(&secreto, codigo, ahora);
                secreto.zeroize();
                // H-06: mismo criterio anti-replay que el login normal
                // (`mfa::service::verificar_login_interno`) — un código ya
                // usado no sirve para completar un segundo reset.
                match paso {
                    Some(paso) => self.totp.marcar_paso_aceptado(credential.id, paso as i64).await?,
                    None => false,
                }
            }
            None => match &fila.email_code_hash {
                Some(hash_esperado) => secreto_coincide(hash_esperado, &hash_de_codigo(mfa_code.trim())),
                None => false,
            },
        };

        if !mfa_valido {
            let _ = self.eventos.send(DomainEvent::Auditoria(
                EventoAuditoria::nuevo(AuditEventType::RecoveryKitResetMfaFailed, Some(fila.user_id)),
            ));
            return Err(DomainError::InvalidCredentials);
        }

        if !self.tokens.marcar_consumido(fila.id).await? {
            return Err(DomainError::Conflict);
        }

        let cambio = CambiarPassphraseService { claves: self.claves, eventos: self.eventos.clone() };
        cambio.actualizar(fila.user_id, nueva).await?;

        self.kits.marcar_para_rotar(fila.user_id).await?;

        let (email, _nombre) = self.usuarios.email_y_nombre(fila.user_id).await?.ok_or(DomainError::NotFound)?;
        let _ = self.eventos.send(DomainEvent::RecoveryKitResetCompleted { user_id: fila.user_id, email });
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RecoveryKitResetCompleted, Some(fila.user_id))
                .con_sujeto("user", fila.user_id),
        ));

        Ok(())
    }
}
