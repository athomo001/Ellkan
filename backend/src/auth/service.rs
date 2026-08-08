// Autor: Athan Espinoza

//! Service de auth — nunca importa nada de `axum`. Recibe argumentos ya
//! extraídos, devuelve `Result<T, DomainError>`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::mfa::models::DecisionMfa;
use crate::mfa::repository::{MfaChallengeRepository, MfaPolicyRepository, TotpCredentialRepository};
use crate::smtp_config::repository::SmtpConfigRepository;
use ellkan_crypto::aleatoriedad::bytes_aleatorios;
use ellkan_crypto::comparacion::secreto_coincide;

use super::models::{DeviceChallengeRow, NuevoUsuario, ResultadoVerify, User};
use super::repository::{
    AuthChallengeRepository, DeviceChallengeRepository, KnownDeviceRepository, SessionRepository,
    UserRepository,
};

const TTL_CHALLENGE_SEGUNDOS: i64 = 120;
const TTL_DEVICE_CHALLENGE_SEGUNDOS: i64 = 600;

fn hash_de_codigo(codigo: &str) -> Vec<u8> {
    Sha256::digest(codigo.as_bytes()).to_vec()
}

/// Código de un solo uso de 6 dígitos — CSPRNG, nunca `thread_rng`.
fn generar_codigo_device() -> String {
    let bytes: [u8; 4] = bytes_aleatorios();
    let n = u32::from_be_bytes(bytes) % 1_000_000;
    format!("{n:06}")
}

pub struct AuthService<'a, U, C, S, KD, DC, MP, MT, MC, SC> {
    pub usuarios: &'a U,
    pub challenges: &'a C,
    pub sesiones: &'a S,
    pub dispositivos: &'a KD,
    pub desafios_dispositivo: &'a DC,
    /// F-14: sólo se consultan para decidir el estado del login una vez que
    /// F-02 (dispositivo conocido) ya se resolvió — la verificación del
    /// código en sí vive en `mfa::service::MfaService`, no acá.
    pub mfa_policy: &'a MP,
    pub mfa_totp: &'a MT,
    pub mfa_challenges: &'a MC,
    /// Parte A/B: si no está configurado, F-02 no puede pedir un código que
    /// nunca va a llegar — se relee en cada intento de login (nunca
    /// cacheado), así que un cambio del admin aplica de inmediato.
    pub smtp_config: &'a SC,
    pub eventos: EmisorDeEventos,
}

impl<'a, U, C, S, KD, DC, MP, MT, MC, SC> AuthService<'a, U, C, S, KD, DC, MP, MT, MC, SC>
where
    U: UserRepository,
    C: AuthChallengeRepository,
    S: SessionRepository,
    KD: KnownDeviceRepository,
    DC: DeviceChallengeRepository,
    MP: MfaPolicyRepository,
    MT: TotpCredentialRepository,
    MC: MfaChallengeRepository,
    SC: SmtpConfigRepository,
{
    pub async fn registrar(&self, nuevo: NuevoUsuario<'_>) -> Result<User, DomainError> {
        if nuevo.public_key_x25519.len() != 32 || nuevo.public_key_ed25519.len() != 32 {
            return Err(DomainError::ValidacionInvalida(
                "las claves públicas deben ser de 32 bytes".to_string(),
            ));
        }
        self.usuarios.crear(nuevo).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })
    }

    /// Anti user-enumeration: misma forma y mismo costo de respuesta exista o
    /// no el email — si no existe, el nonce se genera pero nunca se persiste.
    pub async fn challenge(&self, email: &str) -> Result<Vec<u8>, DomainError> {
        let nonce: [u8; 32] = bytes_aleatorios();
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(TTL_CHALLENGE_SEGUNDOS);

        if let Some(user) = self.usuarios.buscar_por_email(email).await? {
            self.challenges
                .guardar_challenge(user.id, &nonce, expires_at)
                .await?;
        }

        Ok(nonce.to_vec())
    }

    /// F-01 (frontend web): material de desbloqueo por email — mismo
    /// criterio anti-enumeración que `challenge()`: si el email no existe,
    /// devuelve bytes aleatorios con exactamente el mismo largo que el
    /// material real (80/24/16 bytes), para que la forma de la respuesta
    /// nunca distinga "no existe" de "existe" — el intento de desbloqueo
    /// va a fallar en los dos casos de la misma manera (passphrase
    /// "incorrecta").
    pub async fn material_desbloqueo(&self, email: &str) -> Result<crate::auth::models::MaterialDesbloqueo, DomainError> {
        if let Some(material) = self.usuarios.material_desbloqueo_por_email(email).await? {
            return Ok(material);
        }
        Ok(crate::auth::models::MaterialDesbloqueo {
            encrypted_private_key_blob: bytes_aleatorios::<80>().to_vec(),
            private_key_nonce: bytes_aleatorios::<24>().to_vec(),
            kdf_salt: bytes_aleatorios::<16>().to_vec(),
        })
    }

    /// F-13: envuelve `verify_con_usuario` para poder auditar exactamente una
    /// vez por intento, con el `actor_user_id` correcto (`None` si el email
    /// no corresponde a ninguna cuenta — anti user-enumeration en el propio
    /// log: el intento queda registrado internamente aunque la respuesta
    /// HTTP no distinga los dos casos).
    pub async fn verify(
        &self,
        email: &str,
        nonce: &[u8],
        signature: &[u8],
        device_token_hash: &[u8],
    ) -> Result<ResultadoVerify, DomainError> {
        let user_encontrado = self.usuarios.buscar_por_email(email).await?;
        let actor_conocido = user_encontrado.as_ref().map(|u| u.id);

        let resultado =
            self.verify_con_usuario(user_encontrado, email, nonce, signature, device_token_hash).await;

        match &resultado {
            Ok(ResultadoVerify::SesionCompleta(sesion)) => {
                let _ = self.eventos.send(DomainEvent::Auditoria(
                    EventoAuditoria::nuevo(AuditEventType::AuthLoginSucceeded, Some(sesion.user_id))
                        .con_sujeto("user", sesion.user_id),
                ));
            }
            // El caso "dispositivo no reconocido" ya se audita en el punto
            // donde se detecta, más abajo — acá no es ni éxito ni fallo.
            // Los dos estados de MFA tampoco son éxito ni fallo todavía:
            // `mfa::service` audita el desenlace real cuando se resuelvan.
            Ok(ResultadoVerify::PendienteDispositivo { .. })
            | Ok(ResultadoVerify::PendienteMfa { .. })
            | Ok(ResultadoVerify::RequiereConfigurarMfa { .. }) => {}
            Err(_) => {
                let _ = self.eventos.send(DomainEvent::Auditoria(EventoAuditoria::nuevo(
                    AuditEventType::AuthLoginFailed,
                    actor_conocido,
                )));
            }
        }

        resultado
    }

    async fn verify_con_usuario(
        &self,
        user: Option<User>,
        email: &str,
        nonce: &[u8],
        signature: &[u8],
        device_token_hash: &[u8],
    ) -> Result<ResultadoVerify, DomainError> {
        let user = user.ok_or(DomainError::InvalidCredentials)?;

        let consumido = self.challenges.consumir_challenge(user.id, nonce).await?;
        if !consumido {
            return Err(DomainError::InvalidCredentials);
        }

        let keys = self
            .usuarios
            .buscar_keys(user.id)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        let clave_publica_bytes: [u8; 32] = keys
            .public_key_ed25519
            .try_into()
            .map_err(|_| DomainError::InvalidCredentials)?;
        let firma_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| DomainError::InvalidCredentials)?;

        let verificadora =
            VerifyingKey::from_bytes(&clave_publica_bytes).map_err(|_| DomainError::InvalidCredentials)?;
        let firma = Signature::from_bytes(&firma_bytes);

        verificadora
            .verify(nonce, &firma)
            .map_err(|_| DomainError::InvalidCredentials)?;

        // F-02: dispositivo no reconocido -> sesión parcial + código por email,
        // salvo que ya haya MFA/SSO activo — ninguno de los dos existe todavía
        // (F-14/F-17 son Fase 1/2), así que hoy la condición siempre aplica.
        let conocido = self.dispositivos.es_conocido(user.id, device_token_hash).await?;
        if !conocido {
            // Parte A/B: sin SMTP configurado, un código que nunca va a
            // llegar bloquearía a cualquier usuario (incluido el primer
            // admin) para siempre — se marca el dispositivo conocido sin
            // pedirlo, mismo método que usa el camino de éxito real
            // (`verify_device_con_desafio`), y queda trazado en el audit
            // log para que no sea un bypass silencioso. Si el admin
            // configura SMTP después, el próximo dispositivo nuevo sí
            // vuelve a pedir verificación real — esto no marca nada más
            // allá de este dispositivo puntual.
            let smtp_configurado = self.smtp_config.obtener().await?.esta_configurado();
            if !smtp_configurado {
                tracing::warn!(
                    user_id = %user.id,
                    "SMTP no configurado — dispositivo nuevo marcado conocido sin verificación real (F-02 desactivado)"
                );
                self.dispositivos.marcar_conocido(user.id, device_token_hash).await?;
                let _ = self.eventos.send(DomainEvent::Auditoria(
                    EventoAuditoria::nuevo(AuditEventType::AuthDeviceAutoVerifiedNoSmtp, Some(user.id))
                        .con_sujeto("user", user.id),
                ));
                return self.resolver_tras_f02(user).await;
            }

            let codigo = generar_codigo_device();
            let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(TTL_DEVICE_CHALLENGE_SEGUNDOS);
            let device_challenge_id = self
                .desafios_dispositivo
                .crear(user.id, device_token_hash, &hash_de_codigo(&codigo), expires_at)
                .await?;

            // Nunca síncrono dentro del request — el consumidor real corre en
            // su propia tarea, suscripto al broadcast.
            let _ = self.eventos.send(DomainEvent::DispositivoNoReconocido {
                user_id: user.id,
                email: email.to_string(),
                codigo,
            });
            let _ = self.eventos.send(DomainEvent::Auditoria(
                EventoAuditoria::nuevo(AuditEventType::AuthDeviceUnrecognized, Some(user.id))
                    .con_sujeto("user", user.id),
            ));

            return Ok(ResultadoVerify::PendienteDispositivo { device_challenge_id });
        }

        self.resolver_tras_f02(user).await
    }

    /// F-14: una vez que F-02 (dispositivo conocido) ya se resolvió —ya sea
    /// porque el dispositivo ya era conocido, o porque se lo acaba de
    /// verificar—, decide si el login queda completo, pendiente de un
    /// código MFA, o forzado a configurar un segundo factor por primera
    /// vez. Compartido entre `verify_con_usuario` y
    /// `verify_device_con_desafio` — la decisión de MFA es la misma en los
    /// dos casos, sólo cambia cómo se llegó hasta acá.
    pub(crate) async fn resolver_tras_f02(&self, user: User) -> Result<ResultadoVerify, DomainError> {
        let politica = self.mfa_policy.obtener().await?;
        let tiene_confirmado = self.mfa_totp.buscar_confirmado(user.id).await?.is_some();

        match crate::mfa::service::decidir(&politica, tiene_confirmado, user.created_at) {
            DecisionMfa::NoRequerido => {
                let sesion = self.sesiones.crear(user.id, user.security_stamp).await?;
                Ok(ResultadoVerify::SesionCompleta(sesion))
            }
            DecisionMfa::DebeVerificar => {
                let parcial = self.sesiones.crear_parcial(user.id, user.security_stamp).await?;
                let hash = crate::mfa::service::hash_de_sesion(parcial.id);
                let expires_at = OffsetDateTime::now_utc()
                    + time::Duration::seconds(crate::mfa::service::TTL_CHALLENGE_SEGUNDOS);
                self.mfa_challenges.crear(user.id, &hash, expires_at).await?;
                Ok(ResultadoVerify::PendienteMfa { session_id: parcial.id })
            }
            DecisionMfa::DebeConfigurar => {
                let parcial = self.sesiones.crear_parcial(user.id, user.security_stamp).await?;
                Ok(ResultadoVerify::RequiereConfigurarMfa { session_id: parcial.id })
            }
        }
    }

    /// Confirma el código de un dispositivo no reconocido (F-02) — da de alta
    /// el dispositivo y emite la sesión completa que `verify` no pudo emitir.
    /// F-13: mismo criterio que `verify` — se audita exactamente una vez por
    /// intento, con el `actor_user_id` que ya se conoce en cada punto.
    pub async fn verify_device(
        &self,
        device_challenge_id: Uuid,
        codigo: &str,
    ) -> Result<ResultadoVerify, DomainError> {
        let desafio = self.desafios_dispositivo.buscar_pendiente(device_challenge_id).await?;
        let actor_conocido = desafio.as_ref().map(|d| d.user_id);

        let resultado = self.verify_device_con_desafio(desafio, codigo).await;

        // "Dispositivo verificado" es un hecho consumado apenas el código de
        // F-02 es correcto, sin importar qué decida F-14 después — un fallo
        // acá es siempre sobre el código de dispositivo en sí, nunca sobre MFA.
        match &resultado {
            Ok(_) => {
                if let Some(user_id) = actor_conocido {
                    let _ = self.eventos.send(DomainEvent::Auditoria(
                        EventoAuditoria::nuevo(AuditEventType::AuthDeviceVerified, Some(user_id))
                            .con_sujeto("user", user_id),
                    ));
                }
            }
            Err(_) => {
                let _ = self.eventos.send(DomainEvent::Auditoria(EventoAuditoria::nuevo(
                    AuditEventType::AuthDeviceVerificationFailed,
                    actor_conocido,
                )));
            }
        }

        resultado
    }

    async fn verify_device_con_desafio(
        &self,
        desafio: Option<DeviceChallengeRow>,
        codigo: &str,
    ) -> Result<ResultadoVerify, DomainError> {
        let desafio = desafio.ok_or(DomainError::InvalidCredentials)?;

        // Comparación en tiempo constante — nunca en SQL.
        if !secreto_coincide(&desafio.code_hash, &hash_de_codigo(codigo)) {
            return Err(DomainError::InvalidCredentials);
        }
        self.desafios_dispositivo.consumir(desafio.id).await?;
        self.dispositivos.marcar_conocido(desafio.user_id, &desafio.device_token_hash).await?;

        let user = self
            .usuarios
            .buscar_por_id(desafio.user_id)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;
        self.resolver_tras_f02(user).await
    }

    pub async fn logout(&self, session_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        self.sesiones.revocar(session_id).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AuthLogout, Some(user_id)).con_sujeto("user", user_id),
        ));
        Ok(())
    }
}
