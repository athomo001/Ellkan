// Autor: Athan Espinoza

//! Service de auth — nunca importa nada de `axum`. Recibe argumentos ya
//! extraídos, devuelve `Result<T, DomainError>`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use ellkan_crypto::aleatoriedad::bytes_aleatorios;
use ellkan_crypto::comparacion::secreto_coincide;

use super::models::{NuevoUsuario, ResultadoVerify, Session, User};
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

pub struct AuthService<'a, U, C, S, KD, DC> {
    pub usuarios: &'a U,
    pub challenges: &'a C,
    pub sesiones: &'a S,
    pub dispositivos: &'a KD,
    pub desafios_dispositivo: &'a DC,
    pub eventos: EmisorDeEventos,
}

impl<'a, U, C, S, KD, DC> AuthService<'a, U, C, S, KD, DC>
where
    U: UserRepository,
    C: AuthChallengeRepository,
    S: SessionRepository,
    KD: KnownDeviceRepository,
    DC: DeviceChallengeRepository,
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

    pub async fn verify(
        &self,
        email: &str,
        nonce: &[u8],
        signature: &[u8],
        device_token_hash: &[u8],
    ) -> Result<ResultadoVerify, DomainError> {
        let user = self
            .usuarios
            .buscar_por_email(email)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

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

            return Ok(ResultadoVerify::PendienteDispositivo { device_challenge_id });
        }

        let sesion = self.sesiones.crear(user.id, user.security_stamp).await?;
        Ok(ResultadoVerify::SesionCompleta(sesion))
    }

    /// Confirma el código de un dispositivo no reconocido (F-02) — da de alta
    /// el dispositivo y emite la sesión completa que `verify` no pudo emitir.
    pub async fn verify_device(
        &self,
        device_challenge_id: Uuid,
        codigo: &str,
    ) -> Result<Session, DomainError> {
        let desafio = self
            .desafios_dispositivo
            .buscar_pendiente(device_challenge_id)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

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
        self.sesiones.crear(user.id, user.security_stamp).await.map_err(DomainError::from)
    }

    pub async fn logout(&self, session_id: Uuid) -> Result<(), DomainError> {
        self.sesiones.revocar(session_id).await?;
        Ok(())
    }
}
