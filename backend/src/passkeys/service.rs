// Autor: Athan Espinoza

//! Service de passkeys — nunca importa `axum`. Capa fina sobre
//! `webauthn_rs::Webauthn`: éste resuelve la ceremonia criptográfica, acá
//! sólo se persiste su estado y se conecta el resultado con el resto del
//! backend (sesión). El servidor nunca calcula ni valida nada de la
//! extensión PRF — sólo guarda el blob opaco que el cliente decide subir.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
};

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::models::Session;
use crate::auth::repository::{SessionRepository, UserRepository};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::TipoCeremonia;
use super::repository::{CeremonyStateRepository, PasskeyRepository};

/// Ventana de validez de una ceremonia entre `/options` y `/verify` — mismo
/// orden de magnitud que `auth_challenges` de F-02.
const TTL_CEREMONIA_SEGUNDOS: i64 = 300;

pub struct PasskeyService<'a, P, C, U, S> {
    pub passkeys: &'a P,
    pub ceremonias: &'a C,
    pub usuarios: &'a U,
    pub sesiones: &'a S,
    pub webauthn: Arc<Webauthn>,
    pub eventos: EmisorDeEventos,
}

impl<'a, P, C, U, S> PasskeyService<'a, P, C, U, S>
where
    P: PasskeyRepository,
    C: CeremonyStateRepository,
    U: UserRepository,
    S: SessionRepository,
{
    /// `POST /auth/webauthn/register/options` — requiere sesión ya activa
    /// (agregar una passkey a la cuenta propia, no un método de alta).
    pub async fn iniciar_registro(&self, user_id: Uuid) -> Result<CreationChallengeResponse, DomainError> {
        let (email, display_name) = self
            .usuarios
            .email_y_nombre(user_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let existentes = self.passkeys.listar_de(user_id).await?;
        let excluir = existentes.iter().map(|p| p.passkey_data.cred_id().clone()).collect();

        let (ccr, estado) = self
            .webauthn
            .start_passkey_registration(user_id, &email, &display_name, Some(excluir))
            .map_err(|e| DomainError::ValidacionInvalida(format!("no se pudo iniciar el registro WebAuthn: {e}")))?;

        let estado_json = serde_json::to_value(&estado).expect("PasskeyRegistration siempre serializa");
        let expires_at = OffsetDateTime::now_utc() + Duration::from_secs(TTL_CEREMONIA_SEGUNDOS as u64);
        self.ceremonias
            .guardar(user_id, TipoCeremonia::Registro.as_db_str(), estado_json, expires_at)
            .await?;

        Ok(ccr)
    }

    pub async fn finalizar_registro(
        &self,
        user_id: Uuid,
        credencial: RegisterPublicKeyCredential,
        prf_wrapped_private_key: Option<Vec<u8>>,
        label: Option<String>,
    ) -> Result<(), DomainError> {
        let estado_json = self
            .ceremonias
            .tomar(user_id, TipoCeremonia::Registro.as_db_str())
            .await?
            .ok_or_else(|| {
                DomainError::ValidacionInvalida("no hay un registro de passkey en curso (venció o no se inició)".into())
            })?;
        let estado: PasskeyRegistration =
            serde_json::from_value(estado_json).expect("estado persistido siempre es válido");

        let passkey = self
            .webauthn
            .finish_passkey_registration(&credencial, &estado)
            .map_err(|e| DomainError::ValidacionInvalida(format!("ceremonia de registro WebAuthn inválida: {e}")))?;

        let credential_id: Vec<u8> = passkey.cred_id().clone();
        self.passkeys
            .insertar(
                Uuid::now_v7(),
                user_id,
                &credential_id,
                &passkey,
                prf_wrapped_private_key.as_deref(),
                label.as_deref(),
            )
            .await
            .map_err(|e| match e {
                crate::error::RepoError::Conflict => DomainError::Conflict,
                otro => DomainError::Interno(otro),
            })?;

        Ok(())
    }

    /// `POST /auth/webauthn/login/options` — sin sesión, toma `email` igual
    /// que `/auth/challenge`. Anti-enumeración parcial (ver nota de F-03 en
    /// `05-plan-de-implementacion.md`): WebAuthn no-discoverable exige que
    /// el cliente ya sepa qué credenciales intentar, así que "usuario
    /// inexistente" y "usuario sin passkeys" comparten el mismo error.
    pub async fn iniciar_autenticacion(&self, email: &str) -> Result<RequestChallengeResponse, DomainError> {
        let user = self.usuarios.buscar_por_email(email).await?.ok_or(DomainError::InvalidCredentials)?;

        let existentes = self.passkeys.listar_de(user.id).await?;
        if existentes.is_empty() {
            return Err(DomainError::InvalidCredentials);
        }
        let creds: Vec<_> = existentes.iter().map(|p| p.passkey_data.clone()).collect();

        let (rcr, estado) = self
            .webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| DomainError::ValidacionInvalida(format!("no se pudo iniciar la autenticación WebAuthn: {e}")))?;

        let estado_json = serde_json::to_value(&estado).expect("PasskeyAuthentication siempre serializa");
        let expires_at = OffsetDateTime::now_utc() + Duration::from_secs(TTL_CEREMONIA_SEGUNDOS as u64);
        self.ceremonias
            .guardar(user.id, TipoCeremonia::Autenticacion.as_db_str(), estado_json, expires_at)
            .await?;

        Ok(rcr)
    }

    /// Éxito acá mintea sesión directo — un login WebAuthn ya prueba
    /// posesión de un credential ligado a este dispositivo específico, así
    /// que se considera equivalente a MFA activo a los efectos del desafío
    /// de "dispositivo no reconocido" de F-02 (que se omite en ese mismo
    /// caso) — decisión de scope documentada en el plan de esta fase.
    ///
    /// Devuelve además el `prf_wrapped_private_key` de la passkey usada
    /// (`None` si se registró sin PRF) — el servidor sólo lo reenvía, nunca
    /// lo calcula ni lo valida.
    pub async fn finalizar_autenticacion(
        &self,
        email: &str,
        credencial: PublicKeyCredential,
    ) -> Result<(Session, Option<Vec<u8>>), DomainError> {
        let user = self.usuarios.buscar_por_email(email).await?.ok_or(DomainError::InvalidCredentials)?;

        let estado_json = self
            .ceremonias
            .tomar(user.id, TipoCeremonia::Autenticacion.as_db_str())
            .await?
            .ok_or(DomainError::InvalidCredentials)?;
        let estado: PasskeyAuthentication =
            serde_json::from_value(estado_json).expect("estado persistido siempre es válido");

        let resultado = self
            .webauthn
            .finish_passkey_authentication(&credencial, &estado)
            .map_err(|_| DomainError::InvalidCredentials)?;

        let existentes = self.passkeys.listar_de(user.id).await?;
        let mut usada = existentes
            .into_iter()
            .find(|p| p.passkey_data.cred_id() == resultado.cred_id())
            .ok_or(DomainError::InvalidCredentials)?;

        usada.passkey_data.update_credential(&resultado);
        let credential_id: Vec<u8> = usada.passkey_data.cred_id().clone();
        self.passkeys.actualizar_tras_auth(&credential_id, &usada.passkey_data).await?;

        let sesion = self.sesiones.crear(user.id, user.security_stamp).await.map_err(DomainError::from)?;
        Ok((sesion, usada.prf_wrapped_private_key))
    }

    /// `GET /me/passkeys`.
    pub async fn listar(&self, user_id: Uuid) -> Result<Vec<super::models::PasskeyRow>, DomainError> {
        Ok(self.passkeys.listar_de(user_id).await?)
    }

    /// `DELETE /me/passkeys/{id}` — sólo el dueño puede revocar su propia
    /// passkey, mismo guard que `devices::service::revocar`.
    pub async fn revocar(&self, user_id: Uuid, passkey_id: Uuid) -> Result<(), DomainError> {
        let passkey = self.passkeys.buscar(passkey_id).await?.ok_or(DomainError::NotFound)?;
        if passkey.user_id != user_id {
            return Err(DomainError::PermissionDenied);
        }
        self.passkeys.eliminar(passkey_id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PasskeyRevoked, Some(user_id)).con_sujeto("passkey", passkey_id),
        ));

        Ok(())
    }
}
