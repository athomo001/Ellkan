// Autor: Athan Espinoza

//! Service de preferencias propias (F-30/F-31/F-39) — nunca importa `axum`.
//! `clipboard_clear_minutes`/`auto_lock_minutes` quedan acotados por el
//! techo opcional que un admin haya fijado en `password_policy`
//! (`max_clipboard_clear_minutes`/`max_auto_lock_minutes`, sección
//! `/me/preferences` de `03-api-contrato.md`) — un usuario puede pedir un
//! valor más laxo que el techo, pero nunca uno más permisivo que la
//! política de la organización.

use uuid::Uuid;

use crate::error::DomainError;
use crate::password_policy::repository::PasswordPolicyRepository;

use super::models::Preferencias;
use super::repository::PreferenciasRepository;

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
