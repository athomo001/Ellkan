// Autor: Athan Espinoza

//! Service de reportes (F-23) — nunca importa `axum`. Sólo lectura, sin
//! eventos de auditoría (mismo criterio que `GET /admin/audit-log`: leer
//! no se audita).

use uuid::Uuid;

use crate::error::DomainError;
use crate::password_policy::repository::PasswordPolicyRepository;

use super::models::{FilaMfaCoverage, FilaPasswordExpirado, FilaRecursoSinRotar, FilaUsuarioInactivo};
use super::repository::ReportsRepository;

pub const LIMITE_PAGINA_DEFAULT: i64 = 50;
pub const LIMITE_PAGINA_MAXIMO: i64 = 200;
/// Default de `?days=` para `inactive_users`/`resources_never_rotated`
/// cuando el caller no lo especifica — mismo orden de magnitud que otros
/// techos de retención de la app.
const DIAS_DEFAULT: i64 = 90;

pub struct ReportsService<'a, R, PP> {
    pub reportes: &'a R,
    pub password_policy: &'a PP,
}

impl<'a, R, PP> ReportsService<'a, R, PP>
where
    R: ReportsRepository,
    PP: PasswordPolicyRepository,
{
    fn limite(&self, pedido: Option<i64>) -> i64 {
        pedido.unwrap_or(LIMITE_PAGINA_DEFAULT).clamp(1, LIMITE_PAGINA_MAXIMO)
    }

    /// Sin rotación de passphrase implementada (F-15), el umbral real que
    /// importa es el de política — si no está configurado, usa el mismo
    /// default que el resto de los reportes.
    pub async fn passwords_expired(
        &self,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<(Vec<FilaPasswordExpirado>, Option<Uuid>), DomainError> {
        let politica = self.password_policy.obtener().await?;
        let umbral_dias = politica.passphrase_rotation_days.map(i64::from).unwrap_or(DIAS_DEFAULT);
        let limite = self.limite(limit);
        let filas = self.reportes.passwords_expired(umbral_dias, cursor, limite).await?;
        let next_cursor = if filas.len() as i64 == limite { filas.last().map(|f| f.user_id) } else { None };
        Ok((filas, next_cursor))
    }

    pub async fn mfa_coverage(
        &self,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<(Vec<FilaMfaCoverage>, Option<Uuid>), DomainError> {
        let limite = self.limite(limit);
        let filas = self.reportes.mfa_coverage(cursor, limite).await?;
        let next_cursor = if filas.len() as i64 == limite { filas.last().map(|f| f.user_id) } else { None };
        Ok((filas, next_cursor))
    }

    pub async fn inactive_users(
        &self,
        dias: Option<i64>,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<(Vec<FilaUsuarioInactivo>, Option<Uuid>), DomainError> {
        let umbral_dias = dias.unwrap_or(DIAS_DEFAULT).max(1);
        let limite = self.limite(limit);
        let filas = self.reportes.inactive_users(umbral_dias, cursor, limite).await?;
        let next_cursor = if filas.len() as i64 == limite { filas.last().map(|f| f.user_id) } else { None };
        Ok((filas, next_cursor))
    }

    pub async fn resources_never_rotated(
        &self,
        dias: Option<i64>,
        cursor: Option<Uuid>,
        limit: Option<i64>,
    ) -> Result<(Vec<FilaRecursoSinRotar>, Option<Uuid>), DomainError> {
        let umbral_dias = dias.unwrap_or(DIAS_DEFAULT).max(1);
        let limite = self.limite(limit);
        let filas = self.reportes.resources_never_rotated(umbral_dias, cursor, limite).await?;
        let next_cursor = if filas.len() as i64 == limite { filas.last().map(|f| f.resource_id) } else { None };
        Ok((filas, next_cursor))
    }
}
