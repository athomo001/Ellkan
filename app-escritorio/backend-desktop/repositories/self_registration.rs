// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de
//! `SelfRegistrationPolicyRepository` — sin tabla: en modo escritorio no hay
//! "auto-registro público" distinto del bootstrap de la instancia (spec/13
//! §16, siempre el mismo único usuario), y el camino de bootstrap ya
//! saltea esta política en `auth::service` sin importar lo que devuelva acá
//! (mismo criterio que `smtp_config`/`mfa_policy`).

use crate::error::RepoError;

use crate::self_registration::models::SelfRegistrationPolicy;
use crate::self_registration::repository::SelfRegistrationPolicyRepository;

#[derive(Clone, Default)]
pub struct SqliteSelfRegistrationPolicyRepository;

impl SelfRegistrationPolicyRepository for SqliteSelfRegistrationPolicyRepository {
    async fn obtener(&self) -> Result<SelfRegistrationPolicy, RepoError> {
        Ok(SelfRegistrationPolicy { enabled: true, allowed_domains: Vec::new() })
    }

    async fn actualizar(&self, _policy: &SelfRegistrationPolicy) -> Result<(), RepoError> {
        Ok(())
    }
}
