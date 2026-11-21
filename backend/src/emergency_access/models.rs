// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EmergencyAccess {
    pub id: Uuid,
    pub granter_id: Uuid,
    pub grantee_id: Uuid,
    pub access_level: String,
    pub sealed_material: Vec<u8>,
    pub wait_time_days: i32,
    pub status: String,
    pub created_at: OffsetDateTime,
}

/// QA-22: lo que hace falta para avisarle al titular de una solicitud
/// pendiente (al crearla y en el recordatorio de mitad de plazo).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AvisoEmergencia {
    pub granter_email: String,
    pub grantee_email: String,
    pub grantee_nombre: String,
    pub requested_at: OffsetDateTime,
    pub wait_time_days: i32,
}

impl AvisoEmergencia {
    pub fn evento(&self, recordatorio: bool) -> crate::eventos::DomainEvent {
        crate::eventos::DomainEvent::EmergencyAccessRequested {
            granter_email: self.granter_email.clone(),
            grantee_nombre: self.grantee_nombre.clone(),
            grantee_email: self.grantee_email.clone(),
            concede_el: self.concede_el(),
            recordatorio,
        }
    }

    /// Cuándo el job lo concede si el titular no responde.
    pub fn concede_el(&self) -> OffsetDateTime {
        self.requested_at + time::Duration::days(self.wait_time_days.into())
    }
}

#[derive(Debug, Clone)]
pub struct EmergencyAccessRequest {
    pub id: Uuid,
    pub emergency_access_id: Uuid,
    pub requested_at: OffsetDateTime,
    pub status: String,
    pub resolved_at: Option<OffsetDateTime>,
}
