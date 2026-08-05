// Autor: Athan Espinoza

//! Sistema de eventos de dominio: enum cerrado, `tokio::sync::broadcast`,
//! consumidores desacoplados del service que emite. Mínimo necesario para
//! `POST /auth/verify-device` (F-02); se extiende sin tocar lo ya escrito
//! cuando haga falta un consumidor nuevo (auditoría, rotación de metadata key).

use uuid::Uuid;

use crate::audit::models::EventoAuditoria;

/// El campo `codigo` viaja en claro (es lo que efectivamente se manda por
/// email) sólo mientras el evento vive en memoria — el único consumidor hoy
/// lo usa para escribir `outbound_emails.body` y lo suelta ahí mismo, nunca
/// se loguea.
#[derive(Clone)]
pub enum DomainEvent {
    DispositivoNoReconocido { user_id: Uuid, email: String, codigo: String },
    /// F-33: dispara el consumidor de `metadata::rotacion`, que vigila
    /// `saliente_id` hasta que ningún recurso lo referencie más y recién
    /// entonces la expira — nunca antes.
    MetadataKeyRotationStarted { saliente_id: Uuid, entrante_id: Uuid },
    /// F-13: dispara el consumidor de `audit::consumidor`, que persiste la
    /// entrada de forma asíncrona — nunca dentro de la transacción de la
    /// acción que audita.
    Auditoria(EventoAuditoria),
}

pub type EmisorDeEventos = tokio::sync::broadcast::Sender<DomainEvent>;

pub fn nuevo_canal() -> EmisorDeEventos {
    let (tx, _rx) = tokio::sync::broadcast::channel(256);
    tx
}
