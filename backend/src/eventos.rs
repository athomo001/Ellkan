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
    /// F-24: auto-registro (no bootstrap) recién creado, código de
    /// verificación de email — mismo criterio de `codigo` en claro sólo
    /// mientras vive en memoria que `DispositivoNoReconocido`.
    RegistroPendienteVerificacion { user_id: Uuid, email: String, codigo: String },
    /// F-14/2026-08-11: login pendiente de MFA cuando la política tiene
    /// `email` como método activo — a diferencia de `totp` (el código nunca
    /// pasa por el servidor), acá el código lo genera el servidor y no hay
    /// otro momento en el que se pueda mandar.
    MfaCodigoPorCorreo { user_id: Uuid, email: String, codigo: String },
    /// F-33: dispara el consumidor de `metadata::rotacion`, que vigila
    /// `saliente_id` hasta que ningún recurso lo referencie más y recién
    /// entonces la expira — nunca antes.
    MetadataKeyRotationStarted { saliente_id: Uuid, entrante_id: Uuid },
    /// Recovery kit: link de reset — a diferencia de `codigo` en los otros
    /// variantes, `token` viaja en claro sólo mientras el evento vive en
    /// memoria, igual criterio (se usa para armar la URL del email y se
    /// suelta ahí mismo).
    RecoveryKitResetRequested { user_id: Uuid, email: String, token: String },
    /// Recovery kit: fallback de segundo factor cuando el usuario no tiene
    /// TOTP confirmado — mismo criterio de `codigo` en claro que `MfaCodigoPorCorreo`.
    RecoveryKitResetEmailCode { user_id: Uuid, email: String, codigo: String },
    /// Recovery kit: aviso al dueño de la cuenta de que se acaba de
    /// recuperar — si no fue él, tiene que enterarse.
    RecoveryKitResetCompleted { user_id: Uuid, email: String },
    /// F-16, 2026-08-11: notificación de una solicitud pendiente acotada a
    /// los admins del/los grupo(s) del solicitante (fallback a admins de
    /// organización si no tiene grupo) — antes esta acción no mandaba
    /// ningún email a nadie.
    AccountRecoveryAdminNotify { request_id: Uuid, target_email: String, recipient_emails: Vec<String> },
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
