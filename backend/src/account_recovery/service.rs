// Autor: Athan Espinoza

//! Service de Account Recovery (F-16) — nunca importa `axum`.
//!
//! QA-09: la clave privada organizacional la custodian los admins de
//! organización en su navegador (`org_recovery_key_envelopes`); el servidor
//! guarda bytes opacos, aplica el umbral y, al alcanzarlo, deja la solicitud
//! `awaiting_custodian` para que un custodio re-selle el escrow contra la
//! clave efímera del solicitante. Sólo los escrows sellados contra la clave
//! anterior a QA-09 (custodiada por el servidor con `secrets_key`, hasta que
//! se re-sellan o se purga) los sigue desellando el servidor, en el instante
//! del re-sellado y con `zeroize` inmediato. El pinning de fingerprint
//! contra un re-sellado silencioso de la clave pública organizacional es
//! responsabilidad del cliente (F-16, sección de seguridad).

use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::aleatoriedad::bytes_aleatorios;
use ellkan_crypto::comparacion::secreto_coincide;
use ellkan_crypto::secretos::ClaveSecreta32;
use ellkan_crypto::sellado;

use crate::admin::repository::RoleRepository;
use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::repository::{AuthChallengeRepository, UserRepository};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::groups::repository::GroupMemberRepository;
use crate::me::models::NuevaClavePrivada;
use crate::me::repository::ClavePrivadaRepository;
use crate::me::service::{CambiarPassphraseService, PruebaDePosesion, verificar_posesion};

use super::models::{
    AccountRecoveryPolicy, Custodia, CustodioPendiente, Escrow, MaterialParaCustodio, OrgRecoveryKey, RecoveryRequest, SolicitudPendiente,
};
use super::repository::{AccountRecoveryPolicyRepository, EscrowRepository, OrgRecoveryKeyRepository, RecoveryRequestRepository};

pub struct AccountRecoveryService<'a, P, K, E, R, U, C, RR, GM, CH> {
    pub policy: &'a P,
    pub org_key: &'a K,
    pub escrow: &'a E,
    pub requests: &'a R,
    pub usuarios: &'a U,
    pub claves: &'a C,
    pub secrets_key: &'a ClaveSecreta32,
    pub pool: &'a sqlx::PgPool,
    /// 2026-08-11: delegación de autoridad a admin de grupo (aprobar/
    /// rechazar/listar) — mismo patrón que `resources::service::eliminar`.
    pub roles: &'a RR,
    pub grupos: &'a GM,
    /// QA-06: challenges de `POST /auth/challenge` para la prueba de posesión.
    pub challenges: &'a CH,
    pub eventos: EmisorDeEventos,
}

/// Vida del código enviado al email de la cuenta: también es lo que dura
/// una solicitud sin confirmar.
const TTL_CONFIRMACION: Duration = Duration::minutes(15);
/// Vida de una solicitud ya confirmada: aprobarla y completarla tiene que
/// ocurrir dentro de esta ventana.
const TTL_SOLICITUD: Duration = Duration::hours(72);
/// Códigos incorrectos antes de que la solicitud quede vencida.
const MAX_INTENTOS_CONFIRMACION: i32 = 5;
/// Aprobaciones mínimas cuando ninguna viene de un admin de organización:
/// un solo manager de grupo nunca alcanza para entregar la clave de otro.
const UMBRAL_MINIMO_SIN_ADMIN_ORG: i32 = 2;

/// Tope del sellado de 32 o 64 bytes contra una X25519 (con holgura).
const MAX_SELLADO: usize = 512;

/// `GET /account-recovery/status`.
pub struct MiEstado {
    pub enrolled: bool,
    /// Clave contra la que está sellado el escrow propio.
    pub org_recovery_key_id: Option<i32>,
    /// Clave vigente: si difiere de la del escrow, el cliente re-sella.
    pub current_org_recovery_key_id: Option<i32>,
}

/// `GET /admin/account-recovery/custody`.
pub struct EstadoCustodia {
    pub vigente: Option<OrgRecoveryKey>,
    /// La privada vigente sellada para quien pregunta (si es custodio).
    pub mi_sobre: Option<Vec<u8>>,
    /// Admins sin copia de la vigente — todos, si la vigente no es de cliente.
    pub pendientes: Vec<CustodioPendiente>,
    /// Todos los admins de organización con claves: para quiénes se sella
    /// una clave nueva al generarla o rotarla.
    pub admins: Vec<CustodioPendiente>,
    /// Escrows todavía sellados contra la clave del servidor.
    pub escrows_en_servidor: i64,
}

fn validar_sellado(campo: &str, bytes: &[u8]) -> Result<(), DomainError> {
    if bytes.is_empty() || bytes.len() > MAX_SELLADO {
        return Err(DomainError::ValidacionInvalida(format!("{campo} tiene un largo inválido")));
    }
    Ok(())
}

/// Código de 8 dígitos — CSPRNG y sin sesgo (QA-41).
fn generar_codigo_confirmacion() -> String {
    ellkan_crypto::aleatoriedad::codigo_numerico(8)
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// El token del solicitante es la única credencial de las operaciones sin
/// sesión posteriores a la confirmación. Sin token, o con uno incorrecto, la
/// solicitud "no existe" (404), igual que un id inventado.
fn verificar_token(solicitud: &RecoveryRequest, token: &[u8]) -> Result<(), DomainError> {
    match &solicitud.requester_token_hash {
        Some(esperado) if secreto_coincide(esperado, &sha256(token)) => Ok(()),
        _ => Err(DomainError::NotFound),
    }
}

fn parsear_public_key_x25519(bytes: &[u8]) -> Result<X25519PublicKey, DomainError> {
    let arreglo: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DomainError::ValidacionInvalida("clave pública X25519 debe ser de 32 bytes".into()))?;
    Ok(X25519PublicKey::from(arreglo))
}

impl<'a, P, K, E, R, U, C, RR, GM, CH> AccountRecoveryService<'a, P, K, E, R, U, C, RR, GM, CH>
where
    P: AccountRecoveryPolicyRepository,
    K: OrgRecoveryKeyRepository,
    E: EscrowRepository,
    R: RecoveryRequestRepository,
    U: UserRepository,
    C: ClavePrivadaRepository,
    RR: RoleRepository,
    GM: GroupMemberRepository,
    CH: AuthChallengeRepository,
{
    /// `Ok((true, None))` si `admin_id` autoriza como admin de organización;
    /// `Ok((false, Some(group_id)))` si autoriza como admin de un grupo del
    /// solicitante; `PermissionDenied` si ninguna de las dos. Compartido
    /// entre `aprobar`/`rechazar`.
    ///
    /// QA-02: la autoridad delegada de un manager de grupo tiene límites
    /// estrictos, porque aprobar entrega la clave privada de otra persona:
    /// * nunca sobre la propia cuenta;
    /// * nunca sobre una cuenta con privilegio de organización (`*`);
    /// * la membresía del solicitante en ese grupo tiene que ser anterior a
    ///   la solicitud y no haberla dado de alta el propio aprobador (si no,
    ///   alcanzaría con agregar a la víctima al grupo y aprobar).
    async fn autorizar_gestion(
        &self,
        admin_id: Uuid,
        target_user_id: Uuid,
        solicitud_creada: OffsetDateTime,
    ) -> Result<(bool, Option<Uuid>), DomainError> {
        if admin_id == target_user_id {
            return Err(DomainError::PermissionDenied);
        }

        let es_admin_org = self.roles.usuario_tiene_permiso(admin_id, "*").await?;
        if es_admin_org {
            return Ok((true, None));
        }

        if self.roles.usuario_tiene_permiso(target_user_id, "*").await? {
            return Err(DomainError::PermissionDenied);
        }

        match self
            .grupos
            .grupo_administrado_con_membresia_previa(admin_id, target_user_id, solicitud_creada)
            .await?
        {
            Some(gid) => Ok((false, Some(gid))),
            None => Err(DomainError::PermissionDenied),
        }
    }

    pub async fn politica(&self) -> Result<AccountRecoveryPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar_politica(
        &self,
        actor_id: Uuid,
        required: bool,
        grace_period_days: i32,
        default_approval_threshold: i32,
    ) -> Result<AccountRecoveryPolicy, DomainError> {
        if grace_period_days < 0 {
            return Err(DomainError::ValidacionInvalida("grace_period_days no puede ser negativo".into()));
        }
        if default_approval_threshold < 1 {
            return Err(DomainError::ValidacionInvalida("default_approval_threshold debe ser al menos 1".into()));
        }

        let nueva = AccountRecoveryPolicy { required, grace_period_days, default_approval_threshold };
        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryPolicyUpdated, Some(actor_id)).con_metadata(serde_json::json!({
                "required": nueva.required,
                "grace_period_days": nueva.grace_period_days,
                "default_approval_threshold": nueva.default_approval_threshold,
            })),
        ));

        Ok(nueva)
    }

    /// El cliente necesita la clave pública organizacional vigente antes de
    /// poder enrolarse (sella su clave privada contra ella localmente).
    /// QA-09: el servidor ya no la genera; hasta que un admin la cree desde
    /// su navegador no hay recuperación por admin (404).
    pub async fn org_key_vigente(&self) -> Result<OrgRecoveryKey, DomainError> {
        self.org_key.vigente().await?.ok_or(DomainError::NotFound)
    }

    /// `GET /account-recovery/status` — la UI de "Mi cuenta" necesita saber
    /// si ya hay un escrow y si está sellado contra la clave vigente.
    pub async fn mi_estado(&self, user_id: Uuid) -> Result<MiEstado, DomainError> {
        let escrow = self.escrow.buscar_por_usuario(user_id).await?;
        let vigente = self.org_key.vigente().await?;
        Ok(MiEstado {
            enrolled: escrow.is_some(),
            org_recovery_key_id: escrow.map(|e| e.org_recovery_key_id),
            current_org_recovery_key_id: vigente.map(|k| k.id),
        })
    }

    /// `POST /account-recovery/enroll` (F-16) — el cliente ya selló su clave
    /// privada contra la pública organizacional `org_recovery_key_id`
    /// (`sealed_private_key_for_org`, bytes opacos para el servidor).
    /// Re-enrolar reemplaza el escrow anterior. QA-09: sólo contra la clave
    /// vigente (409 si rotó mientras tanto); si con esto ya no queda ningún
    /// escrow en la clave del servidor, se purga.
    pub async fn enrolar(
        &self,
        user_id: Uuid,
        sealed_private_key_for_org: Vec<u8>,
        org_recovery_key_id: i32,
    ) -> Result<Escrow, DomainError> {
        validar_sellado("sealed_private_key_for_org", &sealed_private_key_for_org)?;
        let vigente = self.org_key.vigente().await?.ok_or(DomainError::NotFound)?;
        if vigente.id != org_recovery_key_id {
            return Err(DomainError::Conflict);
        }
        let politica = self.policy.obtener().await?;

        let escrow = self
            .escrow
            .upsert(user_id, &sealed_private_key_for_org, vigente.id, politica.default_approval_threshold)
            .await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryEnrolled, Some(user_id))
                .con_sujeto("user", user_id)
                .con_metadata(serde_json::json!({ "org_recovery_key_id": vigente.id })),
        ));

        if vigente.custodia == Custodia::Cliente
            && self.org_key.escrows_en_servidor().await? == 0
            && self.org_key.servidor_tiene_privada().await?
        {
            self.org_key.purgar_servidor().await?;
            let _ = self.eventos.send(DomainEvent::Auditoria(
                EventoAuditoria::nuevo(AuditEventType::AccountRecoveryServerKeyPurged, None)
                    .con_metadata(serde_json::json!({ "escrows_borrados": 0, "automatico": true })),
            ));
        }

        Ok(escrow)
    }

    /// `GET /admin/account-recovery/custody` (QA-09) — lo que el navegador de
    /// un admin necesita para generar la clave, sumar custodios o ejecutar.
    pub async fn estado_custodia(&self, actor_id: Uuid) -> Result<EstadoCustodia, DomainError> {
        let vigente = self.org_key.vigente().await?;
        let (mi_sobre, pendientes) = match &vigente {
            Some(k) if k.custodia == Custodia::Cliente => {
                (self.org_key.sobre(k.id, actor_id).await?, self.org_key.custodios_pendientes(Some(k.id)).await?)
            }
            _ => (None, self.org_key.custodios_pendientes(None).await?),
        };
        Ok(EstadoCustodia {
            vigente,
            mi_sobre,
            pendientes,
            admins: self.org_key.custodios_pendientes(None).await?,
            escrows_en_servidor: self.org_key.escrows_en_servidor().await?,
        })
    }

    /// `POST /admin/account-recovery/org-keys` (QA-09) — alta de una clave
    /// generada en el navegador de `actor_id`, que pasa a ser la vigente. La
    /// privada llega sellada para cada custodio elegido; tiene que incluir
    /// al propio actor, y cada custodio tiene que ser admin de organización
    /// con claves. Sirve también para rotar.
    pub async fn crear_clave_de_cliente(&self, actor_id: Uuid, publica: Vec<u8>, sobres: Vec<(Uuid, Vec<u8>)>) -> Result<i32, DomainError> {
        parsear_public_key_x25519(&publica)?;
        if !sobres.iter().any(|(id, _)| *id == actor_id) {
            return Err(DomainError::ValidacionInvalida(
                "la clave tiene que quedar sellada también para quien la crea".into(),
            ));
        }
        let mut vistos = std::collections::HashSet::new();
        for (admin_id, sellado) in &sobres {
            if !vistos.insert(*admin_id) {
                return Err(DomainError::ValidacionInvalida("custodio repetido".into()));
            }
            validar_sellado("sealed_private_key", sellado)?;
            if self.org_key.x25519_de_admin(*admin_id).await?.is_none() {
                return Err(DomainError::ValidacionInvalida(
                    "cada custodio tiene que ser admin de organización con claves".into(),
                ));
            }
        }

        let id = self.org_key.crear_de_cliente(&publica, actor_id, &sobres).await?;
        let custodios: Vec<Uuid> = sobres.iter().map(|(id, _)| *id).collect();
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryOrgKeyCreated, Some(actor_id))
                .con_metadata(serde_json::json!({ "org_recovery_key_id": id, "custodians": custodios })),
        ));
        Ok(id)
    }

    /// `POST /admin/account-recovery/org-keys/{id}/envelopes` (QA-09) — un
    /// custodio de la clave vigente se la sella a otro admin de
    /// organización. Nunca automático: un operador que se agregue como admin
    /// en la base no recibe la clave hasta que un custodio lo confirme.
    pub async fn agregar_custodio(&self, actor_id: Uuid, key_id: i32, admin_id: Uuid, sellado: Vec<u8>) -> Result<(), DomainError> {
        validar_sellado("sealed_private_key", &sellado)?;
        let vigente = self.org_key.vigente().await?.ok_or(DomainError::NotFound)?;
        if vigente.id != key_id || vigente.custodia != Custodia::Cliente {
            return Err(DomainError::Conflict);
        }
        if self.org_key.sobre(key_id, actor_id).await?.is_none() {
            return Err(DomainError::PermissionDenied);
        }
        if self.org_key.x25519_de_admin(admin_id).await?.is_none() {
            return Err(DomainError::ValidacionInvalida("el custodio tiene que ser admin de organización con claves".into()));
        }
        if !self.org_key.agregar_sobre(key_id, admin_id, &sellado, actor_id).await? {
            return Err(DomainError::Conflict);
        }
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryCustodianAdded, Some(actor_id))
                .con_sujeto("user", admin_id)
                .con_metadata(serde_json::json!({ "org_recovery_key_id": key_id })),
        ));
        Ok(())
    }

    /// `DELETE /admin/account-recovery/server-key` (QA-09) — el admin decide
    /// no esperar a que todos re-sellen: se borra la privada que custodiaba
    /// el servidor y los escrows que seguían en ella (esos usuarios tienen
    /// que volver a habilitar la recuperación). Sólo con una clave de
    /// cliente vigente.
    pub async fn purgar_clave_servidor(&self, actor_id: Uuid) -> Result<i64, DomainError> {
        let vigente = self.org_key.vigente().await?.ok_or(DomainError::Conflict)?;
        if vigente.custodia != Custodia::Cliente {
            return Err(DomainError::Conflict);
        }
        let borrados = self.org_key.purgar_servidor().await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryServerKeyPurged, Some(actor_id))
                .con_metadata(serde_json::json!({ "escrows_borrados": borrados, "automatico": false })),
        ));
        Ok(borrados)
    }

    /// `POST /account-recovery/requests` — sin sesión, a propósito: cubre el
    /// caso central de F-16 (alguien perdió la passphrase y por eso no puede
    /// autenticarse de ningún otro modo). Identificado por email.
    ///
    /// QA-10: la solicitud nace `unconfirmed` y el código va al email de la
    /// cuenta; nadie más se entera hasta que se confirma. Responde lo mismo
    /// (un id) exista o no la cuenta o su escrow — en ese caso el id no
    /// corresponde a nada y ningún código lo va a confirmar (sección 2.2 de
    /// la guía de codificación segura).
    pub async fn crear_solicitud(&self, email: &str, requester_public_key_x25519: Vec<u8>) -> Result<Uuid, DomainError> {
        parsear_public_key_x25519(&requester_public_key_x25519)?;

        let Some(user) = self.usuarios.buscar_por_email(email).await? else {
            return Ok(Uuid::now_v7());
        };
        let Some(escrow) = self.escrow.buscar_por_usuario(user.id).await? else {
            return Ok(Uuid::now_v7());
        };
        let Some((email_cuenta, _nombre)) = self.usuarios.email_y_nombre(user.id).await? else {
            return Ok(Uuid::now_v7());
        };

        let codigo = generar_codigo_confirmacion();
        let solicitud = self
            .requests
            .crear(
                escrow.id,
                &requester_public_key_x25519,
                &sha256(codigo.as_bytes()),
                OffsetDateTime::now_utc() + TTL_CONFIRMACION,
            )
            .await?;

        let _ = self.eventos.send(DomainEvent::AccountRecoveryCodigoConfirmacion { email: email_cuenta, codigo });

        Ok(solicitud.id)
    }

    /// `POST /account-recovery/requests/{id}/confirm` — QA-10: quien pidió la
    /// recuperación demuestra que controla el email de la cuenta. Recién
    /// entonces la solicitud pasa a `pending`, se avisa a los admins y se
    /// entrega el token del solicitante (sólo su hash queda en la base).
    /// Cualquier falla (id inexistente, vencida, código incorrecto) responde
    /// igual.
    pub async fn confirmar_solicitud(&self, request_id: Uuid, codigo: &str) -> Result<[u8; 32], DomainError> {
        let solicitud = self.requests.buscar(request_id).await?.ok_or(DomainError::InvalidCredentials)?;
        if solicitud.status != "unconfirmed" || solicitud.vencida() {
            return Err(DomainError::InvalidCredentials);
        }
        let Some(esperado) = &solicitud.confirmation_code_hash else {
            return Err(DomainError::InvalidCredentials);
        };
        if !secreto_coincide(esperado, &sha256(codigo.trim().as_bytes())) {
            self.requests.registrar_intento_fallido(request_id, MAX_INTENTOS_CONFIRMACION).await?;
            return Err(DomainError::InvalidCredentials);
        }

        let token: [u8; 32] = bytes_aleatorios();
        let confirmada = self
            .requests
            .confirmar(request_id, &sha256(&token), OffsetDateTime::now_utc() + TTL_SOLICITUD)
            .await
            .map_err(|e| match e {
                // H-27: ya hay otra solicitud pendiente vigente para esta cuenta.
                crate::error::RepoError::Conflict => DomainError::Conflict,
                otro => DomainError::Interno(otro),
            })?;
        if !confirmada {
            return Err(DomainError::InvalidCredentials);
        }

        let escrow = self.escrow.buscar(solicitud.escrow_id).await?.ok_or(DomainError::NotFound)?;
        let (email_cuenta, _nombre) = self.usuarios.email_y_nombre(escrow.user_id).await?.ok_or(DomainError::NotFound)?;

        // 2026-08-11: notificación acotada a los admins del/los grupo(s) del
        // solicitante — fallback a admins de organización sólo si no
        // pertenece a ningún grupo.
        let grupos_del_requester = self.grupos.grupos_de(escrow.user_id).await?;
        let mut destinatarios: Vec<String> = Vec::new();
        for g in &grupos_del_requester {
            for m in self.grupos.miembros_de(g.group_id).await? {
                if m.is_admin && m.user_id != escrow.user_id {
                    destinatarios.push(m.email);
                }
            }
        }
        destinatarios.sort();
        destinatarios.dedup();
        if destinatarios.is_empty() {
            destinatarios = self.roles.listar_emails_con_permiso("*").await?;
        }
        let _ = self.eventos.send(DomainEvent::AccountRecoveryAdminNotify {
            request_id,
            target_email: email_cuenta,
            recipient_emails: destinatarios,
        });

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryRequested, None)
                .con_sujeto("account_recovery_request", request_id)
                .con_metadata(serde_json::json!({ "target_user_id": escrow.user_id })),
        ));

        Ok(token)
    }

    /// `GET /account-recovery/requests/{id}` — exige el token del
    /// solicitante. Una solicitud vencida se informa como `expired` y sin
    /// material.
    pub async fn estado_solicitud(&self, id: Uuid, token: &[u8]) -> Result<RecoveryRequest, DomainError> {
        let mut solicitud = self.requests.buscar(id).await?.ok_or(DomainError::NotFound)?;
        verificar_token(&solicitud, token)?;
        if solicitud.vencida() && matches!(solicitud.status.as_str(), "unconfirmed" | "pending" | "awaiting_custodian" | "approved") {
            solicitud.status = "expired".to_string();
            solicitud.sealed_private_key_for_requester = None;
        }
        Ok(solicitud)
    }

    /// `POST /admin/account-recovery/requests/{id}/approve` — idempotente
    /// por admin (aprobar dos veces no duplica su entrada). Al alcanzar el
    /// umbral: si el escrow está sellado contra una clave de cliente
    /// (QA-09), la solicitud queda `awaiting_custodian` y la re-sella un
    /// custodio (`ejecutar`); si es la clave anterior del servidor, el
    /// servidor la re-sella acá (`resellar_con_clave_de_servidor`).
    pub async fn aprobar(&self, admin_id: Uuid, request_id: Uuid) -> Result<RecoveryRequest, DomainError> {
        let mut tx = self.pool.begin().await.map_err(|e| DomainError::Interno(e.into()))?;

        let Some((solicitud, umbral)) = self.requests.bloquear_pendiente_con_umbral(request_id, &mut tx).await? else {
            return Err(DomainError::NotFound);
        };

        let escrow = self.escrow.buscar(solicitud.escrow_id).await?.ok_or(DomainError::NotFound)?;
        let (es_admin_org, authority_group_id) = self.autorizar_gestion(admin_id, escrow.user_id, solicitud.created_at).await?;

        let ya_aprobo = solicitud
            .approvals
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e.get("admin_id").and_then(|v| v.as_str()) == Some(&admin_id.to_string())));

        let nuevas_aprobaciones = if ya_aprobo {
            solicitud.approvals.clone()
        } else {
            let mut arreglo = solicitud.approvals.as_array().cloned().unwrap_or_default();
            arreglo.push(serde_json::json!({
                "admin_id": admin_id,
                "approved_at": OffsetDateTime::now_utc().to_string(),
                "authority": if es_admin_org { "org_admin" } else { "group_admin" },
            }));
            serde_json::Value::Array(arreglo)
        };

        let cantidad = nuevas_aprobaciones.as_array().map(|a| a.len()).unwrap_or(0) as i32;
        // QA-02: sin ninguna aprobación de un admin de organización, el
        // umbral efectivo nunca baja de `UMBRAL_MINIMO_SIN_ADMIN_ORG`. Las
        // aprobaciones sin `authority` (anteriores a este cambio) cuentan
        // como de grupo.
        let hay_admin_org = nuevas_aprobaciones
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e.get("authority").and_then(|v| v.as_str()) == Some("org_admin")));
        let umbral_efectivo = if hay_admin_org {
            umbral
        } else {
            umbral.max(UMBRAL_MINIMO_SIN_ADMIN_ORG)
        };
        self.requests.guardar_aprobaciones(request_id, nuevas_aprobaciones, &mut tx).await?;

        let umbral_alcanzado = cantidad >= umbral_efectivo;
        let mut espera_custodio = false;
        if umbral_alcanzado {
            let clave = self
                .org_key
                .buscar(escrow.org_recovery_key_id)
                .await?
                .ok_or(DomainError::Interno(crate::error::RepoError::Conflict))?;
            match clave.custodia {
                // QA-09: el servidor no puede abrir el escrow; lo re-sella el
                // navegador de un custodio (`ejecutar`).
                Custodia::Cliente => {
                    self.requests.marcar_esperando_custodio(request_id, &mut tx).await?;
                    espera_custodio = true;
                }
                Custodia::Servidor => {
                    let sellado_para_requester = self.resellar_con_clave_de_servidor(&clave, &escrow, &solicitud)?;
                    self.requests.marcar_aprobada(request_id, &sellado_para_requester, &mut tx).await?;
                }
            }
        }

        tx.commit().await.map_err(|e| DomainError::Interno(e.into()))?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryApproved, Some(admin_id))
                .con_sujeto("account_recovery_request", request_id)
                .con_metadata(serde_json::json!({
                    "threshold_reached": umbral_alcanzado,
                    "awaiting_custodian": espera_custodio,
                    "authority": if es_admin_org { "org_admin" } else { "group_admin" },
                    "group_id": authority_group_id,
                })),
        ));

        self.requests.buscar(request_id).await?.ok_or(DomainError::NotFound)
    }

    /// Escrow sellado contra la clave anterior a QA-09: el servidor lo
    /// desella con `secrets_key` y lo re-sella para el solicitante, con
    /// `zeroize` inmediato de los bytes en claro.
    fn resellar_con_clave_de_servidor(
        &self,
        clave: &OrgRecoveryKey,
        escrow: &Escrow,
        solicitud: &RecoveryRequest,
    ) -> Result<Vec<u8>, DomainError> {
        let interno = || DomainError::Interno(crate::error::RepoError::Conflict);
        let (Some(cifrada), Some(nonce)) = (&clave.encrypted_private_key, &clave.private_key_nonce) else {
            return Err(interno());
        };
        let nonce: [u8; 24] = nonce.as_slice().try_into().map_err(|_| interno())?;
        let envoltura = Envoltura { nonce, ciphertext: cifrada.clone() };
        let mut privada_org_bytes = aead::descifrar(self.secrets_key, &envoltura, b"org_recovery_key").map_err(|_| interno())?;
        let arreglo_privada: [u8; 32] = privada_org_bytes.as_slice().try_into().map_err(|_| interno())?;
        let privada_org = StaticSecret::from(arreglo_privada);
        privada_org_bytes.zeroize();

        let mut material_en_claro = sellado::abrir_bytes(&privada_org, &escrow.sealed_private_key_for_org).map_err(|_| interno())?;
        let publica_requester = parsear_public_key_x25519(&solicitud.requester_public_key_x25519)?;
        let sellado_para_requester = sellado::sellar_bytes(&publica_requester, &material_en_claro);
        material_en_claro.zeroize();
        Ok(sellado_para_requester)
    }

    /// Custodio que actúa sobre una solicitud ajena: admin de organización
    /// (nunca la propia, ver `autorizar_gestion`).
    async fn autorizar_custodio(&self, actor_id: Uuid, request_id: Uuid) -> Result<RecoveryRequest, DomainError> {
        let solicitud = self.requests.buscar(request_id).await?.ok_or(DomainError::NotFound)?;
        let escrow = self.escrow.buscar(solicitud.escrow_id).await?.ok_or(DomainError::NotFound)?;
        let (es_admin_org, _) = self.autorizar_gestion(actor_id, escrow.user_id, solicitud.created_at).await?;
        if !es_admin_org {
            return Err(DomainError::PermissionDenied);
        }
        Ok(solicitud)
    }

    /// `GET /admin/account-recovery/requests/{id}/custody-material` (QA-09)
    /// — el escrow (sellado para la clave org), la clave efímera del
    /// solicitante y la copia del custodio de esa clave. Sólo con la
    /// solicitud `awaiting_custodian` vigente y si `actor_id` es custodio de
    /// la clave del escrow.
    pub async fn material_para_custodio(&self, actor_id: Uuid, request_id: Uuid) -> Result<MaterialParaCustodio, DomainError> {
        self.autorizar_custodio(actor_id, request_id).await?;
        self.requests.material_para_custodio(request_id, actor_id).await?.ok_or(DomainError::NotFound)
    }

    /// `POST /admin/account-recovery/requests/{id}/execute` (QA-09) — el
    /// custodio ya re-selló el escrow para el solicitante en su navegador.
    /// El servidor no puede comprobar el contenido: si es basura, el
    /// solicitante no lo abre, y `complete` exige igual la prueba de
    /// posesión de la identidad (QA-06).
    pub async fn ejecutar(
        &self,
        actor_id: Uuid,
        request_id: Uuid,
        sellado_para_requester: Vec<u8>,
    ) -> Result<RecoveryRequest, DomainError> {
        validar_sellado("sealed_private_key_for_requester", &sellado_para_requester)?;
        self.material_para_custodio(actor_id, request_id).await?;
        if !self.requests.marcar_ejecutada(request_id, &sellado_para_requester).await? {
            return Err(DomainError::Conflict);
        }
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryExecuted, Some(actor_id))
                .con_sujeto("account_recovery_request", request_id),
        ));
        self.requests.buscar(request_id).await?.ok_or(DomainError::NotFound)
    }

    /// `POST /admin/account-recovery/requests/{id}/reject` — 2026-08-11,
    /// mismo gate de autoridad delegada que `aprobar` (`autorizar_gestion`);
    /// a diferencia de aprobar, no hay umbral ni desello: rechazar cierra el
    /// ciclo directo, cualquier admin autorizado alcanza.
    pub async fn rechazar(&self, admin_id: Uuid, request_id: Uuid) -> Result<RecoveryRequest, DomainError> {
        let solicitud = self.requests.buscar(request_id).await?.ok_or(DomainError::NotFound)?;
        let escrow = self.escrow.buscar(solicitud.escrow_id).await?.ok_or(DomainError::NotFound)?;
        let (es_admin_org, authority_group_id) = self.autorizar_gestion(admin_id, escrow.user_id, solicitud.created_at).await?;

        if !self.requests.marcar_rechazada(request_id).await? {
            return Err(DomainError::Conflict);
        }

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryRejected, Some(admin_id))
                .con_sujeto("account_recovery_request", request_id)
                .con_metadata(serde_json::json!({
                    "authority": if es_admin_org { "org_admin" } else { "group_admin" },
                    "group_id": authority_group_id,
                })),
        ));

        self.requests.buscar(request_id).await?.ok_or(DomainError::NotFound)
    }

    /// `POST /account-recovery/requests/{id}/complete` — el cliente ya
    /// desselló localmente el material con la privada de su clave efímera y
    /// fijó una passphrase nueva; acá se persiste esa clave nueva (reusando
    /// `me::service::CambiarPassphraseService`, misma validación de
    /// longitudes y misma rotación de `security_stamp` que
    /// `/me/change-passphrase`) y se cierra el ciclo de estado.
    ///
    /// QA-10: exige el token del solicitante y que la solicitud siga
    /// vigente. QA-06: exige también la prueba de posesión de la identidad
    /// desellada. Todo se valida ANTES de marcar `completed`, para que una
    /// entrada inválida no consuma la solicitud.
    pub async fn completar(
        &self,
        request_id: Uuid,
        token: &[u8],
        nueva: NuevaClavePrivada,
        prueba: &PruebaDePosesion,
    ) -> Result<(), DomainError> {
        let solicitud = self.requests.buscar(request_id).await?.ok_or(DomainError::NotFound)?;
        verificar_token(&solicitud, token)?;
        if solicitud.status != "approved" || solicitud.vencida() {
            return Err(DomainError::Conflict);
        }
        let escrow = self.escrow.buscar(solicitud.escrow_id).await?.ok_or(DomainError::NotFound)?;
        let verificado = verificar_posesion(self.usuarios, self.challenges, escrow.user_id, nueva, prueba).await?;

        if !self.requests.marcar_completada(request_id).await? {
            return Err(DomainError::Conflict);
        }

        let cambio = CambiarPassphraseService { claves: self.claves, eventos: self.eventos.clone() };
        cambio.actualizar(verificado).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::AccountRecoveryCompleted, Some(escrow.user_id))
                .con_sujeto("account_recovery_request", request_id),
        ));

        Ok(())
    }

    /// `GET /admin/account-recovery/requests` — el id de una solicitud sólo
    /// lo conoce quien la creó; sin este listado un admin no tiene forma de
    /// enterarse de que hay algo para aprobar. 2026-08-11: acotado por
    /// visibilidad — un admin de grupo sólo ve las de usuarios que
    /// comparten alguno de sus grupos administrados.
    pub async fn listar_pendientes(&self, actor_id: Uuid) -> Result<Vec<SolicitudPendiente>, DomainError> {
        let es_admin_org = self.roles.usuario_tiene_permiso(actor_id, "*").await?;
        let grupos_administrados = if es_admin_org {
            Vec::new()
        } else {
            self.grupos.grupos_administrados_por(actor_id).await?
        };
        Ok(self.requests.listar_pendientes_visibles(es_admin_org, &grupos_administrados).await?)
    }
}
