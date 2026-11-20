// Autor: Athan Espinoza

//! Revocación remota (docs/revocacion-remota.md): cuando un admin bloquea o
//! purga una cuenta, las apps de escritorio vinculadas a ella borran su
//! bóveda local. Borrar es irreversible, así que la app NUNCA lo hace por
//! inferencia (un 401, un servidor caído): sólo ante un aviso FIRMADO con la
//! clave Ed25519 del servidor (`server_keys`), que la app fijó al vincularse.
//!
//! Dos caminos para que el aviso llegue:
//! - En vivo: un consumidor del bus de eventos ve la desactivación o la
//!   purga, firma el aviso y lo publica en el canal de `GET /sync/eventos`
//!   (`sync::avisos`), que se lo manda a la app y cierra la conexión.
//! - Para la app que estaba sin red: `POST /auth/estado-cuenta`. Sin sesión
//!   (una cuenta revocada ya no puede tener una), pero sólo responde algo útil
//!   a quien demuestra ser dueño de las claves de la cuenta, firmando la
//!   pregunta con su clave Ed25519: a un extraño le contesta lo mismo que a
//!   una cuenta que no existe, así que no rompe la anti-enumeración.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::secretos::ClaveSecreta32;
use zeroize::Zeroize;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::b64;
use crate::error::{ApiError, RepoError};
use crate::eventos::{DomainEvent, EmisorDeEventos, recibir_tolerando_lag};
use crate::state::AppState;
use crate::sync::avisos::{AvisoSync, CanalAvisos};

/// Aviso firmado tal como viaja: `aviso` es el JSON exacto que se firmó (la
/// app verifica la firma sobre esos bytes y recién después lo interpreta, así
/// no depende de cómo se re-serialice).
#[derive(Debug, Clone, Serialize)]
pub struct AvisoFirmado {
    pub aviso: String,
    pub firma_b64: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Motivo {
    Bloqueada,
    Purgada,
}

impl Motivo {
    fn as_str(self) -> &'static str {
        match self {
            Motivo::Bloqueada => "deactivated",
            Motivo::Purgada => "purged",
        }
    }
}

#[derive(Serialize)]
struct CuerpoAviso<'a> {
    tipo: &'static str,
    user_id: Uuid,
    /// `None` en una cuenta purgada: el servidor ya no guarda su correo.
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    motivo: &'static str,
    emitido_en: String,
}

fn ahora_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("formato de fecha válido")
}

/// QA-37: AAD de la privada Ed25519 del servidor cifrada con `secrets_key`.
pub(crate) const AAD_SERVER_KEY: &[u8] = b"server_key";

/// QA-37: `nonce (24) || ciphertext` — formato de `server_keys.private_key_ed25519`.
pub(crate) fn cifrar_clave_del_servidor(clave: &ClaveSecreta32, privada: &[u8]) -> anyhow::Result<Vec<u8>> {
    let envoltura =
        aead::cifrar(clave, privada, AAD_SERVER_KEY).map_err(|_| anyhow::anyhow!("no se pudo cifrar la clave privada del servidor"))?;
    let mut almacenada = envoltura.nonce.to_vec();
    almacenada.extend_from_slice(&envoltura.ciphertext);
    Ok(almacenada)
}

fn error_de_clave(motivo: &'static str) -> RepoError {
    RepoError::Database(sqlx::Error::Decode(motivo.into()))
}

/// Sólo acepta el formato cifrado: `cargar_o_generar_server_key` migra al
/// arrancar cualquier fila en claro de una versión anterior.
async fn clave_del_servidor(pool: &PgPool, clave: &ClaveSecreta32) -> Result<SigningKey, RepoError> {
    let almacenada: Vec<u8> = sqlx::query_scalar("select private_key_ed25519 from server_keys where id = 1")
        .fetch_one(pool)
        .await?;
    if almacenada.len() <= 24 {
        return Err(error_de_clave("clave privada del servidor sin cifrar o truncada"));
    }
    let (nonce, ciphertext) = almacenada.split_at(24);
    let envoltura = Envoltura {
        nonce: nonce.try_into().map_err(|_| error_de_clave("nonce de la clave del servidor inválido"))?,
        ciphertext: ciphertext.to_vec(),
    };
    let mut privada = aead::descifrar(clave, &envoltura, AAD_SERVER_KEY)
        .map_err(|_| error_de_clave("no se pudo descifrar la clave privada del servidor"))?;
    let bytes: Result<[u8; 32], _> = privada.as_slice().try_into();
    privada.zeroize();
    let mut bytes = bytes.map_err(|_| error_de_clave("clave privada del servidor con largo inválido"))?;
    let firmante = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(firmante)
}

/// Arma y firma el aviso de cuenta revocada.
pub async fn firmar_aviso(
    pool: &PgPool,
    clave: &ClaveSecreta32,
    user_id: Uuid,
    email: Option<&str>,
    motivo: Motivo,
) -> Result<AvisoFirmado, RepoError> {
    let cuerpo = CuerpoAviso {
        tipo: "cuenta_revocada",
        user_id,
        email,
        motivo: motivo.as_str(),
        emitido_en: ahora_rfc3339(),
    };
    let aviso = serde_json::to_string(&cuerpo).expect("serializar el aviso no falla");
    let firma = clave_del_servidor(pool, clave).await?.sign(aviso.as_bytes());
    Ok(AvisoFirmado { aviso, firma_b64: b64::encode(&firma.to_bytes()) })
}

/// Escucha bloqueos y purgas en el bus de eventos (desde el panel de admin,
/// SCIM o directory sync) y publica el aviso firmado para las apps conectadas.
pub fn spawn_consumidor(eventos: &EmisorDeEventos, pool: PgPool, clave: Arc<ClaveSecreta32>, avisos: CanalAvisos) {
    let mut receptor = eventos.subscribe();
    let emisor = eventos.clone();
    tokio::spawn(async move {
        while let Some(evento) = recibir_tolerando_lag(&mut receptor, "revocacion").await {
            let DomainEvent::Auditoria(entrada) = evento else { continue };
            let Some(user_id) = entrada.subject_id.filter(|_| entrada.subject_type == Some("user")) else {
                continue;
            };
            let resultado = match entrada.event_type {
                AuditEventType::UserDeactivated | AuditEventType::ScimUserDeactivated => avisar_bloqueada(&pool, &clave, user_id).await,
                AuditEventType::UserPurged => avisar_purgada(&pool, &clave, user_id).await,
                _ => continue,
            };
            match resultado {
                Ok(Some(aviso)) => {
                    let _ = avisos.send(AvisoSync::Revocada { user_id, aviso: Arc::new(aviso) });
                    let _ = emisor.send(DomainEvent::Auditoria(
                        EventoAuditoria::nuevo(AuditEventType::UserRemoteWipeSignaled, entrada.actor_user_id).con_sujeto("user", user_id),
                    ));
                }
                Ok(None) => {}
                Err(e) => tracing::error!(%user_id, error = %e, "no se pudo emitir el aviso de cuenta revocada"),
            }
        }
    });
}

/// `None` si la cuenta ya no está bloqueada (la reactivaron enseguida).
async fn avisar_bloqueada(pool: &PgPool, clave: &ClaveSecreta32, user_id: Uuid) -> Result<Option<AvisoFirmado>, RepoError> {
    let fila = sqlx::query("select email, active from users where id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    let Some(fila) = fila else { return Ok(None) };
    if fila.get::<bool, _>("active") {
        return Ok(None);
    }
    let email: String = fila.get("email");
    Ok(Some(firmar_aviso(pool, clave, user_id, Some(&email), Motivo::Bloqueada).await?))
}

async fn avisar_purgada(pool: &PgPool, clave: &ClaveSecreta32, user_id: Uuid) -> Result<Option<AvisoFirmado>, RepoError> {
    let registrada: bool = sqlx::query_scalar("select exists(select 1 from cuentas_revocadas where user_id = $1)")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    if !registrada {
        return Ok(None);
    }
    Ok(Some(firmar_aviso(pool, clave, user_id, None, Motivo::Purgada).await?))
}

// ---------------------------------------------------------------------------
// POST /auth/estado-cuenta
// ---------------------------------------------------------------------------

/// Cuánto puede diferir `emitido_en` del reloj del servidor.
const TOLERANCIA_RELOJ: time::Duration = time::Duration::minutes(10);

/// Texto que firma la app con la clave Ed25519 de la cuenta. El prefijo fijo
/// impide reusar como prueba la firma de otra cosa (por ejemplo, el nonce del login).
pub fn mensaje_estado_cuenta(email: &str, public_key_b64: &str, emitido_en: &str) -> String {
    format!("ellkan:estado-cuenta:v1\n{email}\n{public_key_b64}\n{emitido_en}")
}

#[derive(Debug, Deserialize)]
pub struct EstadoCuentaRequest {
    pub email: String,
    pub public_key_ed25519_b64: String,
    pub emitido_en: String,
    pub firma_b64: String,
}

#[derive(Debug, Serialize)]
pub struct EstadoCuentaResponse {
    /// `activa` | `revocada` | `desconocida` (también la respuesta a una firma inválida).
    pub estado: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aviso: Option<AvisoFirmado>,
}

const DESCONOCIDA: EstadoCuentaResponse = EstadoCuentaResponse { estado: "desconocida", aviso: None };

/// Comprueba la firma de la pregunta. `None` = no prueba nada (se responde
/// "desconocida", igual que para una cuenta que no existe).
fn verificar_pregunta(req: &EstadoCuentaRequest) -> Option<Vec<u8>> {
    let publica = b64::decode(&req.public_key_ed25519_b64).ok()?;
    let clave = VerifyingKey::from_bytes(&<[u8; 32]>::try_from(publica.as_slice()).ok()?).ok()?;
    let firma = Signature::from_bytes(&<[u8; 64]>::try_from(b64::decode(&req.firma_b64).ok()?.as_slice()).ok()?);
    let emitido = OffsetDateTime::parse(&req.emitido_en, &time::format_description::well_known::Rfc3339).ok()?;
    if (OffsetDateTime::now_utc() - emitido).abs() > TOLERANCIA_RELOJ {
        return None;
    }
    let mensaje = mensaje_estado_cuenta(&req.email, &req.public_key_ed25519_b64, &req.emitido_en);
    clave.verify(mensaje.as_bytes(), &firma).ok()?;
    Some(publica)
}

pub async fn estado_cuenta(
    State(state): State<AppState>,
    Json(req): Json<EstadoCuentaRequest>,
) -> Result<Json<EstadoCuentaResponse>, ApiError> {
    let Some(publica) = verificar_pregunta(&req) else {
        return Ok(Json(DESCONOCIDA));
    };
    let pool = &state.pool;
    let repo = |e: sqlx::Error| ApiError::from(crate::error::DomainError::from(RepoError::Database(e)));

    // La cuenta con ese correo Y esas claves (el correo solo no alcanza: tras
    // una purga, otra persona pudo crear una cuenta nueva con el mismo correo).
    let fila = sqlx::query(
        "select u.id, u.email, u.active from users u join user_keys k on k.user_id = u.id
         where lower(u.email) = lower($1) and k.public_key_ed25519 = $2",
    )
    .bind(req.email.trim())
    .bind(&publica)
    .fetch_optional(pool)
    .await
    .map_err(repo)?;

    if let Some(fila) = fila {
        if fila.get::<bool, _>("active") {
            return Ok(Json(EstadoCuentaResponse { estado: "activa", aviso: None }));
        }
        let user_id: Uuid = fila.get("id");
        let email: String = fila.get("email");
        let aviso = firmar_aviso(pool, &state.secrets_key, user_id, Some(&email), Motivo::Bloqueada)
            .await
            .map_err(|e| ApiError::from(crate::error::DomainError::from(e)))?;
        return Ok(Json(EstadoCuentaResponse { estado: "revocada", aviso: Some(aviso) }));
    }

    let purgada: Option<Uuid> = sqlx::query_scalar("select user_id from cuentas_revocadas where public_key_ed25519 = $1")
        .bind(&publica)
        .fetch_optional(pool)
        .await
        .map_err(repo)?;
    if let Some(user_id) = purgada {
        let aviso = firmar_aviso(pool, &state.secrets_key, user_id, None, Motivo::Purgada)
            .await
            .map_err(|e| ApiError::from(crate::error::DomainError::from(e)))?;
        return Ok(Json(EstadoCuentaResponse { estado: "revocada", aviso: Some(aviso) }));
    }

    Ok(Json(DESCONOCIDA))
}
