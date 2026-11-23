// Autor: Athan Espinoza

use axum::Json;
use axum::extract::{Path, State};
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::b64;
use crate::error::ApiError;
use crate::state::AppState;
use crate::validacion;

use super::dto::{AgregarDestinatarioRequest, CrearMetadataKeyRequest, DestinatarioEnvelope, MetadataKeyResponse, RotationStatusResponse};
use super::service::MetadataKeyService;

type Servicio<'a> = MetadataKeyService<'a, super::repository::PgMetadataKeyRepository, super::repository::PgMetadataKeyEnvelopeRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    MetadataKeyService {
        claves: &state.claves_metadata,
        envelopes: &state.envelopes_metadata,
        eventos: state.eventos.clone(),
    }
}

pub async fn listar(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Json<Vec<MetadataKeyResponse>>, ApiError> {
    let servicio = servicio(&state);
    let activas = servicio.activas().await?;

    let mut respuesta = Vec::with_capacity(activas.len());
    for clave in activas {
        let propio = servicio.envelope_propio(clave.id, auth.user_id).await?;
        respuesta.push(MetadataKeyResponse {
            id: clave.id,
            public_key_x25519_b64: b64::encode(&clave.public_key_x25519),
            fingerprint: clave.fingerprint,
            expired_at: clave.expired_at,
            own_sealed_private_key_b64: propio.map(|p| b64::encode(&p)),
        });
    }
    Ok(Json(respuesta))
}

fn decodificar_destinatarios(destinatarios: Vec<DestinatarioEnvelope>) -> Result<Vec<(uuid::Uuid, Vec<u8>)>, ApiError> {
    let mut resultado = Vec::with_capacity(destinatarios.len());
    for d in destinatarios {
        let sellado = validacion::b64_exacto(&d.sealed_private_key_b64, "sealed_private_key_b64", validacion::LARGO_CLAVE_SELLADA)?;
        resultado.push((d.user_id, sellado));
    }
    Ok(resultado)
}

pub async fn crear(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CrearMetadataKeyRequest>,
) -> Result<Json<MetadataKeyResponse>, ApiError> {
    let public_key = validacion::b64_exacto(&req.public_key_x25519_b64, "public_key_x25519_b64", validacion::LARGO_CLAVE_PUBLICA)?;
    let destinatarios = decodificar_destinatarios(req.destinatarios)?;

    let clave = servicio(&state)
        .crear_clave_compartida(admin.user_id, req.id, &public_key, &req.fingerprint, destinatarios)
        .await?;

    Ok(Json(MetadataKeyResponse {
        id: clave.id,
        public_key_x25519_b64: b64::encode(&clave.public_key_x25519),
        fingerprint: clave.fingerprint,
        expired_at: clave.expired_at,
        own_sealed_private_key_b64: None,
    }))
}

/// `POST /admin/metadata-keys/{id}/members` — agrega un destinatario a una
/// key ya activa sin rotarla. El caller ya abrió su propia
/// `own_sealed_private_key_b64` (`GET /metadata-keys`) y la reselló para el
/// destinatario nuevo — el backend sólo persiste el envelope.
pub async fn agregar_destinatario(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(metadata_key_id): Path<Uuid>,
    Json(req): Json<AgregarDestinatarioRequest>,
) -> Result<(), ApiError> {
    let sealed = validacion::b64_exacto(&req.sealed_private_key_b64, "sealed_private_key_b64", validacion::LARGO_CLAVE_SELLADA)?;

    servicio(&state).agregar_destinatario(admin.user_id, metadata_key_id, req.user_id, &sealed).await?;

    Ok(())
}

pub async fn rotar(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CrearMetadataKeyRequest>,
) -> Result<Json<MetadataKeyResponse>, ApiError> {
    let public_key = validacion::b64_exacto(&req.public_key_x25519_b64, "public_key_x25519_b64", validacion::LARGO_CLAVE_PUBLICA)?;
    let destinatarios = decodificar_destinatarios(req.destinatarios)?;

    let entrante = servicio(&state)
        .iniciar_rotacion(admin.user_id, req.id, &public_key, &req.fingerprint, destinatarios)
        .await?;

    Ok(Json(MetadataKeyResponse {
        id: entrante.id,
        public_key_x25519_b64: b64::encode(&entrante.public_key_x25519),
        fingerprint: entrante.fingerprint,
        expired_at: entrante.expired_at,
        own_sealed_private_key_b64: None,
    }))
}

pub async fn rotation_status(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<RotationStatusResponse>, ApiError> {
    let estado = servicio(&state).estado_rotacion().await?;
    Ok(Json(RotationStatusResponse {
        activa: estado.activa,
        saliente_id: estado.saliente_id,
        entrante_id: estado.entrante_id,
        total_al_iniciar: estado.total_al_iniciar,
        pendientes: estado.pendientes,
    }))
}
