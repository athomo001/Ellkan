// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarPasswordPolicyRequest, PasswordPolicyResponse};
use super::models::PasswordPolicy;
use super::repository::PgPasswordPolicyRepository;
use super::service::PasswordPolicyService;

type Servicio<'a> = PasswordPolicyService<'a, PgPasswordPolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    PasswordPolicyService { policy: &state.password_policy, eventos: state.eventos.clone() }
}

fn a_response(p: PasswordPolicy) -> PasswordPolicyResponse {
    PasswordPolicyResponse {
        min_passphrase_length: p.min_passphrase_length,
        min_passphrase_entropy_bits: p.min_passphrase_entropy_bits,
        passphrase_rotation_days: p.passphrase_rotation_days,
        generator_default_length: p.generator_default_length,
        generator_charset_rules: p.generator_charset_rules,
        max_clipboard_clear_minutes: p.max_clipboard_clear_minutes,
        max_auto_lock_minutes: p.max_auto_lock_minutes,
    }
}

/// Lectura: cualquier usuario autenticado, no sólo admin — la política
/// (longitud/charset del generador, entropía mínima) no es secreta, y el
/// cliente la necesita para generar una contraseña conforme y para validar
/// la propia passphrase client-side. Sólo la escritura (`actualizar_politica`
/// abajo) sigue exigiendo `AdminUser`.
pub async fn politica(
    State(state): State<AppState>,
    _usuario: AuthenticatedUser,
) -> Result<Json<PasswordPolicyResponse>, ApiError> {
    let p = servicio(&state).obtener().await?;
    Ok(Json(a_response(p)))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarPasswordPolicyRequest>,
) -> Result<Json<PasswordPolicyResponse>, ApiError> {
    let nueva = PasswordPolicy {
        min_passphrase_length: req.min_passphrase_length,
        min_passphrase_entropy_bits: req.min_passphrase_entropy_bits,
        passphrase_rotation_days: req.passphrase_rotation_days,
        generator_default_length: req.generator_default_length,
        generator_charset_rules: req.generator_charset_rules,
        max_clipboard_clear_minutes: req.max_clipboard_clear_minutes,
        max_auto_lock_minutes: req.max_auto_lock_minutes,
    };
    let p = servicio(&state).actualizar(admin.user_id, nueva).await?;
    Ok(Json(a_response(p)))
}
