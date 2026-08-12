// Autor: Athan Espinoza

//! Cliente HTTP contra el backend — la CLI reusa `ellkan-crypto` nativo
//! (mismo workspace) y nunca manda a la red nada que no esté ya
//! cifrado/sellado client-side.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct Cliente {
    http: reqwest::blocking::Client,
    base_url: String,
}

/// mTLS opcional (F-35, `GetHTTPClient` de `go-passbolt-cli`): certificado y
/// clave privada de cliente, todo o nada — nunca uno sin el otro.
pub struct OpcionesMtls {
    pub client_cert_path: String,
    pub client_key_path: String,
    pub ca_bundle_path: Option<String>,
}

/// Rechaza redirects cross-host/cross-scheme (F-35, `CheckRedirect`): sin
/// esto, un redirect malicioso podría filtrar el `Authorization: Bearer` a un
/// host distinto del configurado como servidor.
fn checar_redirect(intento: reqwest::redirect::Attempt) -> reqwest::redirect::Action {
    const MAX_REDIRECTS: usize = 10;
    if intento.previous().len() > MAX_REDIRECTS {
        return intento.error("demasiados redirects".to_string());
    }
    // `previous()[0]` es la URL original de la solicitud — la comparación es
    // siempre contra ese origen, no contra el salto anterior, para que una
    // cadena de redirects "válidos" uno a uno no termine deslizando el host.
    let original = intento.previous()[0].clone();
    let destino = intento.url().clone();
    if destino.scheme() != original.scheme() || destino.host_str() != original.host_str() {
        return intento.error(format!("redirect cross-host/cross-scheme rechazado: {original} -> {destino}"));
    }
    intento.follow()
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    email: &'a str,
    display_name: &'a str,
    public_key_x25519_b64: &'a str,
    public_key_ed25519_b64: &'a str,
    encrypted_private_key_blob_b64: &'a str,
    private_key_nonce_b64: &'a str,
    kdf_salt_b64: &'a str,
}

#[derive(Deserialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
}

#[derive(Serialize)]
struct ChallengeRequest<'a> {
    email: &'a str,
}

#[derive(Deserialize)]
pub struct ChallengeResponse {
    pub nonce_b64: String,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    email: &'a str,
    nonce_b64: &'a str,
    signature_b64: &'a str,
    device_token_hash_b64: &'a str,
}

#[derive(Deserialize)]
pub struct VerifyResponse {
    pub estado: String,
    pub session_id: Option<Uuid>,
    #[allow(dead_code)]
    pub user_id: Option<Uuid>,
    pub device_challenge_id: Option<Uuid>,
}

#[derive(Serialize)]
struct VerifyDeviceRequest {
    device_challenge_id: Uuid,
    code: String,
}

#[derive(Deserialize)]
pub struct VerifyDeviceResponse {
    pub session_id: Uuid,
    #[allow(dead_code)]
    pub user_id: Uuid,
}

/// F-24: faltaba por completo en la CLI — `register` nunca llama a esto,
/// así que en cualquier instancia que no sea el bootstrap (self-registration
/// con verificación de email activa) una cuenta creada por `ellkan-cli
/// register`/`admin create-user` quedaba sin forma de completar el alta
/// desde la propia CLI. Hallazgo real, 2026-08-11.
#[derive(Serialize)]
struct VerifyEmailRequest<'a> {
    email: &'a str,
    code: &'a str,
}

#[derive(Serialize)]
pub struct CambiarPassphraseRequest {
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
}

#[derive(Deserialize)]
pub struct PublicKeyResponse {
    pub user_id: Uuid,
    pub public_key_x25519_b64: String,
}

#[derive(Serialize)]
pub struct CrearRecursoRequest {
    pub id: Uuid,
    pub resource_type_slug: String,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
}

#[derive(Deserialize)]
pub struct RecursoResponse {
    pub id: Uuid,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub created_by: Uuid,
}

#[derive(Deserialize)]
pub struct SecretoResponse {
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
}

#[derive(Serialize)]
pub struct CompartirRequest {
    pub recipient_user_id: Uuid,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
    pub level: Option<String>,
}

/// F-12, 2026-08-12: la CLI no tenía ningún comando de grupos — hallazgo de
/// auditoría real (sesión de seeding de usuarios de prueba). `id` es
/// client-generado, mismo criterio que `CrearRecursoRequest`.
#[derive(Serialize)]
pub struct CrearGrupoRequest {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct MiembroGrupoResponse {
    pub user_id: Uuid,
    pub is_admin: bool,
    pub email: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct GrupoResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
    #[serde(default)]
    pub members: Vec<MiembroGrupoResponse>,
}

/// `envelopes` queda siempre vacío — alcanza para un grupo que todavía no
/// comparte recursos (caso normal al armar un grupo nuevo). Si el grupo ya
/// comparte algo, el backend rechaza el alta pidiendo los envelopes
/// correspondientes (mismo criterio que ya documentaba `service.rs`); sellar
/// una DEK ajena por cada recurso ya compartido del grupo queda fuera de
/// alcance de este comando.
#[derive(Serialize)]
struct AgregarMiembroGrupoRequest {
    is_admin: bool,
    envelopes: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorDetalle,
}

#[derive(Deserialize)]
struct ErrorDetalle {
    code: String,
    message: String,
}

fn a_resultado<T: serde::de::DeserializeOwned>(resp: reqwest::blocking::Response) -> anyhow::Result<T> {
    let status = resp.status();
    let texto = resp.text()?;
    if status.is_success() {
        Ok(serde_json::from_str(&texto)?)
    } else if let Ok(env) = serde_json::from_str::<ErrorEnvelope>(&texto) {
        anyhow::bail!("{} ({}): {}", env.error.code, status, env.error.message)
    } else {
        anyhow::bail!("error HTTP {status}: {texto}")
    }
}

impl Cliente {
    pub fn nuevo(base_url: String, mtls: Option<OpcionesMtls>) -> anyhow::Result<Self> {
        let mut builder = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::custom(checar_redirect));

        if let Some(opciones) = mtls {
            let mut pem = std::fs::read(&opciones.client_cert_path)
                .map_err(|e| anyhow::anyhow!("no se pudo leer --client-cert ({}): {e}", opciones.client_cert_path))?;
            let mut clave = std::fs::read(&opciones.client_key_path)
                .map_err(|e| anyhow::anyhow!("no se pudo leer --client-key ({}): {e}", opciones.client_key_path))?;
            pem.append(&mut clave);
            let identidad = reqwest::Identity::from_pem(&pem)
                .map_err(|e| anyhow::anyhow!("certificado/clave de cliente inválidos: {e}"))?;
            builder = builder.identity(identidad);

            if let Some(ca_ruta) = &opciones.ca_bundle_path {
                let ca_pem = std::fs::read(ca_ruta)
                    .map_err(|e| anyhow::anyhow!("no se pudo leer --ca-bundle ({ca_ruta}): {e}"))?;
                let ca = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| anyhow::anyhow!("CA bundle inválido: {e}"))?;
                builder = builder.add_root_certificate(ca);
            }
        }

        Ok(Self { http: builder.build()?, base_url })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &self,
        email: &str,
        display_name: &str,
        public_key_x25519_b64: &str,
        public_key_ed25519_b64: &str,
        encrypted_private_key_blob_b64: &str,
        private_key_nonce_b64: &str,
        kdf_salt_b64: &str,
    ) -> anyhow::Result<RegisterResponse> {
        let resp = self
            .http
            .post(format!("{}/auth/register", self.base_url))
            .json(&RegisterRequest {
                email,
                display_name,
                public_key_x25519_b64,
                public_key_ed25519_b64,
                encrypted_private_key_blob_b64,
                private_key_nonce_b64,
                kdf_salt_b64,
            })
            .send()?;
        a_resultado(resp)
    }

    pub fn challenge(&self, email: &str) -> anyhow::Result<ChallengeResponse> {
        let resp = self
            .http
            .post(format!("{}/auth/challenge", self.base_url))
            .json(&ChallengeRequest { email })
            .send()?;
        a_resultado(resp)
    }

    pub fn verify(
        &self,
        email: &str,
        nonce_b64: &str,
        signature_b64: &str,
        device_token_hash_b64: &str,
    ) -> anyhow::Result<VerifyResponse> {
        let resp = self
            .http
            .post(format!("{}/auth/verify", self.base_url))
            .json(&VerifyRequest { email, nonce_b64, signature_b64, device_token_hash_b64 })
            .send()?;
        a_resultado(resp)
    }

    pub fn verify_device(&self, device_challenge_id: Uuid, code: &str) -> anyhow::Result<VerifyDeviceResponse> {
        let resp = self
            .http
            .post(format!("{}/auth/verify-device", self.base_url))
            .json(&VerifyDeviceRequest { device_challenge_id, code: code.to_string() })
            .send()?;
        a_resultado(resp)
    }

    pub fn verify_email(&self, email: &str, code: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/auth/verify-email", self.base_url))
            .json(&VerifyEmailRequest { email, code })
            .send()?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let texto = resp.text()?;
            anyhow::bail!("error HTTP {status}: {texto}")
        }
    }

    /// 2026-08-11: usado por `login()` cuando `/auth/verify` devuelve
    /// `requiere_cambiar_passphrase` (cuenta creada por un admin con
    /// passphrase provisoria) — misma sesión parcial que ya trae `verify`,
    /// server-side acepta `SesionValida` para este endpoint a propósito.
    pub fn change_passphrase(&self, session_id: Uuid, req: &CambiarPassphraseRequest) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/me/change-passphrase", self.base_url))
            .bearer_auth(session_id)
            .json(req)
            .send()?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let texto = resp.text()?;
            anyhow::bail!("error HTTP {status}: {texto}")
        }
    }

    pub fn public_key(&self, session_id: Uuid, email: &str) -> anyhow::Result<PublicKeyResponse> {
        let resp = self
            .http
            .get(format!("{}/users/{}/public-key", self.base_url, email))
            .bearer_auth(session_id)
            .send()?;
        a_resultado(resp)
    }

    pub fn listar_recursos(&self, session_id: Uuid) -> anyhow::Result<Vec<RecursoResponse>> {
        let resp = self
            .http
            .get(format!("{}/resources", self.base_url))
            .bearer_auth(session_id)
            .send()?;
        a_resultado(resp)
    }

    pub fn crear_recurso(&self, session_id: Uuid, req: &CrearRecursoRequest) -> anyhow::Result<RecursoResponse> {
        let resp = self
            .http
            .post(format!("{}/resources", self.base_url))
            .bearer_auth(session_id)
            .json(req)
            .send()?;
        a_resultado(resp)
    }

    pub fn obtener_recurso(&self, session_id: Uuid, id: Uuid) -> anyhow::Result<RecursoResponse> {
        let resp = self
            .http
            .get(format!("{}/resources/{}", self.base_url, id))
            .bearer_auth(session_id)
            .send()?;
        a_resultado(resp)
    }

    pub fn obtener_secreto(&self, session_id: Uuid, id: Uuid) -> anyhow::Result<SecretoResponse> {
        let resp = self
            .http
            .get(format!("{}/resources/{}/secret", self.base_url, id))
            .bearer_auth(session_id)
            .send()?;
        a_resultado(resp)
    }

    pub fn compartir(&self, session_id: Uuid, id: Uuid, req: &CompartirRequest) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/resources/{}/share", self.base_url, id))
            .bearer_auth(session_id)
            .json(req)
            .send()?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let texto = resp.text()?;
            anyhow::bail!("error HTTP {status}: {texto}")
        }
    }

    pub fn healthz(&self) -> anyhow::Result<String> {
        let resp = self.http.get(format!("{}/healthz", self.base_url)).send()?;
        Ok(resp.text()?)
    }

    pub fn crear_grupo(&self, session_id: Uuid, req: &CrearGrupoRequest) -> anyhow::Result<GrupoResponse> {
        let resp = self
            .http
            .post(format!("{}/groups", self.base_url))
            .bearer_auth(session_id)
            .json(req)
            .send()?;
        a_resultado(resp)
    }

    pub fn listar_grupos(&self, session_id: Uuid) -> anyhow::Result<Vec<GrupoResponse>> {
        let resp = self.http.get(format!("{}/groups", self.base_url)).bearer_auth(session_id).send()?;
        a_resultado(resp)
    }

    pub fn obtener_grupo(&self, session_id: Uuid, group_id: Uuid) -> anyhow::Result<GrupoResponse> {
        let resp = self
            .http
            .get(format!("{}/groups/{}", self.base_url, group_id))
            .bearer_auth(session_id)
            .send()?;
        a_resultado(resp)
    }

    pub fn agregar_miembro_grupo(&self, session_id: Uuid, group_id: Uuid, user_id: Uuid, is_admin: bool) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/groups/{}/members/{}", self.base_url, group_id, user_id))
            .bearer_auth(session_id)
            .json(&AgregarMiembroGrupoRequest { is_admin, envelopes: vec![] })
            .send()?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let texto = resp.text()?;
            anyhow::bail!("error HTTP {status}: {texto}")
        }
    }

    pub fn quitar_miembro_grupo(&self, session_id: Uuid, group_id: Uuid, user_id: Uuid) -> anyhow::Result<()> {
        let resp = self
            .http
            .delete(format!("{}/groups/{}/members/{}", self.base_url, group_id, user_id))
            .bearer_auth(session_id)
            .send()?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let texto = resp.text()?;
            anyhow::bail!("error HTTP {status}: {texto}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Servidor mínimo (sin dependencias nuevas) que siempre responde con un
    /// 302 hacia otro host — criterio de aceptación de F-35: "un redirect
    /// cross-host simulado en un test es rechazado por el cliente HTTP".
    fn servidor_que_redirige_a_otro_host() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let respuesta =
                    "HTTP/1.1 302 Found\r\nLocation: http://otro-host.invalid/robado\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(respuesta.as_bytes());
            }
        });
        addr
    }

    #[test]
    fn rechaza_redirect_cross_host() {
        let addr = servidor_que_redirige_a_otro_host();
        let cliente = Cliente::nuevo(format!("http://{addr}"), None).unwrap();
        let resultado = cliente.healthz();
        assert!(resultado.is_err(), "un redirect cross-host debería fallar, no seguirse");
    }

    /// Mismo host/scheme que la base — el redirect sí debe seguirse hasta el 200 final.
    #[test]
    fn sigue_redirect_al_mismo_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                // `Connection: close` fuerza al cliente a abrir una conexión
                // nueva para la request de redirect en vez de reusar esta
                // vía keep-alive — el mock sólo atiende un `accept()` por
                // conexión, si el cliente reusara la conexión el segundo
                // `accept()` de abajo se quedaría esperando una conexión que
                // nunca llega.
                let respuesta =
                    "HTTP/1.1 302 Found\r\nLocation: /destino\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(respuesta.as_bytes());
            }
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let respuesta = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = stream.write_all(respuesta.as_bytes());
            }
        });

        let cliente = Cliente::nuevo(format!("http://{addr}"), None).unwrap();
        let resultado = cliente.healthz();
        assert_eq!(resultado.unwrap(), "ok", "un redirect same-host sí debe seguirse");
    }
}
