// Autor: Athan Espinoza

//! Revocación remota (docs/revocacion-remota.md): al bloquear o purgar una
//! cuenta, el servidor emite un aviso FIRMADO con su clave para que la app de
//! escritorio vinculada borre la bóveda local. Se prueba:
//! - el aviso en vivo por `GET /sync/eventos` (y que la conexión se cierra),
//! - `POST /auth/estado-cuenta` para activa, bloqueada, purgada, reactivada,
//!   y que a quien no prueba ser dueño de las claves le contesta lo mismo que
//!   a una cuenta inexistente.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use ellkan_crypto::claves::KeypairFirma;
use serde_json::{json, Value};
use time::OffsetDateTime;

async fn clave_del_servidor(entorno: &common::Entorno) -> VerifyingKey {
    let cuerpo: Value = entorno.cliente.get(format!("{}/auth/server-key", entorno.base)).send().await.unwrap().json().await.unwrap();
    let bytes = B64.decode(cuerpo["public_key_ed25519_b64"].as_str().unwrap()).unwrap();
    VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap()
}

/// Verifica la firma del aviso y devuelve su cuerpo.
fn aviso_verificado(clave: &VerifyingKey, firmado: &Value) -> Value {
    let aviso = firmado["aviso"].as_str().expect("trae el aviso");
    let firma = B64.decode(firmado["firma_b64"].as_str().unwrap()).unwrap();
    clave
        .verify(aviso.as_bytes(), &Signature::from_bytes(&firma.try_into().unwrap()))
        .expect("el aviso tiene que estar firmado con la clave del servidor");
    serde_json::from_str(aviso).unwrap()
}

/// `POST /auth/estado-cuenta` firmando con `firmante` (la clave de la cuenta, o no).
async fn estado_cuenta(entorno: &common::Entorno, email: &str, firmante: &KeypairFirma) -> Value {
    let publica = B64.encode(firmante.verificadora().to_bytes());
    let emitido = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap();
    let mensaje = ellkan_backend::revocacion::mensaje_estado_cuenta(email, &publica, &emitido);
    let firma = firmante.firmante().sign(mensaje.as_bytes());
    let resp = entorno
        .cliente
        .post(format!("{}/auth/estado-cuenta", entorno.base))
        .json(&json!({ "email": email, "public_key_ed25519_b64": publica, "emitido_en": emitido, "firma_b64": B64.encode(firma.to_bytes()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

async fn cambiar_activo(entorno: &common::Entorno, sesion_admin: uuid::Uuid, user_id: uuid::Uuid, activo: bool) {
    let resp = entorno
        .cliente
        .put(format!("{}/admin/users/{}", entorno.base, user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "active": activo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn bloquear_manda_el_aviso_firmado_por_el_stream_y_lo_cierra() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima = common::registrar(&entorno, "victima@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    let clave = clave_del_servidor(&entorno).await;

    // Stream abierto ANTES de bloquear (con las cabeceras ya recibidas, el
    // handler ya se suscribió al canal).
    let mut stream = entorno
        .cliente
        .get(format!("{}/sync/eventos", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);

    cambiar_activo(&entorno, sesion_admin, victima.user_id, false).await;

    // Se lee hasta el evento de revocación; después el servidor cierra.
    let mut texto = String::new();
    let lectura = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(trozo) = stream.chunk().await.unwrap() {
            texto.push_str(&String::from_utf8_lossy(&trozo));
        }
    })
    .await;
    assert!(lectura.is_ok(), "el stream tiene que cerrarse solo tras el aviso; llegó: {texto}");

    let mensaje = texto.split("\n\n").find(|m| m.contains("event: cuenta_revocada")).expect("tiene que llegar el aviso de revocación");
    let datos: String = mensaje.lines().filter_map(|l| l.strip_prefix("data:")).map(str::trim_start).collect();
    let aviso = aviso_verificado(&clave, &serde_json::from_str(&datos).unwrap());
    assert_eq!(aviso["tipo"], "cuenta_revocada");
    assert_eq!(aviso["user_id"], victima.user_id.to_string());
    assert_eq!(aviso["email"], "victima@test.ellkan");
    assert_eq!(aviso["motivo"], "deactivated");

    // Queda auditado.
    let auditado = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n: i64 = sqlx::query_scalar("select count(*) from audit_log_entries where event_type = 'user.remote_wipe_signaled' and subject_id = $1")
                .bind(victima.user_id)
                .fetch_one(&entorno.pool)
                .await
                .unwrap();
            if n > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(auditado.is_ok(), "el aviso emitido tiene que quedar en el log de auditoría");
}

#[tokio::test]
async fn estado_cuenta_activa_bloqueada_reactivada_y_purgada() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima = common::registrar(&entorno, "victima@test.ellkan").await;
    let clave = clave_del_servidor(&entorno).await;

    let r = estado_cuenta(&entorno, "victima@test.ellkan", &victima.ed25519).await;
    assert_eq!(r["estado"], "activa");
    assert!(r.get("aviso").is_none());

    cambiar_activo(&entorno, sesion_admin, victima.user_id, false).await;
    let r = estado_cuenta(&entorno, "victima@test.ellkan", &victima.ed25519).await;
    assert_eq!(r["estado"], "revocada");
    let aviso = aviso_verificado(&clave, &r["aviso"]);
    assert_eq!(aviso["user_id"], victima.user_id.to_string());
    assert_eq!(aviso["motivo"], "deactivated");

    cambiar_activo(&entorno, sesion_admin, victima.user_id, true).await;
    let r = estado_cuenta(&entorno, "victima@test.ellkan", &victima.ed25519).await;
    assert_eq!(r["estado"], "activa", "reactivada: ya no hay nada que borrar");

    let resp = entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", entorno.base, victima.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // De la cuenta purgada sólo queda la clave pública (sin correo).
    let guardada: Vec<u8> = sqlx::query_scalar("select public_key_ed25519 from cuentas_revocadas where user_id = $1")
        .bind(victima.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(guardada, victima.ed25519.verificadora().to_bytes().to_vec());

    let r = estado_cuenta(&entorno, "victima@test.ellkan", &victima.ed25519).await;
    assert_eq!(r["estado"], "revocada");
    let aviso = aviso_verificado(&clave, &r["aviso"]);
    assert_eq!(aviso["user_id"], victima.user_id.to_string());
    assert_eq!(aviso["motivo"], "purged");
    assert!(aviso.get("email").is_none(), "de una cuenta purgada el servidor ya no tiene el correo");
}

#[tokio::test]
async fn estado_cuenta_no_le_dice_nada_a_quien_no_es_dueno_de_las_claves() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima = common::registrar(&entorno, "victima@test.ellkan").await;
    cambiar_activo(&entorno, sesion_admin, victima.user_id, false).await;

    // Otra clave para el mismo correo: misma respuesta que un correo inexistente.
    let ajena = KeypairFirma::generar();
    let r = estado_cuenta(&entorno, "victima@test.ellkan", &ajena).await;
    assert_eq!(r["estado"], "desconocida");
    let r = estado_cuenta(&entorno, "nadie@test.ellkan", &ajena).await;
    assert_eq!(r["estado"], "desconocida");

    // La clave pública de la víctima, pero firmado por otro: tampoco.
    let publica = B64.encode(victima.ed25519.verificadora().to_bytes());
    let emitido = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap();
    let mensaje = ellkan_backend::revocacion::mensaje_estado_cuenta("victima@test.ellkan", &publica, &emitido);
    let firma = ajena.firmante().sign(mensaje.as_bytes());
    let r: Value = entorno
        .cliente
        .post(format!("{}/auth/estado-cuenta", entorno.base))
        .json(&json!({ "email": "victima@test.ellkan", "public_key_ed25519_b64": publica, "emitido_en": emitido, "firma_b64": B64.encode(firma.to_bytes()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["estado"], "desconocida");

    // Una pregunta vieja (fuera de la tolerancia de reloj) tampoco.
    let viejo = (OffsetDateTime::now_utc() - time::Duration::hours(1)).format(&time::format_description::well_known::Rfc3339).unwrap();
    let mensaje = ellkan_backend::revocacion::mensaje_estado_cuenta("victima@test.ellkan", &publica, &viejo);
    let firma = victima.ed25519.firmante().sign(mensaje.as_bytes());
    let r: Value = entorno
        .cliente
        .post(format!("{}/auth/estado-cuenta", entorno.base))
        .json(&json!({ "email": "victima@test.ellkan", "public_key_ed25519_b64": publica, "emitido_en": viejo, "firma_b64": B64.encode(firma.to_bytes()) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["estado"], "desconocida");
}
