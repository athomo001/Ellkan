// Autor: Athan Espinoza

//! QA-07: un host SMTP inválido se rechaza al guardarlo (400), en vez de
//! llegar al poller de envío, que antes entraba en pánico con él.

mod common;

use serde_json::json;

async fn guardar(entorno: &common::Entorno, sesion: uuid::Uuid, host: &str, tls: bool) -> u16 {
    entorno
        .cliente
        .put(format!("{}/admin/smtp-config", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "host": host, "port": 587, "from_address": "no-reply@ellkan.test", "tls": tls }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn host_smtp_invalido_se_rechaza_y_el_servidor_sigue_vivo() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "smtp-qa07@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    assert_eq!(guardar(&entorno, sesion, "mail host", true).await, 400, "host con espacios");
    assert_eq!(guardar(&entorno, sesion, "mail host", false).await, 400, "host con espacios, sin TLS");

    // La config previa (la del entorno de prueba) sigue intacta.
    let fila: (Option<String>,) = sqlx::query_as("select host from smtp_config where organization_id = 1")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(fila.0.as_deref(), Some("smtp.invalid"));

    assert_eq!(guardar(&entorno, sesion, "smtp.ejemplo.test", true).await, 200, "host válido");

    // El proceso sigue respondiendo.
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}
