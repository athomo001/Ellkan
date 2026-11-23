// Autor: Athan Espinoza

//! QA-26: detrás de un proxy confiable (`ELLKAN_TRUSTED_PROXIES`), cada
//! cliente tiene su propio límite por IP según `X-Forwarded-For`. Antes todos
//! compartían el bucket del proxy. Binario propio: la variable de entorno es
//! global del proceso y no debe afectar a los demás tests.

mod common;

use serde_json::json;

#[tokio::test]
async fn cada_cliente_detras_del_proxy_tiene_su_propio_limite() {
    // SAFETY: único test de este binario, antes de levantar el servidor.
    unsafe { std::env::set_var("ELLKAN_TRUSTED_PROXIES", "127.0.0.1,::1") };
    let entorno = common::levantar().await;

    let pedir = |ip: &'static str| {
        entorno
            .cliente
            .post(format!("{}/recovery-kit/reset", entorno.base))
            .header("x-forwarded-for", ip)
            .json(&json!({ "email": "nadie@test.ellkan" }))
            .send()
    };

    // `recovery-kit/reset`: 1/s con ráfaga de 5 por IP.
    let mut ultimo = 0;
    for _ in 0..8 {
        ultimo = pedir("198.51.100.1").await.unwrap().status().as_u16();
        if ultimo == 429 {
            break;
        }
    }
    assert_eq!(ultimo, 429, "el cliente que abusa agota su límite");

    let resp = pedir("198.51.100.2").await.unwrap();
    assert_eq!(resp.status(), 200, "otro cliente detrás del mismo proxy no queda bloqueado");

    // Lo que el cliente ponga a la izquierda no le sirve para esquivar su límite.
    let resp = pedir("203.0.113.50, 198.51.100.1").await.unwrap();
    assert_eq!(resp.status(), 429);
}
