// Autor: Athan Espinoza

//! Pendiente #58: cada usuario descarga sus propios datos personales, sin
//! material criptográfico ni datos de otras cuentas.

mod common;

use serde_json::Value;

#[tokio::test]
async fn cada_uno_descarga_sus_datos_y_no_los_de_otro() {
    let entorno = common::levantar().await;
    let ana = common::registrar(&entorno, "ana@test.ellkan").await;
    let sesion_ana = common::login(&entorno, &ana).await;
    let beto = common::registrar(&entorno, "beto@test.ellkan").await;
    let _sesion_beto = common::login(&entorno, &beto).await;
    let ruta = format!("{}/me/personal-data", entorno.base);

    let resp = entorno.cliente.get(&ruta).send().await.unwrap();
    assert_eq!(resp.status(), 401, "sin sesión no hay datos");

    // El login de ana (con verificación de dispositivo) deja entradas en la
    // auditoría, que se escriben en segundo plano.
    let mut datos = Value::Null;
    for _ in 0..50 {
        let resp = entorno.cliente.get(&ruta).bearer_auth(sesion_ana).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers()["content-disposition"].to_str().unwrap().starts_with("attachment;"),
            "se descarga como archivo"
        );
        assert_eq!(resp.headers()["cache-control"], "no-store");
        datos = resp.json().await.unwrap();
        if tiene_evento(&datos, "auth.device_verified") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert_eq!(datos["account"]["email"], "ana@test.ellkan");
    assert_eq!(datos["account"]["id"], ana.user_id.to_string());
    assert!(!datos["sessions"].as_array().unwrap().is_empty(), "su sesión abierta aparece");
    assert!(tiene_evento(&datos, "auth.device_verified"), "su historial en la auditoría: {datos}");
    assert_eq!(datos["audit_entries_truncated"], false);
    assert!(datos["not_included"].as_str().is_some_and(|t| !t.is_empty()));

    let texto = datos.to_string();
    assert!(!texto.contains("beto@test.ellkan"), "nada de la otra cuenta");
    for clave in [
        "security_stamp",
        "encrypted_private_key",
        "sealed",
        "secret_ciphertext",
        "device_token_hash",
        "metadata",
    ] {
        assert!(!texto.contains(clave), "sin material criptográfico ni metadata de auditoría: {clave}");
    }
}

fn tiene_evento(datos: &Value, tipo: &str) -> bool {
    datos["audit_entries"].as_array().is_some_and(|a| a.iter().any(|e| e["event_type"] == tipo))
}
