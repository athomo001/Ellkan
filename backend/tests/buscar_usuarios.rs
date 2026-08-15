// Autor: Athan Espinoza

//! Buscador en vivo del modal de compartir (`GET /users/search?q=`) —
//! coincidencia parcial sobre email/display_name, hasta 10 resultados.

mod common;

use serde_json::Value;

#[tokio::test]
async fn busca_por_coincidencia_parcial_y_respeta_el_minimo_de_caracteres() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-buscar@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    // Menos de 2 caracteres: lista vacía, no un error.
    let resp = entorno
        .cliente
        .get(format!("{}/users/search?q=a", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let vacio: Value = resp.json().await.unwrap();
    assert_eq!(vacio.as_array().unwrap().len(), 0);

    // Coincidencia parcial sobre el email.
    let resp = entorno
        .cliente
        .get(format!("{}/users/search?q=alice-buscar", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resultados: Value = resp.json().await.unwrap();
    let lista = resultados.as_array().unwrap();
    assert!(lista.iter().any(|u| u["email"] == "alice-buscar@test.ellkan"));
    assert!(!lista[0]["public_key_x25519_b64"].as_str().unwrap().is_empty());

    // Sin sesión, 401.
    let resp = entorno.cliente.get(format!("{}/users/search?q=alice", entorno.base)).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}
