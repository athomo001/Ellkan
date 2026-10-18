// Autor: Athan Espinoza

//! Carga real (2026-10-17): muchos usuarios importando a la vez desde la
//! MISMA IP (como detrás de Docker o de la NAT de una oficina), cada uno con
//! 200 claves, y después listando su vault. Antes de este cambio la app de
//! escritorio de un solo usuario subiendo 137 claves dejaba a su propia web
//! con "Too Many Requests". Acá se exige: cero 429, todas las claves creadas,
//! y la lista trae la DEK propia de cada recurso (sin N+1).

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

const USUARIOS: usize = 25;
const CLAVES_POR_USUARIO: usize = 200;

/// Cuerpo de `POST /resources` como lo arma el cliente al importar: metadata
/// y secreto cifrados con una DEK propia, DEK sellada para el dueño.
fn cuerpo_recurso(owner: &common::Usuario, n: usize) -> Value {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek = SecretBox::new(Box::new(dek_bytes));
    let id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata = format!(r#"{{"name":"clave {n}","username":"u{n}","uri":"https://ejemplo{n}.test"}}"#);
    let metadata_env = aead::cifrar(&dek, metadata.as_bytes(), &aad).unwrap();
    let secreto_env = aead::cifrar(&dek, b"{\"password\":\"x\"}", &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek);
    json!({
        "id": id,
        "resource_type_slug": "login-password",
        "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
        "metadata_nonce_b64": B64.encode(metadata_env.nonce),
        "sealed_dek_b64": B64.encode(&sealed_dek),
        "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
        "secret_nonce_b64": B64.encode(secreto_env.nonce),
    })
}

#[tokio::test]
async fn muchos_usuarios_importando_a_la_vez_desde_la_misma_ip_no_reciben_429() {
    let entorno = common::levantar().await;

    // Registro + login de todos (pedidos SIN sesión, cupo por IP).
    let mut trabajos = Vec::with_capacity(USUARIOS);
    for i in 0..USUARIOS {
        let usuario = common::registrar(&entorno, &format!("carga{i}@test.ellkan")).await;
        let sesion = common::login(&entorno, &usuario).await;
        let cuerpos: Vec<Value> = (0..CLAVES_POR_USUARIO).map(|n| cuerpo_recurso(&usuario, n)).collect();
        trabajos.push((sesion, cuerpos));
    }

    // Todos importan a la vez; cada uno de a una clave, como `importar()`.
    let inicio = std::time::Instant::now();
    let mut tareas = tokio::task::JoinSet::new();
    for (sesion, cuerpos) in trabajos {
        let cliente = entorno.cliente.clone();
        let base = entorno.base.clone();
        tareas.spawn(async move {
            let mut rechazos = Vec::new();
            for cuerpo in cuerpos {
                let resp = cliente
                    .post(format!("{base}/resources"))
                    .bearer_auth(sesion)
                    .json(&cuerpo)
                    .send()
                    .await
                    .unwrap();
                if resp.status() != 200 {
                    rechazos.push(resp.status().as_u16());
                }
            }

            // Y lista su vault: un solo pedido, con la DEK propia adentro.
            let lista: Vec<Value> = cliente
                .get(format!("{base}/resources"))
                .bearer_auth(sesion)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            (rechazos, lista)
        });
    }

    let mut total_creadas = 0;
    while let Some(resultado) = tareas.join_next().await {
        let (rechazos, lista) = resultado.unwrap();
        assert!(rechazos.is_empty(), "hubo pedidos rechazados durante la importación: {rechazos:?}");
        assert_eq!(lista.len(), CLAVES_POR_USUARIO, "cada usuario ve exactamente sus claves");
        assert!(
            lista.iter().all(|r| r["own_sealed_dek_b64"].as_str().is_some_and(|s| !s.is_empty())),
            "GET /resources tiene que traer la DEK propia de cada recurso (sin N+1)"
        );
        total_creadas += lista.len();
    }
    assert_eq!(total_creadas, USUARIOS * CLAVES_POR_USUARIO);
    println!(
        "{USUARIOS} usuarios × {CLAVES_POR_USUARIO} claves = {total_creadas} en {:.1}s",
        inicio.elapsed().as_secs_f64()
    );
}
