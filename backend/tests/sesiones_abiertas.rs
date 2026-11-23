// Autor: Athan Espinoza

//! QA-21: sesiones abiertas (`/me/sessions`) — listar, cerrar una ajena,
//! cerrar todas las demás, y que nadie toque las sesiones de otro usuario.

mod common;

use serde_json::Value;
use uuid::Uuid;

async fn listar(entorno: &common::Entorno, sesion: Uuid) -> Vec<Value> {
    let resp = entorno
        .cliente
        .get(format!("{}/me/sessions", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

async fn status_con(entorno: &common::Entorno, sesion: Uuid) -> u16 {
    entorno
        .cliente
        .get(format!("{}/me", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn listar_cerrar_una_y_cerrar_las_demas() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice@test.ellkan").await;
    let s1 = common::login(&entorno, &alice).await;
    let s2 = common::login_dispositivo_conocido(&entorno, &alice).await;
    let s3 = common::login_dispositivo_conocido(&entorno, &alice).await;

    // El nombre del dispositivo sale del User-Agent, se anota en segundo plano.
    let resp = entorno
        .cliente
        .get(format!("{}/me", entorno.base))
        .bearer_auth(s2)
        .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut dispositivo = None;
    for _ in 0..50 {
        dispositivo = sqlx::query_scalar::<_, Option<String>>("select dispositivo from sessions where id = $1")
            .bind(s2)
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
        if dispositivo.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(dispositivo.as_deref(), Some("Firefox · Linux"));
    let (ua_guardado,): (bool,) = sqlx::query_as("select exists(select 1 from sessions where dispositivo like '%Gecko%')")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!ua_guardado, "nunca se guarda el User-Agent completo");

    let lista = listar(&entorno, s1).await;
    let ids: Vec<&str> = lista.iter().map(|s| s["id"].as_str().unwrap()).collect();
    for s in [s1, s2, s3] {
        assert!(ids.contains(&s.to_string().as_str()), "falta {s} en {lista:?}");
    }
    let actuales: Vec<_> = lista.iter().filter(|s| s["actual"] == true).collect();
    assert_eq!(actuales.len(), 1);
    assert_eq!(actuales[0]["id"], s1.to_string());

    // Bob no puede cerrar una sesión de Alice: 404, y la sesión sigue viva.
    let bob = common::registrar(&entorno, "bob@test.ellkan").await;
    let sb = common::login(&entorno, &bob).await;
    let resp = entorno
        .cliente
        .delete(format!("{}/me/sessions/{s2}", entorno.base))
        .bearer_auth(sb)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(status_con(&entorno, s2).await, 200);
    assert!(
        listar(&entorno, sb).await.iter().all(|s| s["id"] != s2.to_string()),
        "bob no ve las sesiones de alice"
    );

    // Alice cierra s2 desde s1.
    let resp = entorno
        .cliente
        .delete(format!("{}/me/sessions/{s2}", entorno.base))
        .bearer_auth(s1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(status_con(&entorno, s2).await, 401);
    let resp = entorno
        .cliente
        .delete(format!("{}/me/sessions/{s2}", entorno.base))
        .bearer_auth(s1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "ya estaba cerrada");

    // Cerrar las demás: s3 cae, s1 sigue, la de Bob no se toca.
    let resp = entorno
        .cliente
        .post(format!("{}/me/sessions/close-others", entorno.base))
        .bearer_auth(s1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert!(cuerpo["cerradas"].as_u64().unwrap() >= 1);
    assert_eq!(status_con(&entorno, s3).await, 401);
    assert_eq!(status_con(&entorno, s1).await, 200);
    assert_eq!(status_con(&entorno, sb).await, 200);
    let lista = listar(&entorno, s1).await;
    assert_eq!(lista.len(), 1, "{lista:?}");
}
