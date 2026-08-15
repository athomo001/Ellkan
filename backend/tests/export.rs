// Autor: Athan Espinoza

//! F-27 (export_policy + `/export-events`) y F-29 (export masivo de
//! usuarios/grupos). `/export-events` es a la vez el registro de auditoría
//! y el único gate server-side real de F-27 — ver el comentario de diseño
//! en `backend/src/export/mod.rs`.

mod common;

use serde_json::json;

#[tokio::test]
async fn defaults_de_fabrica_coinciden_con_la_spec() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "user@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/export-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "cualquier usuario autenticado puede leer la política");
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["export_enabled"], true);
    assert_eq!(cuerpo["allowed_formats"], json!(["kdbx"]));
    assert_eq!(cuerpo["import_enabled"], true);
}

#[tokio::test]
async fn no_admin_no_puede_cambiar_la_politica() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sinadmin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/export-policy", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "export_enabled": false, "allowed_formats": ["kdbx"], "import_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn formato_no_habilitado_rechaza_el_evento_sin_auditar_nada() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "csv@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    // Política default sólo habilita kdbx.
    let resp = entorno
        .cliente
        .post(format!("{}/export-events", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "event_type": "export", "format": "csv", "resource_count": 3 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = entorno
        .cliente
        .post(format!("{}/export-events", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "event_type": "export", "format": "kdbx", "resource_count": 3 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "kdbx sí está en allowed_formats por default");
}

#[tokio::test]
async fn politica_deshabilitada_bloquea_a_no_admin_pero_no_a_admin() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/export-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "export_enabled": false, "allowed_formats": ["kdbx"], "import_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let user = common::registrar(&entorno, "userexport@test.ellkan").await;
    let sesion_user = common::login(&entorno, &user).await;
    let resp = entorno
        .cliente
        .post(format!("{}/export-events", entorno.base))
        .bearer_auth(sesion_user)
        .json(&json!({ "event_type": "export", "format": "kdbx", "resource_count": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "export_enabled=false bloquea a un usuario sin rol admin");

    let resp = entorno
        .cliente
        .post(format!("{}/export-events", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "event_type": "export", "format": "kdbx", "resource_count": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin exporta su propia cuenta igual, vía la excepción de rol");
}

#[tokio::test]
async fn excepcion_de_admin_no_aplica_a_import_enabled() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "adminimport@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/export-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "export_enabled": true, "allowed_formats": ["kdbx"], "import_enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .post(format!("{}/export-events", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "event_type": "import", "format": "kdbx", "resource_count": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "la excepción de rol de F-27 es sólo sobre export_enabled, nunca import_enabled");
}

#[tokio::test]
async fn evento_exitoso_deja_exactamente_una_entrada_de_auditoria() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "adminaudit@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .post(format!("{}/export-events", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "event_type": "export", "format": "kdbx", "resource_count": 7 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // El consumidor de `DomainEvent::Auditoria` escribe la fila de forma
    // asíncrona, desacoplado del request que la disparó (mismo patrón que
    // el resto del proyecto) — bajo carga (toda la suite corriendo en
    // paralelo) puede no estar escrita todavía en el instante exacto en
    // que este test la busca, así que se reintenta brevemente en vez de
    // asumir el peor caso al primer intento.
    let mut items = Vec::new();
    for _ in 0..30 {
        let resp = entorno
            .cliente
            .get(format!("{}/admin/audit-log?event_type=export.performed", entorno.base))
            .bearer_auth(sesion)
            .send()
            .await
            .unwrap();
        let cuerpo: serde_json::Value = resp.json().await.unwrap();
        items = cuerpo["items"].as_array().cloned().unwrap_or_default();
        if !items.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(items.len(), 1, "items: {items:?}");
    assert_eq!(items[0]["metadata"]["format"], "kdbx");
    assert_eq!(items[0]["metadata"]["resource_count"], 7);
}

#[tokio::test]
async fn export_masivo_de_usuarios_y_grupos_excluye_todo_campo_criptografico() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "adminmasivo@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;
    let otro = common::registrar(&entorno, "otromasivo@test.ellkan").await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/users/export", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "application/x-ndjson; charset=utf-8");
    let cuerpo = resp.text().await.unwrap();
    let lineas: Vec<&str> = cuerpo.lines().collect();
    // No exactamente 2: el bootstrap de la instancia (`common::levantar()`)
    // deja su propio usuario admin dummy, que este export sí incluye a
    // propósito (auditoría, incluye hasta usuarios ya borrados) — se
    // verifica contenido, no cantidad exacta, mismo criterio que el resto
    // de la suite para este tipo de aserción.
    let emails_exportados: Vec<String> = lineas
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["email"].as_str().unwrap().to_string())
        .collect();
    assert!(emails_exportados.contains(&admin.email), "el admin registrado en este test debe aparecer");
    assert!(emails_exportados.contains(&otro.email), "el segundo usuario registrado en este test debe aparecer");

    for linea in &lineas {
        let fila: serde_json::Value = serde_json::from_str(linea).unwrap();
        assert!(fila.get("encrypted_private_key_blob").is_none());
        assert!(fila.get("kdf_salt").is_none());
        assert!(fila.get("kdf_params").is_none());
        assert!(fila["email"].is_string());
        assert!(fila["mfa_configured"].is_boolean());
    }

    let resp = entorno
        .cliente
        .get(format!("{}/admin/groups/export?format=csv", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/csv; charset=utf-8");
}

#[tokio::test]
async fn csv_injection_en_export_masivo_se_neutraliza() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admincsv@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    // display_name con un payload de fórmula — el registro real no valida
    // el contenido de display_name (es texto libre), así que esto es un
    // vector legítimo de probar acá, no un caso artificial.
    let _atacante = common::registrar(&entorno, "atacante@test.ellkan").await;
    sqlx::query("update users set display_name = $1 where email = $2")
        .bind("=cmd|'/c calc'!A1")
        .bind("atacante@test.ellkan")
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/admin/users/export?format=csv", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo = resp.text().await.unwrap();
    assert!(
        cuerpo.contains("'=cmd") || cuerpo.contains("\"'=cmd"),
        "el campo con fórmula debe quedar neutralizado con un ' inicial, cuerpo: {cuerpo}"
    );
    assert!(!cuerpo.contains("\n=cmd") && !cuerpo.contains(",=cmd"), "nunca debe quedar sin neutralizar");
}
