// Autor: Athan Espinoza

//! Hallazgo real de uso: `GET /admin/roles` es simultáneamente una página
//! del frontend y un `.nest` de la API — F5 sobre esa URL le pegaba directo
//! al handler de la API (sin `Authorization`, porque una navegación real
//! nunca lo manda) en vez de servir el shell de la SPA. `rescate_spa_en_recarga`
//! en `lib.rs` detecta ese patrón (`GET`, sin `Authorization`, `Accept` que
//! prefiere HTML) y lo desvía al fallback estático antes de que la ruta de
//! la API lo intercepte.

// `#[allow]`: este archivo sólo usa `common::levantar`, el resto de los
// helpers del módulo (`registrar`, etc.) quedan sin uso en este binario
// puntual — cada test de integración compila `common` como su propio crate.
#[allow(dead_code)]
mod common;

#[tokio::test]
async fn navegacion_sin_credenciales_sobre_ruta_colisionada_no_llega_a_la_api() {
    let entorno = common::levantar().await;

    // Sin `Authorization`, con `Accept` de navegación real — exactamente lo
    // que manda un browser en un F5, nunca lo que manda `$lib/api/client.ts`.
    let resp = entorno
        .cliente
        .get(format!("{}/admin/roles", entorno.base))
        .header("accept", "text/html,application/xhtml+xml")
        .send()
        .await
        .unwrap();

    // Bajo test no hay build de frontend (`ELLKAN_FRONTEND_DIST` apunta a un
    // directorio inexistente), así que el fallback cae a 404 — lo que
    // importa acá no es el 404 en sí, sino que el body NO sea el error de la
    // API: si el rescate no funcionara, esto sería 401 con `INVALID_CREDENTIALS`.
    let cuerpo = resp.text().await.unwrap();
    assert!(
        !cuerpo.contains("INVALID_CREDENTIALS"),
        "una navegación sin credenciales no debería llegar al handler de la API: {cuerpo}"
    );
}

#[tokio::test]
async fn llamada_de_api_real_sin_auth_sigue_devolviendo_401_json() {
    let entorno = common::levantar().await;

    // Mismo path, pero con el `Accept` que manda un cliente de API real
    // (`$lib/api/client.ts`, la CLI, la futura extensión) — tiene que seguir
    // yendo al handler de la API tal cual, el rescate no debe interferir.
    let resp = entorno
        .cliente
        .get(format!("{}/admin/roles", entorno.base))
        .header("accept", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let cuerpo = resp.text().await.unwrap();
    assert!(cuerpo.contains("INVALID_CREDENTIALS"));
}
