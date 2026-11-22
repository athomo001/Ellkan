// Autor: Athan Espinoza

//! QA-27: cabeceras de seguridad del navegador. Un solo test que levanta el
//! servidor dos veces (sin y con dirección `https://`): la variable de entorno
//! es global del proceso.

mod common;

async fn cabeceras(entorno: &common::Entorno) -> reqwest::header::HeaderMap {
    let resp = entorno.cliente.get(format!("{}/auth/setup-status", entorno.base)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    resp.headers().clone()
}

#[tokio::test]
async fn csp_permissions_policy_y_hsts_solo_con_https() {
    let entorno = common::levantar().await;
    let h = cabeceras(&entorno).await;
    let csp = h["content-security-policy"].to_str().unwrap();
    for directiva in [
        "connect-src 'self' https://api.pwnedpasswords.com",
        "img-src 'self' data: blob:",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    ] {
        assert!(csp.contains(directiva), "falta «{directiva}» en {csp}");
    }
    // `default-src` en el header bloquearía el script inline de arranque,
    // que sólo autoriza el `<meta>` de SvelteKit.
    assert!(!csp.contains("default-src"), "{csp}");
    assert!(h["permissions-policy"].to_str().unwrap().contains("camera=()"));
    assert!(h.get("strict-transport-security").is_none(), "sin https no hay HSTS");

    // SAFETY: único test de este binario; el primer servidor ya leyó el entorno.
    // El RP ID tiene que coincidir con el origen (WebAuthn lo valida al armar el estado).
    unsafe {
        std::env::set_var("ELLKAN_RP_ID", "ellkan.example");
        std::env::set_var("ELLKAN_RP_ORIGIN", "https://ellkan.example");
    }
    let entorno = common::levantar().await;
    let h = cabeceras(&entorno).await;
    assert_eq!(h["strict-transport-security"], "max-age=31536000");
}
