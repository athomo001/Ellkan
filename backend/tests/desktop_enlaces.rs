// Autor: Athan Espinoza

//! Enlaces `ellkan://`: la URL viene de afuera, así que sólo se aceptan unas
//! pocas formas y el resultado es siempre una ruta interna de la app.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::enlaces::{interpretar, parece_enlace};

const ID: &str = "01a0a85d-3be1-70f1-b692-e270dd61fcf3";

#[test]
fn abrir_la_boveda() {
    for url in ["ellkan://abrir", "ellkan://boveda", "ellkan://vault", "ELLKAN://Abrir", "ellkan://vault/"] {
        assert_eq!(interpretar(url).as_deref(), Some("/vault"), "{url}");
    }
}

#[test]
fn abrir_un_recurso_por_su_id() {
    assert_eq!(interpretar(&format!("ellkan://item/{ID}")).as_deref(), Some(format!("/vault?abrir={ID}").as_str()));
    assert_eq!(interpretar(&format!("ellkan://recurso/{ID}/")).as_deref(), Some(format!("/vault?abrir={ID}").as_str()));
    assert_eq!(
        interpretar(&format!("ellkan://item/{}", ID.to_uppercase())).as_deref(),
        Some(format!("/vault?abrir={ID}").as_str()),
        "el id se normaliza a minúsculas"
    );
}

#[test]
fn lo_que_no_es_una_forma_aceptada_se_rechaza() {
    for url in [
        "",
        "ellkan://",
        "ellkan://desconocido",
        "ellkan://item",
        "ellkan://item/no-es-un-uuid",
        "ellkan://item/../../etc/passwd",
        &format!("ellkan://item/{ID}/extra"),
        &format!("ellkan://item/{ID}?x=1"),
        &format!("ellkan://item/{ID}#frag"),
        "ellkan://abrir/algo",
        "ellkan://abrir?next=https://evil.example",
        "https://evil.example",
        "javascript:alert(1)",
        "file:///C:/Windows/System32/cmd.exe",
    ] {
        assert_eq!(interpretar(url), None, "{url:?} no debería aceptarse");
    }
}

#[test]
fn el_resultado_nunca_sale_de_las_rutas_de_la_boveda() {
    // Cualquier cosa que se acepte tiene que caer en `/vault…`: el frontend
    // navega a ese valor tal cual.
    let candidatos = ["ellkan://abrir", "ellkan://vault", &format!("ellkan://item/{ID}")];
    for url in candidatos {
        assert!(interpretar(url).unwrap().starts_with("/vault"));
    }
}

#[test]
fn se_reconoce_un_enlace_entre_los_argumentos_de_la_linea_de_comandos() {
    assert!(parece_enlace("ellkan://abrir"));
    assert!(parece_enlace("Ellkan://abrir"));
    assert!(!parece_enlace("--minimizado"));
    assert!(!parece_enlace(r"C:\Ellkan\ellkan-desktop.exe"));
    assert!(!parece_enlace("ellkan"));
    assert!(!parece_enlace("ellkan://"));
}
