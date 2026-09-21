// Autor: Athan Espinoza

//! `ellkan_backend::desktop::bindear_puerto` (spec/13 §3, 2026-09-16):
//! autoelección de puerto dentro del rango IANA privado/dinámico, con
//! persistencia en `<datadir>/config.json` y fallback si el puerto
//! persistido ya está ocupado por otro proceso. Sólo compila/corre con
//! `--features desktop`.
#![cfg(feature = "desktop")]

use std::path::PathBuf;

use uuid::Uuid;

fn datadir_de_prueba() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan-puerto-test-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn primer_arranque_elige_un_puerto_del_rango_privado_y_lo_persiste() {
    let datadir = datadir_de_prueba();

    let (_listener, puerto) = ellkan_backend::desktop::bindear_puerto(&datadir).await.unwrap();
    assert!((49152..=65535).contains(&puerto), "el puerto autoelegido debe estar en el rango IANA privado/dinámico");

    let config_json = std::fs::read_to_string(datadir.join("config.json")).expect("config.json debe haberse creado");
    let config: serde_json::Value = serde_json::from_str(&config_json).unwrap();
    assert_eq!(config["puerto_fijo"], puerto, "el puerto elegido debe quedar persistido en config.json");

    std::fs::remove_dir_all(&datadir).ok();
}

#[tokio::test]
async fn un_arranque_posterior_reusa_el_puerto_ya_persistido() {
    let datadir = datadir_de_prueba();

    let (primer_listener, puerto_1) = ellkan_backend::desktop::bindear_puerto(&datadir).await.unwrap();
    drop(primer_listener); // libera el puerto antes del segundo intento

    let (_segundo_listener, puerto_2) = ellkan_backend::desktop::bindear_puerto(&datadir).await.unwrap();
    assert_eq!(puerto_1, puerto_2, "un arranque posterior debe reusar el puerto fijo ya elegido, no autoelegir otro");

    std::fs::remove_dir_all(&datadir).ok();
}

#[tokio::test]
async fn si_el_puerto_persistido_esta_ocupado_cae_a_uno_libre_sin_fallar() {
    let datadir = datadir_de_prueba();

    // Primer bind real: fija y persiste un puerto.
    let (listener_ocupante, puerto_fijo) = ellkan_backend::desktop::bindear_puerto(&datadir).await.unwrap();

    // Segundo intento sobre el MISMO datadir, sin soltar el primer listener
    // — el puerto persistido sigue tomado por `listener_ocupante`.
    let (_otro_listener, puerto_alternativo) = ellkan_backend::desktop::bindear_puerto(&datadir).await.unwrap();

    assert_ne!(puerto_alternativo, puerto_fijo, "con el puerto fijo ocupado, debe caer a uno distinto");
    assert!((49152..=65535).contains(&puerto_alternativo), "el fallback también debe salir del rango IANA privado");

    drop(listener_ocupante);
    std::fs::remove_dir_all(&datadir).ok();
}
