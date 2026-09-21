// Autor: Athan Espinoza

//! Preferencia "al cerrar la ventana" (`AlCerrar`): antes la "X" ocultaba la app
//! a la bandeja sin avisar y el usuario creía haberla cerrado. Por defecto
//! ahora se le pregunta. Sólo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::fs;
use std::path::PathBuf;

use ellkan_backend::desktop::{cargar_config, guardar_config, AlCerrar};
use uuid::Uuid;

fn carpeta_temporal() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_cierre_{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn por_defecto_se_le_pregunta_al_usuario() {
    assert_eq!(AlCerrar::default(), AlCerrar::Preguntar);
    let dir = carpeta_temporal();
    assert_eq!(cargar_config(&dir).unwrap().al_cerrar, AlCerrar::Preguntar, "sin config.json también se pregunta");
}

#[test]
fn cada_opcion_se_guarda_y_se_recupera() {
    let dir = carpeta_temporal();
    for modo in [AlCerrar::Bandeja, AlCerrar::Salir, AlCerrar::Preguntar] {
        let mut config = cargar_config(&dir).unwrap();
        config.al_cerrar = modo;
        guardar_config(&dir, &config).unwrap();
        assert_eq!(cargar_config(&dir).unwrap().al_cerrar, modo);
    }
}

#[test]
fn en_el_archivo_se_guarda_con_los_nombres_que_usa_el_frontend() {
    let dir = carpeta_temporal();
    let mut config = cargar_config(&dir).unwrap();
    config.al_cerrar = AlCerrar::Bandeja;
    guardar_config(&dir, &config).unwrap();

    let texto = fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(texto.contains("\"al_cerrar\": \"bandeja\""), "el frontend manda y espera 'preguntar' | 'bandeja' | 'salir': {texto}");
}

#[test]
fn guardar_la_preferencia_no_pisa_el_resto_de_la_configuracion() {
    let dir = carpeta_temporal();
    fs::write(dir.join("config.json"), r#"{"puerto_fijo":51234,"extension_navegadores":["chrome"]}"#).unwrap();

    let mut config = cargar_config(&dir).unwrap();
    assert_eq!(config.al_cerrar, AlCerrar::Preguntar, "un config.json anterior sin el campo sigue cargando");
    config.al_cerrar = AlCerrar::Salir;
    guardar_config(&dir, &config).unwrap();

    let recargada = cargar_config(&dir).unwrap();
    assert_eq!(recargada.puerto_fijo, Some(51234));
    assert_eq!(recargada.extension_navegadores, vec!["chrome".to_string()]);
    assert_eq!(recargada.al_cerrar, AlCerrar::Salir);
}

#[test]
fn un_valor_invalido_en_el_archivo_no_se_interpreta_como_salir() {
    let dir = carpeta_temporal();
    fs::write(dir.join("config.json"), r#"{"al_cerrar":"cerrar_ya"}"#).unwrap();

    // `cargar_config` falla; quien la usa en el cierre de la ventana cae a
    // `AlCerrar::default()` (preguntar), nunca a cerrar sin avisar.
    assert!(cargar_config(&dir).is_err());
}
