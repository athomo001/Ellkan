// Autor: Athan Espinoza

//! Punto 9: la app de escritorio instala la extensión de navegador desde su
//! propio bundle. Estos tests cubren la parte sin Tauri (extraer a una carpeta
//! estable, saber qué versión hay, decidir si hay que actualizar, no escribir
//! nunca afuera de la carpeta). Sólo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::fs;
use std::path::PathBuf;

use ellkan_backend::desktop::extension::{
    buscar_ejecutable_en, candidatos_ejecutable, carpeta_en, escribir_conexion, esta_al_dia, instalar, nombre_de_carpeta, objetivo_de,
    pagina_extensiones, url_backend, ARCHIVO_CONEXION, version_de_manifest, version_incluida, version_instalada, ArchivoExtension,
};
use ellkan_backend::desktop::{cargar_config, guardar_config};
use uuid::Uuid;

fn carpeta_temporal(nombre: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_extension_{nombre}_{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn manifest(version: &str) -> Vec<u8> {
    format!(r#"{{"manifest_version":3,"name":"Ellkan","version":"{version}"}}"#).into_bytes()
}

fn bundle<'a>(manifest_json: &'a [u8], extra: &'a [(&'a str, &'a [u8])]) -> Vec<ArchivoExtension<'a>> {
    let mut archivos = vec![ArchivoExtension { ruta: "manifest.json", contenido: manifest_json }];
    archivos.extend(extra.iter().map(|(ruta, contenido)| ArchivoExtension { ruta, contenido }));
    archivos
}

#[test]
fn instalar_extrae_los_archivos_con_sus_subcarpetas_y_la_version_queda_visible() {
    let destino = carpeta_temporal("extraer").join("chromium");
    let m = manifest("0.3.0");
    let archivos = bundle(&m, &[("background.js", b"fondo"), ("popup/index.html", b"<html>"), ("popup/assets/a.js", b"js")]);

    instalar(&destino, &archivos).expect("instalar");

    assert_eq!(fs::read(destino.join("background.js")).unwrap(), b"fondo");
    assert_eq!(fs::read(destino.join("popup").join("assets").join("a.js")).unwrap(), b"js");
    assert_eq!(version_instalada(&destino).as_deref(), Some("0.3.0"));
    assert!(esta_al_dia(&destino, &archivos));
}

#[test]
fn actualizar_pisa_lo_existente_y_borra_lo_que_ya_no_esta_en_el_bundle() {
    let destino = carpeta_temporal("actualizar").join("chromium");
    let m1 = manifest("0.3.0");
    instalar(&destino, &bundle(&m1, &[("popup/assets/index-viejo.js", b"viejo"), ("background.js", b"v1")])).unwrap();

    let m2 = manifest("0.4.0");
    let nuevos = bundle(&m2, &[("popup/assets/index-nuevo.js", b"nuevo"), ("background.js", b"v2")]);
    assert!(!esta_al_dia(&destino, &nuevos), "con una versión más nueva en el bundle hay que actualizar");
    instalar(&destino, &nuevos).unwrap();

    assert_eq!(fs::read(destino.join("background.js")).unwrap(), b"v2");
    assert!(destino.join("popup").join("assets").join("index-nuevo.js").exists());
    assert!(!destino.join("popup").join("assets").join("index-viejo.js").exists(), "el asset con hash de la versión anterior debe borrarse");
    assert_eq!(version_instalada(&destino).as_deref(), Some("0.4.0"));
    assert!(esta_al_dia(&destino, &nuevos));
}

#[test]
fn una_carpeta_que_queda_vacia_tras_actualizar_se_elimina() {
    let destino = carpeta_temporal("vacias").join("chromium");
    let m1 = manifest("1.0.0");
    instalar(&destino, &bundle(&m1, &[("viejo/solo.txt", b"x")])).unwrap();
    let m2 = manifest("1.0.1");
    instalar(&destino, &bundle(&m2, &[])).unwrap();

    assert!(!destino.join("viejo").exists());
}

#[test]
fn sin_nada_instalado_no_esta_al_dia_y_no_hay_version() {
    let destino = carpeta_temporal("vacio").join("chromium");
    let m = manifest("0.3.0");
    assert_eq!(version_instalada(&destino), None);
    assert!(!esta_al_dia(&destino, &bundle(&m, &[])));
}

#[test]
fn rutas_inseguras_se_rechazan_sin_escribir_nada() {
    let base = carpeta_temporal("inseguras");
    let destino = base.join("chromium");
    let m = manifest("0.3.0");

    for peligrosa in ["../fuera.txt", "a/../../fuera.txt", "/etc/passwd", "./x.txt", ""] {
        let extra: [(&str, &[u8]); 1] = [(peligrosa, b"malo")];
        let archivos = bundle(&m, &extra);
        assert!(instalar(&destino, &archivos).is_err(), "{peligrosa:?} tiene que rechazarse");
    }
    // Una letra de unidad sólo es un prefijo especial en Windows.
    #[cfg(windows)]
    {
        let extra: [(&str, &[u8]); 1] = [("C:/Windows/x.txt", b"malo")];
        let archivos = bundle(&m, &extra);
        assert!(instalar(&destino, &archivos).is_err(), "una ruta con letra de unidad tiene que rechazarse en Windows");
    }
    assert!(!base.join("fuera.txt").exists(), "nada se puede escribir afuera de la carpeta de la extensión");
    assert!(!destino.exists(), "se validan todas las rutas ANTES de escribir: no debe haber quedado ni la carpeta");
}

#[test]
fn un_bundle_vacio_se_rechaza_con_un_mensaje_claro() {
    let destino = carpeta_temporal("bundle_vacio").join("chromium");
    let error = instalar(&destino, &[]).unwrap_err().to_string();
    assert!(error.contains("no incluye la extensión"), "{error}");
}

#[test]
fn version_de_manifest_tolera_basura_y_manifests_sin_version() {
    assert_eq!(version_de_manifest(&manifest("2.5.1")).as_deref(), Some("2.5.1"));
    assert_eq!(version_de_manifest(b"no es json"), None);
    assert_eq!(version_de_manifest(br#"{"name":"sin version"}"#), None);
    assert_eq!(version_de_manifest(br#"{"version":3}"#), None, "una versión que no es texto no vale");

    let sin_manifest = [ArchivoExtension { ruta: "background.js", contenido: b"x" }];
    assert_eq!(version_incluida(&sin_manifest), None);
}

#[test]
fn los_navegadores_soportados_mapean_a_su_build_y_los_desconocidos_no_tienen_ruta() {
    for chromium in ["chrome", "edge", "brave", "opera"] {
        assert_eq!(objetivo_de(chromium), Some("chromium"));
    }
    assert_eq!(objetivo_de("firefox"), Some("firefox"));
    for raro in ["safari", "", "../chrome", "Chrome", "chrome/../x"] {
        assert_eq!(objetivo_de(raro), None, "{raro:?} nunca debe convertirse en una ruta");
    }
}

fn entorno_de_prueba(variable: &str) -> Option<String> {
    match variable {
        "ProgramFiles" => Some("C:/PF".to_string()),
        "ProgramFiles(x86)" => Some("C:/PF86".to_string()),
        "LOCALAPPDATA" => Some("C:/LA".to_string()),
        _ => None,
    }
}

#[test]
fn los_candidatos_de_cada_navegador_se_arman_desde_las_variables_de_entorno() {
    let chrome = candidatos_ejecutable("chrome", &entorno_de_prueba);
    assert_eq!(chrome.len(), 3, "Program Files, Program Files (x86) y el perfil del usuario");
    assert!(chrome.contains(&PathBuf::from("C:/PF").join("Google").join("Chrome").join("Application").join("chrome.exe")));
    assert!(chrome.contains(&PathBuf::from("C:/LA").join("Google").join("Chrome").join("Application").join("chrome.exe")));

    let edge = candidatos_ejecutable("edge", &entorno_de_prueba);
    assert!(edge.contains(&PathBuf::from("C:/PF86").join("Microsoft").join("Edge").join("Application").join("msedge.exe")));

    let opera = candidatos_ejecutable("opera", &entorno_de_prueba);
    assert!(opera.contains(&PathBuf::from("C:/LA").join("Programs").join("Opera").join("opera.exe")), "Opera se instala por usuario");

    let firefox = candidatos_ejecutable("firefox", &entorno_de_prueba);
    assert!(firefox.contains(&PathBuf::from("C:/PF").join("Mozilla Firefox").join("firefox.exe")));

    let brave = candidatos_ejecutable("brave", &entorno_de_prueba);
    assert!(brave.contains(&PathBuf::from("C:/PF").join("BraveSoftware").join("Brave-Browser").join("Application").join("brave.exe")));
}

#[test]
fn sin_variables_de_entorno_o_con_un_navegador_desconocido_no_hay_candidatos() {
    assert!(candidatos_ejecutable("chrome", &|_| None).is_empty());
    for raro in ["safari", "", "../chrome", "Chrome"] {
        assert!(candidatos_ejecutable(raro, &entorno_de_prueba).is_empty(), "{raro:?} no debe generar ninguna ruta");
    }
}

#[test]
fn cada_navegador_tiene_su_pagina_de_extensiones_y_los_desconocidos_no() {
    assert_eq!(pagina_extensiones("chrome"), Some("chrome://extensions"));
    assert_eq!(pagina_extensiones("edge"), Some("edge://extensions"));
    assert_eq!(pagina_extensiones("brave"), Some("brave://extensions"));
    assert_eq!(pagina_extensiones("opera"), Some("opera://extensions"));
    assert_eq!(pagina_extensiones("firefox"), Some("about:debugging#/runtime/this-firefox"));
    assert_eq!(pagina_extensiones("safari"), None);
    assert_eq!(pagina_extensiones("chrome; calc"), None, "lo que llega de afuera nunca se usa como URL");
}

#[test]
fn con_una_carpeta_de_pruebas_solo_se_buscan_los_navegadores_que_hay_ahi() {
    let carpeta = carpeta_temporal("navegadores");
    let nombre = |n: &str| if cfg!(windows) { format!("{n}.exe") } else { n.to_string() };
    fs::write(carpeta.join(nombre("chrome")), b"falso").unwrap();
    fs::write(carpeta.join(nombre("firefox")), b"falso").unwrap();

    assert_eq!(buscar_ejecutable_en("chrome", Some(&carpeta)), Some(carpeta.join(nombre("chrome"))));
    assert_eq!(buscar_ejecutable_en("firefox", Some(&carpeta)), Some(carpeta.join(nombre("firefox"))));
    assert_eq!(buscar_ejecutable_en("edge", Some(&carpeta)), None, "no hay uno falso de Edge: no se cae a buscar el real");
    assert_eq!(buscar_ejecutable_en("brave", Some(&carpeta)), None);

    for raro in ["safari", "", "../chrome", "chrome/../x"] {
        assert_eq!(buscar_ejecutable_en(raro, Some(&carpeta)), None, "{raro:?} no es un navegador soportado");
    }
}

#[test]
fn la_carpeta_de_la_extension_tiene_un_nombre_que_el_usuario_reconoce_y_no_se_pisan_los_builds() {
    assert_eq!(nombre_de_carpeta("chromium"), "Ellkan extensión");
    assert_eq!(nombre_de_carpeta("firefox"), "Ellkan extensión Firefox");
    assert_ne!(nombre_de_carpeta("chromium"), nombre_de_carpeta("firefox"), "cada build necesita su propia carpeta");

    let documentos = PathBuf::from("C:/Users/x/Documents");
    assert_eq!(carpeta_en(&documentos, "chromium"), documentos.join("Ellkan extensión"));
    assert_eq!(carpeta_en(&documentos, "firefox"), documentos.join("Ellkan extensión Firefox"));
}

#[test]
fn instalar_en_una_carpeta_con_espacios_y_acentos_funciona() {
    let base = carpeta_temporal("acentos");
    let destino = carpeta_en(&base, "chromium");
    let m = manifest("0.3.0");

    instalar(&destino, &bundle(&m, &[("popup/index.html", b"<html>")])).expect("instalar");

    assert_eq!(version_instalada(&destino).as_deref(), Some("0.3.0"));
    assert!(destino.join("popup").join("index.html").exists());
}

#[test]
fn la_eleccion_de_navegadores_se_persiste_en_la_configuracion() {
    let dir = carpeta_temporal("config");
    assert!(cargar_config(&dir).unwrap().extension_navegadores.is_empty(), "por defecto no hay ninguno elegido");

    let mut config = cargar_config(&dir).unwrap();
    config.extension_navegadores = vec!["chrome".into(), "firefox".into()];
    guardar_config(&dir, &config).unwrap();

    assert_eq!(cargar_config(&dir).unwrap().extension_navegadores, vec!["chrome".to_string(), "firefox".to_string()]);
}

#[test]
fn una_configuracion_anterior_sin_el_campo_sigue_cargando() {
    let dir = carpeta_temporal("config_vieja");
    fs::write(dir.join("config.json"), r#"{"puerto_fijo":51234}"#).unwrap();

    let config = cargar_config(&dir).expect("un config.json de una versión previa tiene que seguir siendo válido");
    assert_eq!(config.puerto_fijo, Some(51234));
    assert!(config.extension_navegadores.is_empty());
}

#[test]
fn la_direccion_del_backend_queda_en_la_carpeta_de_la_extension() {
    let destino = carpeta_temporal("conexion").join("chromium");
    let m = manifest("0.3.1");
    instalar(&destino, &bundle(&m, &[("background.js", b"fondo")])).unwrap();

    escribir_conexion(&destino, 54416).expect("escribir conexión");

    let json: serde_json::Value = serde_json::from_slice(&fs::read(destino.join(ARCHIVO_CONEXION)).unwrap()).unwrap();
    assert_eq!(json["server_url"], "http://127.0.0.1:54416");
    assert_eq!(url_backend(54416), "http://127.0.0.1:54416");
}

#[test]
fn escribir_la_conexion_crea_la_carpeta_y_se_actualiza_si_cambia_el_puerto() {
    let destino = carpeta_temporal("conexion_puerto").join("no-existe-todavia");

    escribir_conexion(&destino, 50001).unwrap();
    escribir_conexion(&destino, 50001).unwrap(); // idempotente
    escribir_conexion(&destino, 50002).unwrap();

    let json: serde_json::Value = serde_json::from_slice(&fs::read(destino.join(ARCHIVO_CONEXION)).unwrap()).unwrap();
    assert_eq!(json["server_url"], "http://127.0.0.1:50002");
}

#[test]
fn actualizar_la_extension_no_borra_la_direccion_del_backend() {
    let destino = carpeta_temporal("conexion_actualiza").join("chromium");
    let v1 = manifest("0.3.0");
    instalar(&destino, &bundle(&v1, &[("viejo.js", b"x")])).unwrap();
    escribir_conexion(&destino, 54416).unwrap();

    let v2 = manifest("0.3.1");
    instalar(&destino, &bundle(&v2, &[("nuevo.js", b"y")])).unwrap();

    assert!(destino.join(ARCHIVO_CONEXION).exists(), "un archivo que no es del bundle no se borra como obsoleto");
    assert!(!destino.join("viejo.js").exists(), "lo obsoleto del bundle sí se borra");
    assert!(destino.join("nuevo.js").exists());
}
