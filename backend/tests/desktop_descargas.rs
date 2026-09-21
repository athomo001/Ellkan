// Autor: Athan Espinoza

//! Guardar en escritorio lo que la ventana "descarga": el webview de Tauri no
//! procesa un `<a download>` sobre un blob (el clic no hace nada), así que el
//! backend escribe el archivo en Descargas. El nombre llega desde el frontend
//! y se trata como no confiable. Sólo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::fs;
use std::path::PathBuf;

use ellkan_backend::desktop::descargas::{guardar_sin_pisar, nombre_seguro};
use uuid::Uuid;

fn carpeta_temporal() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_descargas_{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn un_nombre_normal_no_se_toca() {
    assert_eq!(nombre_seguro("ellkan-recovery-kit.txt").as_deref(), Some("ellkan-recovery-kit.txt"));
    assert_eq!(nombre_seguro("Mis contraseñas 2026.kdbx").as_deref(), Some("Mis contraseñas 2026.kdbx"));
}

#[test]
fn las_carpetas_del_nombre_se_descartan_y_no_se_puede_escapar_de_descargas() {
    assert_eq!(nombre_seguro("..\\..\\Windows\\x.txt").as_deref(), Some("x.txt"));
    assert_eq!(nombre_seguro("../../etc/passwd").as_deref(), Some("passwd"));
    assert_eq!(nombre_seguro("/absoluto/kit.txt").as_deref(), Some("kit.txt"));
    assert_eq!(nombre_seguro("C:\\Users\\x\\kit.txt").as_deref(), Some("kit.txt"));
}

#[test]
fn los_caracteres_que_windows_no_acepta_se_reemplazan() {
    assert_eq!(nombre_seguro("a<b>c:d|e?f*g\"h.txt").as_deref(), Some("a_b_c_d_e_f_g_h.txt"));
    assert_eq!(nombre_seguro("con\tcontrol\n.txt").as_deref(), Some("con_control_.txt"));
}

#[test]
fn los_nombres_de_dispositivo_reservados_de_windows_se_evitan() {
    assert_eq!(nombre_seguro("CON.txt").as_deref(), Some("_CON.txt"));
    assert_eq!(nombre_seguro("nul").as_deref(), Some("_nul"));
    assert_eq!(nombre_seguro("Com1.kdbx").as_deref(), Some("_Com1.kdbx"));
    assert_eq!(nombre_seguro("console.txt").as_deref(), Some("console.txt"), "sólo el nombre exacto está reservado");
}

#[test]
fn los_nombres_vacios_o_inutilizables_se_rechazan() {
    for inutil in ["", "   ", ".", "..", "...", "/", "\\", "___", "a/", " . "] {
        // "a/" queda vacío después de quedarse con la última parte.
        assert_eq!(nombre_seguro(inutil), None, "{inutil:?} no es un nombre de archivo utilizable");
    }
}

#[test]
fn el_punto_y_los_espacios_del_final_se_quitan_porque_windows_los_rechaza() {
    assert_eq!(nombre_seguro("  kit.txt. ").as_deref(), Some("kit.txt"));
    assert_eq!(nombre_seguro("kit...").as_deref(), Some("kit"));
}

#[test]
fn un_nombre_larguisimo_se_acorta_conservando_la_extension() {
    let largo = format!("{}.kdbx", "a".repeat(400));
    let seguro = nombre_seguro(&largo).unwrap();
    assert!(seguro.chars().count() <= 150);
    assert!(seguro.ends_with(".kdbx"));
}

#[test]
fn guardar_escribe_el_contenido_y_devuelve_la_ruta() {
    let carpeta = carpeta_temporal();
    let ruta = guardar_sin_pisar(&carpeta, "kit.txt", b"CLAVE-DEL-KIT").unwrap();

    assert_eq!(ruta, carpeta.join("kit.txt"));
    assert_eq!(fs::read(&ruta).unwrap(), b"CLAVE-DEL-KIT");
}

#[test]
fn guardar_nunca_pisa_un_archivo_existente() {
    let carpeta = carpeta_temporal();
    fs::write(carpeta.join("kit.txt"), b"ORIGINAL").unwrap();

    let segundo = guardar_sin_pisar(&carpeta, "kit.txt", b"segundo").unwrap();
    let tercero = guardar_sin_pisar(&carpeta, "kit.txt", b"tercero").unwrap();

    assert_eq!(segundo, carpeta.join("kit (1).txt"));
    assert_eq!(tercero, carpeta.join("kit (2).txt"));
    assert_eq!(fs::read(carpeta.join("kit.txt")).unwrap(), b"ORIGINAL", "el archivo que ya estaba no se toca");
    assert_eq!(fs::read(&segundo).unwrap(), b"segundo");
    assert_eq!(fs::read(&tercero).unwrap(), b"tercero");
}

#[test]
fn guardar_funciona_con_nombres_sin_extension_y_con_bytes_binarios() {
    let carpeta = carpeta_temporal();
    let binario: Vec<u8> = (0..=255).collect();

    let primero = guardar_sin_pisar(&carpeta, "exportacion", &binario).unwrap();
    let segundo = guardar_sin_pisar(&carpeta, "exportacion", &binario).unwrap();

    assert_eq!(primero, carpeta.join("exportacion"));
    assert_eq!(segundo, carpeta.join("exportacion (1)"));
    assert_eq!(fs::read(&primero).unwrap(), binario, "un KDBX/7z no puede alterarse al guardarlo");
}

#[test]
fn guardar_con_un_nombre_con_carpetas_escribe_adentro_de_la_carpeta_de_descargas() {
    let carpeta = carpeta_temporal();
    let ruta = guardar_sin_pisar(&carpeta, "..\\..\\escape.txt", b"x").unwrap();

    assert_eq!(ruta, carpeta.join("escape.txt"));
    assert!(!carpeta.parent().unwrap().join("escape.txt").exists());
}

#[test]
fn guardar_rechaza_un_nombre_invalido_y_una_carpeta_inexistente() {
    let carpeta = carpeta_temporal();
    assert!(guardar_sin_pisar(&carpeta, "..", b"x").is_err());
    assert!(guardar_sin_pisar(&carpeta.join("no_existe"), "kit.txt", b"x").is_err());
}
