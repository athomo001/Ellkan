// Autor: Athan Espinoza

//! Una bóveda creada por una app compilada desde una copia de trabajo con
//! CRLF (Windows) guardaba checksums que la app de CI (LF) rechazaba: el
//! backend local no arrancaba y «Conectar» fallaba. `bootstrap_sqlite` debe
//! aceptar esa diferencia (mismo SQL) y seguir rechazando un cambio real.
//! Sólo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::path::PathBuf;

use ellkan_backend::desktop::bootstrap_sqlite;
use sha2::{Digest, Sha384};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use uuid::Uuid;

fn datadir_temporal(nombre: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_checksum_{nombre}_{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn abrir(dir: &std::path::Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(dir.join("ellkan.db")))
        .await
        .unwrap()
}

/// Deja guardado para la migración 8 el checksum de `sql_guardado`.
async fn falsear_checksum_8(dir: &std::path::Path, sql_guardado: impl Fn(&str) -> String) -> Vec<u8> {
    let migrador = sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite");
    let m = migrador.iter().find(|m| m.version == 8).unwrap();
    let falso = Sha384::digest(sql_guardado(m.sql.as_str()).as_bytes()).to_vec();
    let pool = abrir(dir).await;
    sqlx::query("update _sqlx_migrations set checksum = ? where version = 8").bind(&falso).execute(&pool).await.unwrap();
    pool.close().await;
    m.checksum.to_vec()
}

#[tokio::test]
async fn una_boveda_con_checksum_crlf_arranca_y_queda_corregida() {
    let dir = datadir_temporal("crlf");
    bootstrap_sqlite(&dir).await.unwrap().close().await;
    let correcto = falsear_checksum_8(&dir, |sql| sql.replace("\r\n", "\n").replace('\n', "\r\n")).await;

    let pool = bootstrap_sqlite(&dir).await.expect("el mismo SQL con CRLF no debe frenar el arranque");
    let guardado: Vec<u8> = sqlx::query_scalar("select checksum from _sqlx_migrations where version = 8").fetch_one(&pool).await.unwrap();
    assert_eq!(guardado, correcto);
    pool.close().await;
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn un_cambio_real_de_la_migracion_sigue_frenando_el_arranque() {
    let dir = datadir_temporal("cambio");
    bootstrap_sqlite(&dir).await.unwrap().close().await;
    falsear_checksum_8(&dir, |sql| format!("{sql}\n-- otra cosa")).await;

    let err = bootstrap_sqlite(&dir).await.expect_err("un SQL distinto debe seguir rechazándose");
    assert!(format!("{err:#}").contains("previously applied but has been modified"), "{err:#}");
    std::fs::remove_dir_all(&dir).ok();
}
