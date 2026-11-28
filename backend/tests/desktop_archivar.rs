// Autor: Athan Espinoza

//! Login → «Usar mi cuenta de un servidor» con otra cuenta en el equipo: la
//! bóveda anterior se guarda entera en `backups/` (con lo que estaba en el
//! `-wal`) y la app arranca vacía. Sólo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::archivar;
use ellkan_backend::desktop::bootstrap_sqlite;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use uuid::Uuid;

#[tokio::test]
async fn archivar_guarda_la_boveda_completa_y_la_siguiente_arranca_vacia() {
    let dir = std::env::temp_dir().join(format!("ellkan_test_archivar_{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();

    // Bóveda con un dato escrito y la conexión todavía abierta: queda en el `-wal`.
    let pool = bootstrap_sqlite(&dir).await.unwrap();
    sqlx::query("create table marca_de_prueba (valor text)").execute(&pool).await.unwrap();
    sqlx::query("insert into marca_de_prueba values ('dato de la cuenta anterior')")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    archivar::marcar(&dir).unwrap();
    assert!(archivar::pendiente(&dir));
    let copia = archivar::ejecutar(&dir).await.unwrap().expect("había una bóveda que archivar");

    assert!(!archivar::pendiente(&dir), "la marca se quita al terminar");
    assert!(!dir.join("ellkan.db").exists(), "la bóveda anterior ya no está en su lugar");
    assert!(copia.starts_with(dir.join("backups")));

    let archivada = SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(&copia).create_if_missing(false))
        .await
        .unwrap();
    let valor: String = sqlx::query_scalar("select valor from marca_de_prueba").fetch_one(&archivada).await.unwrap();
    assert_eq!(valor, "dato de la cuenta anterior");
    archivada.close().await;

    let nueva = bootstrap_sqlite(&dir).await.unwrap();
    let usuarios: i64 = sqlx::query_scalar("select count(*) from users").fetch_one(&nueva).await.unwrap();
    assert_eq!(usuarios, 0, "la app arranca como recién instalada");
    nueva.close().await;
    std::fs::remove_dir_all(&dir).ok();
}
