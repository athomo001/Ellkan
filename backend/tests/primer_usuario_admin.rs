// Autor: Athan Espinoza

//! Bootstrap: el primer usuario que se auto-registra en una instancia sin
//! ningún usuario previo nace `admin`; cualquier registro posterior nace
//! `user` como siempre (`backend/src/auth/repository.rs::crear`).

mod common;

#[tokio::test]
async fn primer_usuario_de_una_instancia_nueva_nace_admin() {
    let entorno = common::levantar_sin_usuarios().await;
    let primero = common::registrar(&entorno, "primer-usuario@test.ellkan").await;

    let rol: String = sqlx::query_scalar(
        "select r.name from users u join roles r on r.id = u.role_id where u.id = $1",
    )
    .bind(primero.user_id)
    .fetch_one(&entorno.pool)
    .await
    .unwrap();

    assert_eq!(rol, "admin", "el primer registro de una instancia nueva debe nacer admin");
}

#[tokio::test]
async fn segundo_usuario_nace_user_aunque_el_primero_ya_sea_admin() {
    let entorno = common::levantar_sin_usuarios().await;
    common::registrar(&entorno, "primero@test.ellkan").await;
    let segundo = common::registrar(&entorno, "segundo@test.ellkan").await;

    let rol: String = sqlx::query_scalar(
        "select r.name from users u join roles r on r.id = u.role_id where u.id = $1",
    )
    .bind(segundo.user_id)
    .fetch_one(&entorno.pool)
    .await
    .unwrap();

    assert_eq!(rol, "user", "a partir del segundo registro, sigue naciendo user como siempre");
}
