// Autor: Athan Espinoza

//! F-40 (primer checkbox): un registro soft-deleted hace más de
//! `data_retention_days` desaparece físicamente al correr la purga;
//! `audit_log_entries` nunca se purga por esa política (retención propia,
//! `audit_log_retention_days`); una entrada de auditoría reciente sigue
//! bloqueada por el trigger append-only aunque la política de datos general
//! ya haya vencido.

mod common;

use ellkan_backend::retention::repository::{PgPurgeRepository, PgRetentionPolicyRepository, PurgeRepository, RetentionPolicyRepository};
use serde_json::json;

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_la_politica() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/data-retention-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn defaults_de_fabrica_coinciden_con_la_spec() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/data-retention-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["data_retention_days"], 90);
    assert_eq!(cuerpo["audit_log_retention_days"], 365);
}

#[tokio::test]
async fn purga_elimina_lo_vencido_y_nunca_toca_el_audit_log_reciente() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    // Grupo real, soft-deleted vía el endpoint real (deja también una
    // entrada de auditoría reciente, útil para el segundo assert).
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": uuid::Uuid::now_v7(), "name": "grupo-a-purgar" }))
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    let group_id = cuerpo["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/groups/{group_id}", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Fuerza a que quede "viejo" — 100 días atrás, por encima del default
    // de 90.
    sqlx::query("update groups set deleted_at = now() - interval '100 days' where id = $1")
        .bind(group_id.parse::<uuid::Uuid>().unwrap())
        .execute(&entorno.pool)
        .await
        .unwrap();

    let existe_antes: (bool,) =
        sqlx::query_as("select exists(select 1 from groups where id = $1)").bind(group_id.parse::<uuid::Uuid>().unwrap()).fetch_one(&entorno.pool).await.unwrap();
    assert!(existe_antes.0, "el grupo debería seguir en la tabla (soft-delete, no hard-delete)");

    let policy = PgRetentionPolicyRepository { pool: entorno.pool.clone() };
    let purga = PgPurgeRepository { pool: entorno.pool.clone() };
    let politica = policy.obtener().await.unwrap();
    let resultado = purga.purgar(politica.data_retention_days, politica.audit_log_retention_days).await.unwrap();

    assert_eq!(resultado.groups, 1, "el grupo vencido debe purgarse");
    assert_eq!(resultado.audit_log_entries, 0, "ninguna entrada de audit log tiene 365+ días todavía");

    let existe_despues: (bool,) =
        sqlx::query_as("select exists(select 1 from groups where id = $1)").bind(group_id.parse::<uuid::Uuid>().unwrap()).fetch_one(&entorno.pool).await.unwrap();
    assert!(!existe_despues.0, "tras la purga, el grupo vencido ya no debe existir en la tabla");

    // El trigger append-only sigue bloqueando un DELETE manual de una
    // entrada de auditoría reciente, aunque el job de retención en general
    // ya haya corrido — insertada directo (no vía el consumidor asíncrono
    // de eventos) para no depender de su timing.
    sqlx::query("insert into audit_log_entries (actor_user_id, event_type) values ($1, 'auth.logout')")
        .bind(admin.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
    let resultado_delete = sqlx::query("delete from audit_log_entries where actor_user_id = $1")
        .bind(admin.user_id)
        .execute(&entorno.pool)
        .await;
    assert!(resultado_delete.is_err(), "una entrada de audit log reciente sigue protegida por el trigger");
}

#[tokio::test]
async fn purga_no_toca_lo_que_todavia_no_vencio() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": uuid::Uuid::now_v7(), "name": "grupo-reciente" }))
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    let group_id: uuid::Uuid = cuerpo["id"].as_str().unwrap().parse().unwrap();

    entorno.cliente.delete(format!("{}/groups/{group_id}", entorno.base)).bearer_auth(sesion).send().await.unwrap();

    let policy = PgRetentionPolicyRepository { pool: entorno.pool.clone() };
    let purga = PgPurgeRepository { pool: entorno.pool.clone() };
    let politica = policy.obtener().await.unwrap();
    let resultado = purga.purgar(politica.data_retention_days, politica.audit_log_retention_days).await.unwrap();
    assert_eq!(resultado.groups, 0, "un grupo borrado hace un instante no debe purgarse todavía");

    let existe: (bool,) =
        sqlx::query_as("select exists(select 1 from groups where id = $1)").bind(group_id).fetch_one(&entorno.pool).await.unwrap();
    assert!(existe.0);
}
