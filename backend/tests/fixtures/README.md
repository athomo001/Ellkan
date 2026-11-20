# Fixtures de los tests de integración

Autor: Athan Espinoza

Servicios externos que necesitan dos archivos de tests (pendiente #127). El CI (`.github/workflows/ci.yml`) los levanta antes de `cargo test`; en local, los mismos comandos del job sirven tal cual.

| Archivo | Servicio | Lo usa |
| --- | --- | --- |
| `ldap/semilla.ldif` | OpenLDAP con LDAPS en `localhost:6360` (base `dc=ellkan-test,dc=example`, admin `cn=admin,…` / `admin_password`, `uid=carol`) | `backend/tests/directory_sync.rs` |
| `keycloak/ellkan-test-realm.json` | Keycloak en `localhost:8090`, realm `ellkan-test`, cliente público `ellkan-backend`, usuarios `alice` (email verificado) y `bob` (sin verificar) | `backend/tests/sso_oidc.rs` |

Los tests de LDAP aceptan el certificado autofirmado del contenedor (que además ya venció) con `ELLKAN_DIRECTORY_SYNC_INSECURE_TLS=1`; en el CI está a nivel del job, para los dos pasos de tests. Las contraseñas son sólo de prueba.
