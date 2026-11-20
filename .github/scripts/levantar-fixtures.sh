#!/usr/bin/env bash
# Autor: Athan Espinoza
#
# Pendiente #127: levanta los servicios externos de los tests de integración
# (OpenLDAP para `directory_sync.rs`, Keycloak para `sso_oidc.rs`) con los
# datos de `backend/tests/fixtures/`. Lo usa el CI y sirve igual en local:
#
#   bash .github/scripts/levantar-fixtures.sh          # levantar
#   bash .github/scripts/levantar-fixtures.sh --bajar  # borrar los contenedores
#
# Después, los tests necesitan ELLKAN_DIRECTORY_SYNC_INSECURE_TLS=1 (el
# certificado del LDAP de prueba es autofirmado).
set -euo pipefail

# Fijadas por digest (mismo criterio que QA-29); el tag va de referencia.
LDAP_IMAGEN="osixia/openldap@sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28" # 1.5.0
KEYCLOAK_IMAGEN="quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007" # 26.4
LDAP="ellkan-test-ldap"
KEYCLOAK="ellkan-test-keycloak"
BASE_DN="dc=ellkan-test,dc=example"
ADMIN_DN="cn=admin,$BASE_DN"
ADMIN_PASS="admin_password"

# Git Bash en Windows: que no reescriba las rutas de dentro del contenedor.
export MSYS_NO_PATHCONV=1

raiz="$(cd "$(dirname "$0")/../.." && pwd)"
fixtures="$raiz/backend/tests/fixtures"
dir_keycloak="$fixtures/keycloak"
if command -v cygpath > /dev/null; then dir_keycloak="$(cygpath -w "$dir_keycloak")"; fi

docker rm -f "$LDAP" "$KEYCLOAK" > /dev/null 2>&1 || true
if [ "${1:-}" = "--bajar" ]; then exit 0; fi

docker run -d --name "$LDAP" -p 6360:636 \
  -e LDAP_ORGANISATION="Ellkan Test" -e LDAP_DOMAIN=ellkan-test.example \
  -e LDAP_ADMIN_PASSWORD="$ADMIN_PASS" -e LDAP_TLS_VERIFY_CLIENT=never \
  "$LDAP_IMAGEN" > /dev/null

docker run -d --name "$KEYCLOAK" -p 8090:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$dir_keycloak:/opt/keycloak/data/import:ro" \
  "$KEYCLOAK_IMAGEN" start-dev --import-realm > /dev/null

echo "Esperando a OpenLDAP…"
for _ in $(seq 1 60); do
  if docker exec "$LDAP" ldapsearch -x -H ldap://localhost -D "$ADMIN_DN" -w "$ADMIN_PASS" -b "$BASE_DN" -s base > /dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker exec -i "$LDAP" ldapadd -x -H ldap://localhost -D "$ADMIN_DN" -w "$ADMIN_PASS" < "$fixtures/ldap/semilla.ldif"

echo "Esperando a Keycloak…"
for _ in $(seq 1 120); do
  if curl -sf http://localhost:8090/realms/ellkan-test/.well-known/openid-configuration > /dev/null; then
    echo "Fixtures listos: LDAPS en localhost:6360, Keycloak en localhost:8090."
    exit 0
  fi
  sleep 2
done
echo "Keycloak no arrancó a tiempo:" >&2
docker logs --tail 50 "$KEYCLOAK" >&2
exit 1
