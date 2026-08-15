-- Autor: Athan Espinoza

-- F-03: passkeys. `passkey_data` guarda el `Passkey` de `webauthn-rs`
-- serializado tal cual (opaco para nuestro código, sólo esa librería lo
-- interpreta) — `credential_id` se extrae aparte sólo para poder indexar.
create table passkeys (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    credential_id bytea not null unique,
    passkey_data jsonb not null,
    -- Nullable: null si el autenticador no soporta la extensión PRF de
    -- WebAuthn, en cuyo caso esta passkey sólo reemplaza el paso HTTP de
    -- login, sin desbloquear cripto (F-03). El servidor nunca calcula ni ve
    -- la salida PRF en sí — es 100% client-side; esto es sólo el blob
    -- opaco que el cliente decide subir.
    prf_wrapped_private_key bytea,
    label text,
    created_at timestamptz not null default now(),
    last_used_at timestamptz
);

create index passkeys_user_id_idx on passkeys(user_id);

-- Estado efímero de una ceremonia WebAuthn en curso (entre /options y
-- /verify) — persistido en Postgres, no en memoria del proceso, mismo
-- criterio que `auth_challenges` de Fase 0: sobrevive un reinicio del
-- backend a mitad de una ceremonia. Una ceremonia nueva reemplaza (upsert)
-- cualquier pendiente sin terminar del mismo tipo para ese usuario.
create table webauthn_ceremony_state (
    user_id uuid not null references users(id),
    kind text not null check (kind in ('register', 'authenticate')),
    state_json jsonb not null,
    expires_at timestamptz not null,
    primary key (user_id, kind)
);
