-- Autor: Athan Espinoza

-- Cierre de F-02 (Fase 0): dispositivo desconocido dispara verificación por
-- email + cola de emails en Postgres, sin broker externo. `known_devices` ya
-- existía desde 0001; acá se agrega el desafío pendiente y la cola.

-- Un solo código pendiente por (user_id, device_token_hash) a la vez —
-- `code_hash` nunca el código en claro, la comparación en tiempo constante la
-- hace el service, no esta tabla.
create table device_challenges (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    device_token_hash bytea not null,
    code_hash bytea not null,
    expires_at timestamptz not null,
    consumed_at timestamptz
);

create index device_challenges_user_id_idx on device_challenges(user_id);

-- `body` sí contiene el código en claro — es exactamente lo que se manda por
-- email, no es un secreto zero-knowledge del vault. El consumidor real de
-- SMTP (pendiente, Fase 1) lee de acá; el stub de Fase 0 sólo marca `enviado`.
create table outbound_emails (
    id uuid primary key default uuidv7(),
    recipient text not null,
    subject text not null,
    body text not null,
    status text not null default 'pendiente' check (status in ('pendiente', 'enviado', 'fallido')),
    attempts integer not null default 0,
    created_at timestamptz not null default now(),
    sent_at timestamptz
);

create index outbound_emails_status_idx on outbound_emails(status);
