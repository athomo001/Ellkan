-- Autor: Athan Espinoza

-- Avatar del único usuario local. Tabla aparte (una sola fila) y no columnas
-- en `users`, a propósito: `reemplazar_identidad` borra `users` al vincular la
-- bóveda con su cuenta del servidor, y la foto local tiene que sobrevivir a
-- eso para poder subirse allá si la cuenta del servidor no tiene ninguna.
-- Igual que en Postgres, no es un dato secreto: se guarda en claro.
create table avatar_local (
    id integer primary key check (id = 1),
    bytes blob not null,
    content_type text not null
);
