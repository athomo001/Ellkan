// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// `since` ausente = sync completo desde el principio (primera vinculación,
/// spec/13 §7 "vinculación inicial"). Presente = sólo lo cambiado desde ese
/// momento — el valor viene del `cursor` de la respuesta anterior.
#[derive(Debug, Deserialize, Default)]
pub struct SyncQuery {
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub since: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct SyncSecretItem {
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
}

/// `deleted: true` = tombstone — el resto de los campos van en `None`, el
/// cliente sólo necesita el `id` para borrar su copia local. `secret`
/// siempre `Some` cuando `!deleted` (F-05: 1 fila de `secret_envelopes` por
/// destinatario, sellada para quien pide el sync).
#[derive(Debug, Serialize)]
pub struct SyncResourceItem {
    pub id: Uuid,
    pub deleted: bool,
    pub resource_type_slug: Option<String>,
    pub metadata_ciphertext_b64: Option<String>,
    pub metadata_nonce_b64: Option<String>,
    pub created_by: Option<Uuid>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
    pub metadata_key_type: Option<String>,
    pub metadata_key_id: Option<Uuid>,
    /// Carpeta donde el que pide el sync tiene posicionado este recurso —
    /// `None` = raíz, o el recurso todavía no tiene posición.
    pub folder_id: Option<Uuid>,
    pub secret: Option<SyncSecretItem>,
}

#[derive(Debug, Serialize)]
pub struct SyncFolderItem {
    pub folder_id: Uuid,
    pub deleted: bool,
    pub parent_folder_id: Option<Uuid>,
    pub name_ciphertext_b64: Option<String>,
    pub name_nonce_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncTagItem {
    pub id: Uuid,
    pub deleted: bool,
    pub name: Option<String>,
    pub is_shared: Option<bool>,
    pub created_by: Option<Uuid>,
}

/// `cursor`: se fija con el reloj del servidor ANTES de correr las
/// consultas (no el máximo `updated_at` visto en la respuesta) — así un
/// cambio que llegue a mitad de la consulta no se pierde: en el peor caso
/// aparece de nuevo en el próximo pull, nunca desaparece.
#[derive(Debug, Serialize)]
pub struct SyncResponse {
    #[serde(with = "time::serde::rfc3339")]
    pub cursor: OffsetDateTime,
    pub resources: Vec<SyncResourceItem>,
    pub folders: Vec<SyncFolderItem>,
    pub tags: Vec<SyncTagItem>,
}
