// Autor: Athan Espinoza

//! Service de carpetas (F-09/F-11) — nunca importa `axum`. Reposicionar la
//! propia vista de una carpeta sigue sin control de acceso (F-09 original:
//! "nunca toca la vista de otro usuario", así que no hay nada ajeno que
//! proteger ahí). Lo que sí gana control de acceso (F-11, "permisos tipo
//! Passbolt") es: quién puede mover un recurso hacia/desde una carpeta ya
//! compartida, y quién puede compartir una carpeta — una carpeta sin
//! ninguna fila en `permissions` (nunca compartida, incluidas todas las
//! creadas antes de F-11) se trata como personal/sin restricción, mismo
//! bypass que hace Passbolt para carpetas 100% personales.

use uuid::Uuid;

use crate::admin::repository::RoleRepository;
use crate::error::DomainError;
use crate::groups::repository::GroupMemberRepository;
use crate::resources::models::NivelPermiso;
use crate::resources::repository::PermissionRepository;

use super::models::{Folder, NodoDeArbol};
use super::repository::{FolderItemRepository, FolderRepository};

/// 2026-08-11: hallazgo real de uso — un usuario regular queda en carpetas
/// planas (profundidad 1, su "espacio de trabajo principal", sin anidar ni
/// compartir — `parent_folder_id` siempre `None` para ese rol, ver
/// `es_privilegiado`); un admin de grupo (o de organización) puede anidar
/// hasta este nivel. Mismo patrón que `groups.max_group_depth`, pero sin
/// columna configurable en `organizations` — no se pidió que sea ajustable,
/// agregarla sería alcance de más.
const MAX_FOLDER_DEPTH_PRIVILEGIADO: i32 = 3;

pub struct FolderService<'a, F, FI, P, GM, RR> {
    pub carpetas: &'a F,
    pub items: &'a FI,
    pub permisos: &'a P,
    pub grupos: &'a GM,
    pub roles: &'a RR,
}

impl<'a, F, FI, P, GM, RR> FolderService<'a, F, FI, P, GM, RR>
where
    F: FolderRepository,
    FI: FolderItemRepository,
    P: PermissionRepository,
    GM: GroupMemberRepository,
    RR: RoleRepository,
{
    /// 2026-08-11: admin de organización o admin de al menos un grupo —
    /// único conjunto de gente que puede anidar/compartir carpetas. Un
    /// usuario regular no llega a ninguna de las dos.
    async fn es_privilegiado(&self, user_id: Uuid) -> Result<bool, DomainError> {
        Ok(self.grupos.es_admin_de_algun_grupo(user_id).await?
            || self.roles.usuario_tiene_permiso(user_id, "*").await?)
    }

    pub async fn crear(
        &self,
        user_id: Uuid,
        id: Uuid,
        name_ciphertext: &[u8],
        name_nonce: &[u8],
        parent_folder_id: Option<Uuid>,
    ) -> Result<Folder, DomainError> {
        if let Some(padre) = parent_folder_id {
            self.carpetas
                .buscar(padre)
                .await?
                .ok_or_else(|| DomainError::ValidacionInvalida("parent_folder_id no existe".into()))?;

            let privilegiado = self.es_privilegiado(user_id).await?;
            if !privilegiado {
                return Err(DomainError::PermissionDenied);
            }
            let profundidad_nueva = self.carpetas.profundidad(user_id, padre).await? + 1;
            if profundidad_nueva > MAX_FOLDER_DEPTH_PRIVILEGIADO {
                return Err(DomainError::ValidacionInvalida(format!(
                    "excede la profundidad máxima de carpetas ({MAX_FOLDER_DEPTH_PRIVILEGIADO})"
                )));
            }
        }

        let carpeta = self.carpetas.crear(id).await?;
        self.items.insertar_carpeta(user_id, carpeta.id, parent_folder_id, name_ciphertext, name_nonce).await?;
        self.permisos.otorgar("folder", carpeta.id, "user", user_id, NivelPermiso::Owner.as_db_str()).await?;
        Ok(carpeta)
    }

    pub async fn listar_arbol(&self, user_id: Uuid) -> Result<Vec<NodoDeArbol>, DomainError> {
        Ok(self.items.arbol_de(user_id).await?)
    }

    /// Reposiciona una carpeta sólo en el árbol de `user_id` — nunca toca la
    /// vista de otro usuario, aunque tenga la misma carpeta en la suya
    /// (F-09, criterio de aceptación literal). Sin chequeo de permisos: es
    /// 100% la vista propia de quien llama, no afecta a nadie más.
    pub async fn mover(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        new_parent_folder_id: Option<Uuid>,
    ) -> Result<(), DomainError> {
        if Some(folder_id) == new_parent_folder_id {
            return Err(DomainError::ValidacionInvalida("una carpeta no puede ser su propio padre".into()));
        }

        if !self.items.tiene_en_su_arbol(user_id, folder_id).await? {
            return Err(DomainError::NotFound);
        }

        if let Some(padre) = new_parent_folder_id {
            self.carpetas
                .buscar(padre)
                .await?
                .ok_or_else(|| DomainError::ValidacionInvalida("new_parent_folder_id no existe".into()))?;

            // Bug latente real encontrado en el camino (2026-08-11): esta
            // función nunca detectó ciclos más allá del auto-padre directo
            // — `A.parent=B` y después `B.parent=A` no tenía nada que lo
            // impidiera. Mismo chequeo que ya tiene `GroupService::mover`.
            if self.carpetas.ancestros_inclusive(user_id, padre).await?.contains(&folder_id) {
                return Err(DomainError::ValidacionInvalida(
                    "ese movimiento crearía un ciclo en el árbol de carpetas".into(),
                ));
            }

            if !self.es_privilegiado(user_id).await? {
                return Err(DomainError::PermissionDenied);
            }
            let profundidad_nueva = self.carpetas.profundidad(user_id, padre).await? + 1;
            if profundidad_nueva > MAX_FOLDER_DEPTH_PRIVILEGIADO {
                return Err(DomainError::ValidacionInvalida(format!(
                    "excede la profundidad máxima de carpetas ({MAX_FOLDER_DEPTH_PRIVILEGIADO})"
                )));
            }
        }

        self.items.reposicionar_carpeta(user_id, folder_id, new_parent_folder_id).await?;
        Ok(())
    }

    /// F-11: mueve un RECURSO a una carpeta (o a la raíz, `folder_id: None`)
    /// en el árbol de `user_id`. A diferencia de `mover` (reposicionar la
    /// vista propia de una carpeta, sin restricción), esto exige `update`
    /// sobre la carpeta destino si ya está compartida — moverlo a una
    /// carpeta compartida **nunca comparte el recurso automáticamente**
    /// (igual que Passbolt: compartir sigue siendo `compartir_recurso`,
    /// un paso client-side aparte, imposible de saltear en una arquitectura
    /// zero-knowledge — el servidor no puede otorgar acceso a un secreto
    /// cifrado).
    ///
    /// 2026-08-11: excepción para carpetas de grupo — cualquier miembro del
    /// grupo dueño puede agregar recursos (hallazgo real de uso: "todos los
    /// users pueden agregar contraseñas a las carpetas que están
    /// agregados"), no hace falta `update` sobre la carpeta en sí como para
    /// una carpeta compartida a un usuario individual. Ceder/mantener la
    /// propiedad del recurso hacia el grupo sigue siendo un paso aparte del
    /// cliente vía `POST /resources/share-bulk` (ya existente) contra los
    /// miembros actuales del grupo, con nivel `update` (ceder) o `read`
    /// (mantener, sólo visibilidad) — mismo motivo zero-knowledge de
    /// siempre, el servidor no puede resellar una DEK que no puede leer.
    pub async fn mover_recurso(
        &self,
        user_id: Uuid,
        resource_id: Uuid,
        folder_id: Option<Uuid>,
    ) -> Result<(), DomainError> {
        // Hallazgo de seguridad (auditoría 2026-08-12, H-02): esta función
        // sólo validaba autorización sobre la carpeta DESTINO, nunca sobre
        // el recurso movido — un admin de grupo sin ningún permiso sobre
        // `resource_id` podía "enmarcarlo" en una carpeta propia compartida
        // con su grupo y de ahí borrarlo vía `ResourceService::eliminar`
        // (que confía en `carpetas_de_recurso` sin volver a chequear
        // ownership). Mismo nivel mínimo que el resto de las lecturas de
        // recurso (`obtener`, `obtener_secreto`, `listar_destinatarios`).
        if !self.permisos.tiene_permiso("resource", resource_id, user_id, NivelPermiso::Read.as_db_str()).await? {
            return Err(DomainError::PermissionDenied);
        }

        if let Some(destino) = folder_id {
            self.carpetas
                .buscar(destino)
                .await?
                .ok_or_else(|| DomainError::ValidacionInvalida("folder_id no existe".into()))?;

            let autorizado = if let Some(group_id) = self.permisos.grupo_grantee_de("folder", destino).await? {
                self.grupos.es_miembro(group_id, user_id).await?
            } else {
                let compartida = self.permisos.existe_algun_permiso("folder", destino).await?;
                if compartida {
                    self.permisos.tiene_permiso("folder", destino, user_id, NivelPermiso::Update.as_db_str()).await?
                } else {
                    self.items.tiene_en_su_arbol(user_id, destino).await?
                }
            };
            if !autorizado {
                return Err(DomainError::PermissionDenied);
            }
        }

        self.items.posicionar_recurso(user_id, resource_id, folder_id).await?;
        Ok(())
    }

    /// 2026-08-11: chequeo común a `compartir`/`compartir_a_grupo` — sólo
    /// admin de grupo o de organización llega a compartir CUALQUIER carpeta
    /// (hallazgo real de uso: un usuario regular no puede compartir
    /// carpetas, quedan 100% personales), y sigue exigiendo `owner` sobre
    /// la carpeta puntual como ya exigía antes de esta fecha.
    async fn verificar_puede_compartir(&self, actor_id: Uuid, folder_id: Uuid) -> Result<(), DomainError> {
        if !self.es_privilegiado(actor_id).await? {
            return Err(DomainError::PermissionDenied);
        }
        self.carpetas.buscar(folder_id).await?.ok_or(DomainError::NotFound)?;
        if !self.permisos.tiene_permiso("folder", folder_id, actor_id, NivelPermiso::Owner.as_db_str()).await? {
            return Err(DomainError::PermissionDenied);
        }
        Ok(())
    }

    /// F-11: comparte una carpeta con otro usuario — exige `owner` sobre
    /// ella. El cliente ya reselló el nombre para el destinatario
    /// (`sellar_para`, mismo patrón que compartir un recurso); acá sólo se
    /// persiste el permiso nuevo y la fila de árbol del destinatario (nace
    /// en la raíz de su propio árbol — puede reposicionarla después con
    /// `mover`, sin que eso afecte a nadie más).
    pub async fn compartir(
        &self,
        actor_id: Uuid,
        folder_id: Uuid,
        grantee_user_id: Uuid,
        nivel: &str,
        name_ciphertext_para_destinatario: &[u8],
        name_nonce_para_destinatario: &[u8],
    ) -> Result<(), DomainError> {
        if !["read", "update", "owner"].contains(&nivel) {
            return Err(DomainError::ValidacionInvalida("nivel de permiso inválido".into()));
        }

        self.verificar_puede_compartir(actor_id, folder_id).await?;

        self.permisos.otorgar("folder", folder_id, "user", grantee_user_id, nivel).await?;
        self.items
            .insertar_carpeta(grantee_user_id, folder_id, None, name_ciphertext_para_destinatario, name_nonce_para_destinatario)
            .await?;
        Ok(())
    }

    /// 2026-08-11: comparte una carpeta con un GRUPO entero (antes sólo se
    /// podía compartir de a un usuario) — mismo chequeo de elegibilidad que
    /// `compartir`. El cliente ya reselló el nombre para CADA miembro actual
    /// del grupo (mismo patrón que `agregar_con_envelopes` de F-12, no hay
    /// forma de que el servidor lo haga por él en zero-knowledge); acá se
    /// persiste el permiso del grupo y una fila de árbol por miembro, todo
    /// en la misma llamada.
    pub async fn compartir_a_grupo(
        &self,
        actor_id: Uuid,
        folder_id: Uuid,
        group_id: Uuid,
        nivel: &str,
        miembros: &[(Uuid, Vec<u8>, Vec<u8>)],
    ) -> Result<(), DomainError> {
        if !["read", "update", "owner"].contains(&nivel) {
            return Err(DomainError::ValidacionInvalida("nivel de permiso inválido".into()));
        }

        self.verificar_puede_compartir(actor_id, folder_id).await?;

        self.permisos.otorgar("folder", folder_id, "group", group_id, nivel).await?;
        for (user_id, name_ciphertext, name_nonce) in miembros {
            self.items.insertar_carpeta(*user_id, folder_id, None, name_ciphertext, name_nonce).await?;
        }
        Ok(())
    }
}
