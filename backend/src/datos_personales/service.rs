// Autor: Athan Espinoza

//! Service de la exportación de datos personales — nunca importa `axum`.

use uuid::Uuid;

use crate::error::DomainError;

use super::models::DatosPersonales;
use super::repository::DatosPersonalesRepository;

pub struct DatosPersonalesService<'a, R> {
    pub repo: &'a R,
}

impl<R: DatosPersonalesRepository> DatosPersonalesService<'_, R> {
    pub async fn exportar(&self, user_id: Uuid) -> Result<DatosPersonales, DomainError> {
        self.repo.leer(user_id).await?.ok_or(DomainError::NotFound)
    }
}
