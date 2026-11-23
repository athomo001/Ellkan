// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

use super::models::TextosLegales;

pub trait LegalLinksRepository {
    async fn obtener(&self) -> Result<TextosLegales, RepoError>;
    async fn actualizar(&self, textos: &TextosLegales) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgLegalLinksRepository {
    pub pool: sqlx::PgPool,
}

impl LegalLinksRepository for PgLegalLinksRepository {
    async fn obtener(&self) -> Result<TextosLegales, RepoError> {
        let fila = sqlx::query!(r#"select privacy_url, terms_url from legal_links where id"#)
            .fetch_one(&self.pool)
            .await?;
        Ok(TextosLegales { privacy_url: fila.privacy_url, terms_url: fila.terms_url })
    }

    async fn actualizar(&self, textos: &TextosLegales) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update legal_links set privacy_url = $1, terms_url = $2, updated_at = now() where id"#,
            textos.privacy_url,
            textos.terms_url,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
