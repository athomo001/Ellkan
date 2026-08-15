// Autor: Athan Espinoza

#[derive(Debug, Clone)]
pub struct SelfRegistrationPolicy {
    pub enabled: bool,
    /// Vacío = sin restricción de dominio (cualquier email). No vacío =
    /// allowlist estricta.
    pub allowed_domains: Vec<String>,
}
