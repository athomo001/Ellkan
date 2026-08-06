// Autor: Athan Espinoza

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub data_retention_days: i32,
    pub audit_log_retention_days: i32,
}

/// Cuántas filas se purgaron por tabla en una corrida del job — para el
/// evento de auditoría y para que el test pueda verificar sin adivinar.
#[derive(Debug, Clone, Default)]
pub struct ResultadoPurga {
    pub resources: u64,
    pub folders: u64,
    pub tags: u64,
    pub groups: u64,
    pub user_totp_credentials: u64,
    pub audit_log_entries: u64,
}
