// Autor: Athan Espinoza

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: Option<String>,
    pub port: Option<i32>,
    pub from_address: Option<String>,
    pub tls: bool,
    pub username: Option<String>,
    pub password_ciphertext: Option<Vec<u8>>,
    pub password_nonce: Option<Vec<u8>>,
}

impl SmtpConfig {
    /// F-02/Parte B: `host` no vacío es la única señal real de "está
    /// configurado" — todo lo demás tiene un default razonable o es opcional.
    pub fn esta_configurado(&self) -> bool {
        self.host.as_deref().is_some_and(|h| !h.trim().is_empty())
    }
}
