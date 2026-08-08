// Autor: Athan Espinoza

#[derive(Debug, Clone)]
pub struct Preferencias {
    pub locale: String,
    pub theme: String,
    pub clipboard_clear_minutes: i32,
    pub auto_lock_minutes: Option<i32>,
}
