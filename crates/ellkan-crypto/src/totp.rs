// Autor: Athan Espinoza

//! Desbloqueo local rápido con TOTP (F-38): cambia "algo que sabés"
//! (passphrase) por "algo que tenés" (secreto TOTP local), opt-in por
//! dispositivo, validación 100% client-side sin request al backend — el
//! servidor nunca participa ni se entera de que existe. Independiente del
//! TOTP de login (F-14/F-08).
//!
//! El algoritmo (RFC 4226/6238, HMAC-SHA1) no es una elección de diseño
//! propia — es el estándar que esperan las apps autenticadoras (Google
//! Authenticator y similares); SHA-1 está obsoleto para uso propio pero acá
//! es interoperabilidad, no una decisión de seguridad nueva.

use hmac::{digest::KeyInit, Hmac, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha1::Sha1;

use crate::aead::{cifrar, descifrar, Envoltura, ErrorAead};
use crate::aleatoriedad::bytes_aleatorios;
use crate::comparacion::secreto_coincide;
use crate::derivacion::{contexto, derivar_clave_desde_secreto};
use crate::secretos::PassphraseSecreta;

type HmacSha1 = Hmac<Sha1>;

/// Longitud del secreto TOTP en bytes (160 bits) — la convención de RFC 4226
/// y de las apps autenticadoras habituales.
pub const SECRETO_LEN: usize = 20;
const PASO_SEGUNDOS: u64 = 30;
const DIGITOS: u32 = 6;
/// Intentos fallidos consecutivos antes de aplicar backoff.
const INTENTOS_ANTES_DE_BLOQUEAR: u32 = 3;
const BLOQUEO_SEGUNDOS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum ErrorTotp {
    #[error("demasiados intentos fallidos, esperá antes de volver a intentar")]
    Bloqueado,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorDesenvolturaTotp {
    #[error(transparent)]
    Aead(#[from] ErrorAead),
    #[error("la passphrase descifrada no es UTF-8 válido")]
    Utf8Invalido,
}

/// Genera un secreto TOTP nuevo para este dispositivo — CSPRNG, nunca
/// derivado de otra cosa (independiente del TOTP de login, F-14).
pub fn generar_secreto_totp() -> [u8; SECRETO_LEN] {
    bytes_aleatorios::<SECRETO_LEN>()
}

/// HOTP (RFC 4226) sobre un contador de pasos dado.
fn hotp(secreto: &[u8], contador: u64) -> u32 {
    let mut mac =
        HmacSha1::new_from_slice(secreto).expect("HMAC-SHA1 acepta claves de cualquier longitud");
    mac.update(&contador.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let codigo_binario = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    codigo_binario % 10u32.pow(DIGITOS)
}

/// Código TOTP (RFC 6238) para el paso de tiempo que contiene `tiempo_unix`.
/// El tiempo se recibe como parámetro (no se lee `SystemTime::now()` acá)
/// porque este crate corre también en `wasm32-unknown-unknown` sin reloj de
/// sistema disponible — el llamador (web/extensión/CLI) provee la hora.
pub fn codigo_totp(secreto: &[u8], tiempo_unix: u64) -> u32 {
    hotp(secreto, tiempo_unix / PASO_SEGUNDOS)
}

fn formatear_codigo(codigo: u32) -> String {
    format!("{codigo:0width$}", width = DIGITOS as usize)
}

/// Verifica un código de 6 dígitos contra el secreto, tolerando ±1 paso de
/// reloj (RFC 6238 recomienda una ventana pequeña para tolerar desfasaje) —
/// comparación en tiempo constante contra cada candidato de la ventana.
pub fn verificar_totp(secreto: &[u8], codigo_recibido: u32, tiempo_unix: u64) -> bool {
    let contador_actual = tiempo_unix / PASO_SEGUNDOS;
    let recibido = formatear_codigo(codigo_recibido);
    (contador_actual.saturating_sub(1)..=contador_actual + 1)
        .any(|contador| secreto_coincide(formatear_codigo(hotp(secreto, contador)).as_bytes(), recibido.as_bytes()))
}

/// Envuelve la passphrase con una clave derivada (HKDF, sin Argon2id) del
/// secreto TOTP — el envoltorio resultante se guarda cifrado sólo en este
/// dispositivo, nunca en el servidor.
pub fn envolver_passphrase(
    secreto_totp: &[u8],
    passphrase: &PassphraseSecreta,
    aad: &[u8],
) -> Result<Envoltura, ErrorAead> {
    let clave = derivar_clave_desde_secreto(secreto_totp, contexto::DESBLOQUEO_TOTP);
    cifrar(&clave, passphrase.expose_secret().as_bytes(), aad)
}

/// Abre el envoltorio y reconstruye la passphrase — sólo se llama tras un
/// `ControlDeIntentos::intentar` exitoso.
pub fn desenvolver_passphrase(
    secreto_totp: &[u8],
    envoltura: &Envoltura,
    aad: &[u8],
) -> Result<PassphraseSecreta, ErrorDesenvolturaTotp> {
    let clave = derivar_clave_desde_secreto(secreto_totp, contexto::DESBLOQUEO_TOTP);
    let bytes = descifrar(&clave, envoltura, aad)?;
    let texto = String::from_utf8(bytes).map_err(|_| ErrorDesenvolturaTotp::Utf8Invalido)?;
    Ok(SecretBox::new(Box::new(texto)))
}

/// Backoff tras intentos fallidos — la validación es 100% client-side, así
/// que sin este control un atacante con acceso al dispositivo podría probar
/// códigos sin límite. Basado en `tiempo_unix` provisto por el llamador, no
/// en un reloj monotónico interno (ver nota de `codigo_totp` sobre WASM).
#[derive(Default)]
pub struct ControlDeIntentos {
    fallos_consecutivos: u32,
    bloqueado_hasta_unix: Option<u64>,
}

impl ControlDeIntentos {
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Intenta validar un código. Devuelve `Err(ErrorTotp::Bloqueado)` si el
    /// backoff sigue activo — ni siquiera evalúa el código en ese caso.
    pub fn intentar(&mut self, secreto: &[u8], codigo: u32, tiempo_unix: u64) -> Result<bool, ErrorTotp> {
        if let Some(bloqueado_hasta) = self.bloqueado_hasta_unix
            && tiempo_unix < bloqueado_hasta
        {
            return Err(ErrorTotp::Bloqueado);
        }
        let valido = verificar_totp(secreto, codigo, tiempo_unix);
        if valido {
            self.fallos_consecutivos = 0;
            self.bloqueado_hasta_unix = None;
        } else {
            self.fallos_consecutivos += 1;
            if self.fallos_consecutivos >= INTENTOS_ANTES_DE_BLOQUEAR {
                self.bloqueado_hasta_unix = Some(tiempo_unix + BLOQUEO_SEGUNDOS);
            }
        }
        Ok(valido)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectores de RFC 6238 Apéndice B (secreto ASCII de 20 bytes, HMAC-SHA1),
    /// truncados a 6 dígitos: `valor_de_8_digitos % 10^6`.
    const SECRETO_RFC: &[u8] = b"12345678901234567890";

    #[test]
    fn vectores_rfc6238_truncados_a_6_digitos() {
        assert_eq!(codigo_totp(SECRETO_RFC, 59), 287_082);
        assert_eq!(codigo_totp(SECRETO_RFC, 1_111_111_109), 81_804);
        assert_eq!(codigo_totp(SECRETO_RFC, 1_111_111_111), 50_471);
        assert_eq!(codigo_totp(SECRETO_RFC, 1_234_567_890), 5_924);
        assert_eq!(codigo_totp(SECRETO_RFC, 2_000_000_000), 279_037);
    }

    #[test]
    fn verificar_totp_acepta_el_codigo_del_paso_actual() {
        let codigo = codigo_totp(SECRETO_RFC, 59);
        assert!(verificar_totp(SECRETO_RFC, codigo, 59));
    }

    #[test]
    fn verificar_totp_rechaza_codigo_incorrecto() {
        assert!(!verificar_totp(SECRETO_RFC, 0, 59));
    }

    #[test]
    fn verificar_totp_tolera_un_paso_de_desfasaje() {
        // Mismo contador (59/30 = 1) pero evaluado con la hora del paso siguiente.
        let codigo = codigo_totp(SECRETO_RFC, 59);
        assert!(verificar_totp(SECRETO_RFC, codigo, 59 + PASO_SEGUNDOS));
    }

    #[test]
    fn verificar_totp_no_tolera_dos_pasos_de_desfasaje() {
        let codigo = codigo_totp(SECRETO_RFC, 59);
        assert!(!verificar_totp(SECRETO_RFC, codigo, 59 + 2 * PASO_SEGUNDOS));
    }

    #[test]
    fn envuelve_y_desenvuelve_la_passphrase_correctamente() {
        let secreto = generar_secreto_totp();
        let pass: PassphraseSecreta = SecretBox::new(Box::new("passphrase-de-prueba".to_string()));
        let aad = b"device_id:1";
        let envoltura = envolver_passphrase(&secreto, &pass, aad).unwrap();
        let recuperada = desenvolver_passphrase(&secreto, &envoltura, aad).unwrap();
        assert_eq!(recuperada.expose_secret(), "passphrase-de-prueba");
    }

    #[test]
    fn secreto_totp_distinto_no_desenvuelve() {
        let secreto_a = generar_secreto_totp();
        let secreto_b = generar_secreto_totp();
        let pass: PassphraseSecreta = SecretBox::new(Box::new("passphrase".to_string()));
        let envoltura = envolver_passphrase(&secreto_a, &pass, b"aad").unwrap();
        assert!(desenvolver_passphrase(&secreto_b, &envoltura, b"aad").is_err());
    }

    #[test]
    fn control_de_intentos_bloquea_tras_tres_fallos() {
        let secreto = generar_secreto_totp();
        let mut control = ControlDeIntentos::nuevo();
        assert!(!control.intentar(&secreto, 0, 0).unwrap());
        assert!(!control.intentar(&secreto, 0, 0).unwrap());
        assert!(!control.intentar(&secreto, 0, 0).unwrap());
        // Cuarto intento: bloqueado, ni siquiera evalúa el código correcto.
        let codigo_correcto = codigo_totp(&secreto, 0);
        assert!(matches!(
            control.intentar(&secreto, codigo_correcto, 0),
            Err(ErrorTotp::Bloqueado)
        ));
    }

    #[test]
    fn control_de_intentos_desbloquea_pasado_el_tiempo_de_backoff() {
        let secreto = generar_secreto_totp();
        let mut control = ControlDeIntentos::nuevo();
        let _ = control.intentar(&secreto, 0, 0);
        let _ = control.intentar(&secreto, 0, 0);
        let _ = control.intentar(&secreto, 0, 0);
        let codigo_correcto = codigo_totp(&secreto, BLOQUEO_SEGUNDOS);
        assert!(control.intentar(&secreto, codigo_correcto, BLOQUEO_SEGUNDOS).unwrap());
    }
}
