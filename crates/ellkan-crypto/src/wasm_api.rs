// Autor: Athan Espinoza

//! Superficie JS del núcleo criptográfico (F-01/F-38, Fase 1.4) — cada
//! función es un wrapper delgado sobre el resto del crate, nunca reimplementa
//! nada acá. Tipos simples (`Vec<u8>`/`String`) cruzan la frontera hacia
//! `Uint8Array`/`string` de JS automáticamente vía `wasm-bindgen`; structs
//! exportados usan getters en vez de campos públicos porque wasm-bindgen no
//! soporta acceso directo a campos de un struct exportado.
//!
//! La clave privada en claro sí cruza hacia JS (a propósito): el store de
//! sesión del cliente ("memory", spec `07-frontend-web.md` sección 1) la
//! mantiene en memoria mientras dura la sesión, igual criterio ya fijado
//! para la extensión (F-04) — nunca se persiste a disco desde acá.

use secrecy::SecretBox;
use wasm_bindgen::prelude::*;

use crate::aead::{self, Envoltura};
use crate::aleatoriedad::bytes_aleatorios;
use crate::clave_privada::{cifrar_clave_privada, descifrar_clave_privada, EncryptedPrivateKeyBlob};
use crate::prf;
use crate::secretos::PassphraseSecreta;
use crate::totp;

fn passphrase_de(valor: String) -> PassphraseSecreta {
    SecretBox::new(Box::new(valor))
}

fn err_js(msg: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&msg.to_string())
}

#[wasm_bindgen]
pub struct Identidad {
    x25519_public: Vec<u8>,
    x25519_private: Vec<u8>,
    ed25519_public: Vec<u8>,
    ed25519_private: Vec<u8>,
}

#[wasm_bindgen]
impl Identidad {
    #[wasm_bindgen(getter)]
    pub fn x25519_public(&self) -> Vec<u8> {
        self.x25519_public.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn x25519_private(&self) -> Vec<u8> {
        self.x25519_private.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ed25519_public(&self) -> Vec<u8> {
        self.ed25519_public.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ed25519_private(&self) -> Vec<u8> {
        self.ed25519_private.clone()
    }
}

/// Genera los dos keypairs de identidad de un usuario nuevo (F-01) — X25519
/// para acuerdo de claves (compartir), Ed25519 para firmar el desafío de
/// login.
#[wasm_bindgen]
pub fn generar_identidad() -> Identidad {
    let x = crate::claves::KeypairAcuerdo::generar();
    let e = crate::claves::KeypairFirma::generar();
    Identidad {
        x25519_public: x.publica().as_bytes().to_vec(),
        x25519_private: x.privada().to_bytes().to_vec(),
        ed25519_public: e.verificadora().to_bytes().to_vec(),
        ed25519_private: e.firmante().to_bytes().to_vec(),
    }
}

#[wasm_bindgen]
pub fn generar_salt_kdf() -> Vec<u8> {
    bytes_aleatorios::<16>().to_vec()
}

#[wasm_bindgen]
pub struct BlobClavePrivada {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[wasm_bindgen]
impl BlobClavePrivada {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
}

/// Cadena completa Argon2id→HKDF→XChaCha20-Poly1305 (F-01) — cifra los dos
/// privados concatenados (64 bytes) con una clave derivada de la
/// passphrase, nunca con el output de Argon2id directo.
#[wasm_bindgen]
pub fn sellar_clave_privada(
    passphrase: String,
    salt: Vec<u8>,
    x25519_private: Vec<u8>,
    ed25519_private: Vec<u8>,
    aad: Vec<u8>,
) -> Result<BlobClavePrivada, JsValue> {
    let salt: [u8; 16] = salt.try_into().map_err(|_| err_js("salt debe ser de 16 bytes"))?;
    let mut privadas = Vec::with_capacity(64);
    privadas.extend_from_slice(&x25519_private);
    privadas.extend_from_slice(&ed25519_private);

    let blob = cifrar_clave_privada(&passphrase_de(passphrase), salt, &privadas, &aad).map_err(err_js)?;
    Ok(BlobClavePrivada { ciphertext: blob.envoltura.ciphertext, nonce: blob.envoltura.nonce.to_vec() })
}

#[wasm_bindgen]
pub struct ClavePrivadaAbierta {
    x25519_private: Vec<u8>,
    ed25519_private: Vec<u8>,
}

#[wasm_bindgen]
impl ClavePrivadaAbierta {
    #[wasm_bindgen(getter)]
    pub fn x25519_private(&self) -> Vec<u8> {
        self.x25519_private.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ed25519_private(&self) -> Vec<u8> {
        self.ed25519_private.clone()
    }
}

/// Reconstruye la clave privada a partir de la passphrase + el blob
/// guardado en el servidor (F-01) — nunca se cachea el resultado, el
/// llamador lo mantiene sólo en el store "memory" de la sesión.
#[wasm_bindgen]
pub fn abrir_clave_privada(
    passphrase: String,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<ClavePrivadaAbierta, JsValue> {
    let salt: [u8; 16] = salt.try_into().map_err(|_| err_js("salt debe ser de 16 bytes"))?;
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| err_js("nonce debe ser de 24 bytes"))?;
    let blob = EncryptedPrivateKeyBlob { salt, envoltura: Envoltura { nonce, ciphertext } };

    let privadas = descifrar_clave_privada(&passphrase_de(passphrase), &blob, &aad)
        .map_err(|_| err_js("passphrase incorrecta o blob inválido"))?;
    if privadas.len() != 64 {
        return Err(err_js("blob de clave privada corrupto"));
    }
    Ok(ClavePrivadaAbierta { x25519_private: privadas[..32].to_vec(), ed25519_private: privadas[32..].to_vec() })
}

/// Firma un nonce de desafío de login con la clave Ed25519 (F-01/F-02).
#[wasm_bindgen]
pub fn firmar(ed25519_private: Vec<u8>, mensaje: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    use ed25519_dalek::{Signer, SigningKey};
    let arreglo: [u8; 32] = ed25519_private.try_into().map_err(|_| err_js("clave privada debe ser de 32 bytes"))?;
    let firmante = SigningKey::from_bytes(&arreglo);
    Ok(firmante.sign(&mensaje).to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn clave_publica_x25519_de(x25519_private: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let arreglo: [u8; 32] = x25519_private.try_into().map_err(|_| err_js("clave privada debe ser de 32 bytes"))?;
    let privada = StaticSecret::from(arreglo);
    Ok(PublicKey::from(&privada).as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn clave_publica_ed25519_de(ed25519_private: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    use ed25519_dalek::SigningKey;
    let arreglo: [u8; 32] = ed25519_private.try_into().map_err(|_| err_js("clave privada debe ser de 32 bytes"))?;
    let firmante = SigningKey::from_bytes(&arreglo);
    Ok(firmante.verifying_key().to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn generar_dek() -> Vec<u8> {
    bytes_aleatorios::<32>().to_vec()
}

/// Sella una DEK (o cualquier payload corto) para la clave pública X25519
/// de un destinatario (F-05/F-06/F-11/F-16/F-36) — caja anónima
/// `crypto_box`, el destinatario no necesita saber quién selló.
#[wasm_bindgen]
pub fn sellar_para(x25519_public_destinatario: Vec<u8>, payload: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    use x25519_dalek::PublicKey;
    let arreglo: [u8; 32] =
        x25519_public_destinatario.try_into().map_err(|_| err_js("clave pública debe ser de 32 bytes"))?;
    let publica = PublicKey::from(arreglo);
    Ok(crate::sellado::sellar_bytes(&publica, &payload))
}

#[wasm_bindgen]
pub fn abrir_sellado(x25519_private: Vec<u8>, sellado: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    use x25519_dalek::StaticSecret;
    let arreglo: [u8; 32] = x25519_private.try_into().map_err(|_| err_js("clave privada debe ser de 32 bytes"))?;
    let privada = StaticSecret::from(arreglo);
    crate::sellado::abrir_bytes(&privada, &sellado).map_err(|_| err_js("no se pudo abrir (clave incorrecta o datos corruptos)"))
}

#[wasm_bindgen]
pub struct Cifrado {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

#[wasm_bindgen]
impl Cifrado {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
}

/// AEAD genérico (F-05/F-06/F-07) — usado para metadata y secreto de un
/// recurso, siempre con AAD explícito (nunca reusado fuera del contexto
/// para el que se selló).
#[wasm_bindgen]
pub fn cifrar_aead(clave: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Cifrado, JsValue> {
    let clave: [u8; 32] = clave.try_into().map_err(|_| err_js("clave debe ser de 32 bytes"))?;
    let clave: crate::secretos::ClaveSecreta32 = SecretBox::new(Box::new(clave));
    let envoltura = aead::cifrar(&clave, &plaintext, &aad).map_err(err_js)?;
    Ok(Cifrado { ciphertext: envoltura.ciphertext, nonce: envoltura.nonce.to_vec() })
}

#[wasm_bindgen]
pub fn descifrar_aead(clave: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let clave: [u8; 32] = clave.try_into().map_err(|_| err_js("clave debe ser de 32 bytes"))?;
    let clave: crate::secretos::ClaveSecreta32 = SecretBox::new(Box::new(clave));
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| err_js("nonce debe ser de 24 bytes"))?;
    aead::descifrar(&clave, &Envoltura { nonce, ciphertext }, &aad)
        .map_err(|_| err_js("no se pudo descifrar (clave incorrecta o datos corruptos)"))
}

/// F-26: combina la clave del fragmento de la URL (nunca llega al
/// servidor) con la capa opcional de passphrase de un external share —
/// Argon2id(passphrase, salt) → HKDF-combinar con la clave del fragmento.
/// El resultado es la clave real de `descifrar_aead`/`cifrar_aead` cuando
/// `password_protected` está activo; sin esta función el destinatario
/// necesitaría reimplementar Argon2id en TS, que es exactamente lo que el
/// resto de este archivo evita.
#[wasm_bindgen]
pub fn combinar_clave_de_share_con_passphrase(
    clave_fragmento: Vec<u8>,
    passphrase: String,
    salt: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    use secrecy::ExposeSecret;
    let salt: [u8; 16] = salt.try_into().map_err(|_| err_js("salt debe ser de 16 bytes"))?;
    let derivada_passphrase =
        crate::derivacion::derivar_clave_maestra(&passphrase_de(passphrase), &salt).map_err(err_js)?;
    let combinada = crate::derivacion::combinar_secretos(
        &clave_fragmento,
        derivada_passphrase.expose_secret(),
        crate::derivacion::contexto::EXTERNAL_SHARE_PASSPHRASE,
    );
    Ok(combinada.expose_secret().to_vec())
}

/// F-38: desbloqueo local por TOTP, alternativa a la passphrase — nunca
/// toca el servidor (distinto de F-14, que sí es server-verified).
#[wasm_bindgen]
pub fn totp_generar_secreto() -> Vec<u8> {
    totp::generar_secreto_totp().to_vec()
}

#[wasm_bindgen]
pub fn totp_codigo_actual(secreto: Vec<u8>, ahora_unix_segundos: u64) -> u32 {
    totp::codigo_totp(&secreto, ahora_unix_segundos)
}

#[wasm_bindgen]
pub fn totp_verificar(secreto: Vec<u8>, codigo: u32, ahora_unix_segundos: u64) -> bool {
    totp::verificar_totp(&secreto, codigo, ahora_unix_segundos)
}

/// F-38: envuelve la passphrase con una clave derivada (HKDF, sin Argon2id)
/// del secreto TOTP local — el resultado se guarda cifrado sólo en este
/// dispositivo (`localStorage`), nunca en el servidor.
#[wasm_bindgen]
pub fn totp_envolver_passphrase(secreto: Vec<u8>, passphrase: String, aad: Vec<u8>) -> Result<Cifrado, JsValue> {
    let envoltura = totp::envolver_passphrase(&secreto, &passphrase_de(passphrase), &aad).map_err(err_js)?;
    Ok(Cifrado { ciphertext: envoltura.ciphertext, nonce: envoltura.nonce.to_vec() })
}

/// F-38: reconstruye la passphrase a partir del código TOTP ya verificado —
/// el llamador ya corrió `totp_verificar` (o el control de intentos propio)
/// antes de llegar acá.
#[wasm_bindgen]
pub fn totp_desenvolver_passphrase(
    secreto: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<String, JsValue> {
    use secrecy::ExposeSecret;
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| err_js("nonce debe ser de 24 bytes"))?;
    let envoltura = Envoltura { nonce, ciphertext };
    let passphrase = totp::desenvolver_passphrase(&secreto, &envoltura, &aad)
        .map_err(|_| err_js("no se pudo recuperar la passphrase (secreto TOTP incorrecto o datos corruptos)"))?;
    Ok(passphrase.expose_secret().clone())
}

/// F-03 (PRF): envuelve la passphrase con una clave derivada (HKDF, sin
/// Argon2id) del output de la extensión PRF de WebAuthn obtenido al
/// registrar la passkey — el resultado se manda al backend como
/// `prf_wrapped_private_key_b64`, un blob opaco que el servidor nunca
/// puede descifrar.
#[wasm_bindgen]
pub fn prf_envolver_passphrase(prf_output: Vec<u8>, passphrase: String, aad: Vec<u8>) -> Result<Cifrado, JsValue> {
    let envoltura = prf::envolver_passphrase(&prf_output, &passphrase_de(passphrase), &aad).map_err(err_js)?;
    Ok(Cifrado { ciphertext: envoltura.ciphertext, nonce: envoltura.nonce.to_vec() })
}

/// F-03 (PRF): reconstruye la passphrase a partir del output de PRF
/// obtenido en la ceremonia de login (`getClientExtensionResults().prf`).
#[wasm_bindgen]
pub fn prf_desenvolver_passphrase(
    prf_output: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<String, JsValue> {
    use secrecy::ExposeSecret;
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| err_js("nonce debe ser de 24 bytes"))?;
    let envoltura = Envoltura { nonce, ciphertext };
    let passphrase = prf::desenvolver_passphrase(&prf_output, &envoltura, &aad)
        .map_err(|_| err_js("no se pudo recuperar la passphrase (output de PRF incorrecto o datos corruptos)"))?;
    Ok(passphrase.expose_secret().clone())
}
