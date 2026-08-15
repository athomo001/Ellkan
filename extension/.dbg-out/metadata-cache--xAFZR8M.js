import { t as BrowserApi } from "./browser-api-Dqf8nftw.js";
//#region \0rolldown/runtime.js
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
//#endregion
//#region ../frontend/src/lib/wasm/ellkan_crypto.js
var ellkan_crypto_exports = /* @__PURE__ */ __exportAll({
	BlobClavePrivada: () => BlobClavePrivada,
	Cifrado: () => Cifrado,
	ClavePrivadaAbierta: () => ClavePrivadaAbierta,
	Identidad: () => Identidad,
	abrir_clave_privada: () => abrir_clave_privada,
	abrir_sellado: () => abrir_sellado,
	cifrar_aead: () => cifrar_aead,
	clave_publica_ed25519_de: () => clave_publica_ed25519_de,
	clave_publica_x25519_de: () => clave_publica_x25519_de,
	combinar_clave_de_share_con_passphrase: () => combinar_clave_de_share_con_passphrase,
	default: () => __wbg_init,
	descifrar_aead: () => descifrar_aead,
	firmar: () => firmar,
	generar_dek: () => generar_dek,
	generar_identidad: () => generar_identidad,
	generar_salt_kdf: () => generar_salt_kdf,
	initSync: () => initSync,
	prf_desenvolver_passphrase: () => prf_desenvolver_passphrase,
	prf_envolver_passphrase: () => prf_envolver_passphrase,
	sellar_clave_privada: () => sellar_clave_privada,
	sellar_para: () => sellar_para,
	totp_codigo_actual: () => totp_codigo_actual,
	totp_desenvolver_passphrase: () => totp_desenvolver_passphrase,
	totp_envolver_passphrase: () => totp_envolver_passphrase,
	totp_generar_secreto: () => totp_generar_secreto,
	totp_verificar: () => totp_verificar
});
var BlobClavePrivada = class BlobClavePrivada {
	static __wrap(ptr) {
		const obj = Object.create(BlobClavePrivada.prototype);
		obj.__wbg_ptr = ptr;
		BlobClavePrivadaFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		BlobClavePrivadaFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_blobclaveprivada_free(ptr, 0);
	}
	/**
	* @returns {Uint8Array}
	*/
	get ciphertext() {
		const ret = wasm.blobclaveprivada_ciphertext(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	* @returns {Uint8Array}
	*/
	get nonce() {
		const ret = wasm.blobclaveprivada_nonce(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
};
if (Symbol.dispose) BlobClavePrivada.prototype[Symbol.dispose] = BlobClavePrivada.prototype.free;
var Cifrado = class Cifrado {
	static __wrap(ptr) {
		const obj = Object.create(Cifrado.prototype);
		obj.__wbg_ptr = ptr;
		CifradoFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		CifradoFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_cifrado_free(ptr, 0);
	}
	/**
	* @returns {Uint8Array}
	*/
	get ciphertext() {
		const ret = wasm.cifrado_ciphertext(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	* @returns {Uint8Array}
	*/
	get nonce() {
		const ret = wasm.cifrado_nonce(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
};
if (Symbol.dispose) Cifrado.prototype[Symbol.dispose] = Cifrado.prototype.free;
var ClavePrivadaAbierta = class ClavePrivadaAbierta {
	static __wrap(ptr) {
		const obj = Object.create(ClavePrivadaAbierta.prototype);
		obj.__wbg_ptr = ptr;
		ClavePrivadaAbiertaFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		ClavePrivadaAbiertaFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_claveprivadaabierta_free(ptr, 0);
	}
	/**
	* @returns {Uint8Array}
	*/
	get ed25519_private() {
		const ret = wasm.claveprivadaabierta_ed25519_private(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	* @returns {Uint8Array}
	*/
	get x25519_private() {
		const ret = wasm.claveprivadaabierta_x25519_private(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
};
if (Symbol.dispose) ClavePrivadaAbierta.prototype[Symbol.dispose] = ClavePrivadaAbierta.prototype.free;
var Identidad = class Identidad {
	static __wrap(ptr) {
		const obj = Object.create(Identidad.prototype);
		obj.__wbg_ptr = ptr;
		IdentidadFinalization.register(obj, obj.__wbg_ptr, obj);
		return obj;
	}
	__destroy_into_raw() {
		const ptr = this.__wbg_ptr;
		this.__wbg_ptr = 0;
		IdentidadFinalization.unregister(this);
		return ptr;
	}
	free() {
		const ptr = this.__destroy_into_raw();
		wasm.__wbg_identidad_free(ptr, 0);
	}
	/**
	* @returns {Uint8Array}
	*/
	get ed25519_private() {
		const ret = wasm.identidad_ed25519_private(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	* @returns {Uint8Array}
	*/
	get ed25519_public() {
		const ret = wasm.identidad_ed25519_public(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	* @returns {Uint8Array}
	*/
	get x25519_private() {
		const ret = wasm.identidad_x25519_private(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
	/**
	* @returns {Uint8Array}
	*/
	get x25519_public() {
		const ret = wasm.identidad_x25519_public(this.__wbg_ptr);
		var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
		wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
		return v1;
	}
};
if (Symbol.dispose) Identidad.prototype[Symbol.dispose] = Identidad.prototype.free;
/**
* Reconstruye la clave privada a partir de la passphrase + el blob
* guardado en el servidor (F-01) — nunca se cachea el resultado, el
* llamador lo mantiene sólo en el store "memory" de la sesión.
* @param {string} passphrase
* @param {Uint8Array} salt
* @param {Uint8Array} nonce
* @param {Uint8Array} ciphertext
* @param {Uint8Array} aad
* @returns {ClavePrivadaAbierta}
*/
function abrir_clave_privada(passphrase, salt, nonce, ciphertext, aad) {
	const ptr0 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
	const len3 = WASM_VECTOR_LEN;
	const ptr4 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
	const len4 = WASM_VECTOR_LEN;
	const ret = wasm.abrir_clave_privada(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
	if (ret[2]) throw takeFromExternrefTable0(ret[1]);
	return ClavePrivadaAbierta.__wrap(ret[0]);
}
/**
* @param {Uint8Array} x25519_private
* @param {Uint8Array} sellado
* @returns {Uint8Array}
*/
function abrir_sellado(x25519_private, sellado) {
	const ptr0 = passArray8ToWasm0(x25519_private, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(sellado, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ret = wasm.abrir_sellado(ptr0, len0, ptr1, len1);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v3;
}
/**
* AEAD genérico (F-05/F-06/F-07) — usado para metadata y secreto de un
* recurso, siempre con AAD explícito (nunca reusado fuera del contexto
* para el que se selló).
* @param {Uint8Array} clave
* @param {Uint8Array} plaintext
* @param {Uint8Array} aad
* @returns {Cifrado}
*/
function cifrar_aead(clave, plaintext, aad) {
	const ptr0 = passArray8ToWasm0(clave, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ret = wasm.cifrar_aead(ptr0, len0, ptr1, len1, ptr2, len2);
	if (ret[2]) throw takeFromExternrefTable0(ret[1]);
	return Cifrado.__wrap(ret[0]);
}
/**
* @param {Uint8Array} ed25519_private
* @returns {Uint8Array}
*/
function clave_publica_ed25519_de(ed25519_private) {
	const ptr0 = passArray8ToWasm0(ed25519_private, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ret = wasm.clave_publica_ed25519_de(ptr0, len0);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v2;
}
/**
* @param {Uint8Array} x25519_private
* @returns {Uint8Array}
*/
function clave_publica_x25519_de(x25519_private) {
	const ptr0 = passArray8ToWasm0(x25519_private, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ret = wasm.clave_publica_x25519_de(ptr0, len0);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v2;
}
/**
* F-26: combina la clave del fragmento de la URL (nunca llega al
* servidor) con la capa opcional de passphrase de un external share —
* Argon2id(passphrase, salt) → HKDF-combinar con la clave del fragmento.
* El resultado es la clave real de `descifrar_aead`/`cifrar_aead` cuando
* `password_protected` está activo; sin esta función el destinatario
* necesitaría reimplementar Argon2id en TS, que es exactamente lo que el
* resto de este archivo evita.
* @param {Uint8Array} clave_fragmento
* @param {string} passphrase
* @param {Uint8Array} salt
* @returns {Uint8Array}
*/
function combinar_clave_de_share_con_passphrase(clave_fragmento, passphrase, salt) {
	const ptr0 = passArray8ToWasm0(clave_fragmento, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ret = wasm.combinar_clave_de_share_con_passphrase(ptr0, len0, ptr1, len1, ptr2, len2);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v4;
}
/**
* @param {Uint8Array} clave
* @param {Uint8Array} nonce
* @param {Uint8Array} ciphertext
* @param {Uint8Array} aad
* @returns {Uint8Array}
*/
function descifrar_aead(clave, nonce, ciphertext, aad) {
	const ptr0 = passArray8ToWasm0(clave, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ptr3 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
	const len3 = WASM_VECTOR_LEN;
	const ret = wasm.descifrar_aead(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v5;
}
/**
* Firma un nonce de desafío de login con la clave Ed25519 (F-01/F-02).
* @param {Uint8Array} ed25519_private
* @param {Uint8Array} mensaje
* @returns {Uint8Array}
*/
function firmar(ed25519_private, mensaje) {
	const ptr0 = passArray8ToWasm0(ed25519_private, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(mensaje, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ret = wasm.firmar(ptr0, len0, ptr1, len1);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v3;
}
/**
* @returns {Uint8Array}
*/
function generar_dek() {
	const ret = wasm.generar_dek();
	var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v1;
}
/**
* Genera los dos keypairs de identidad de un usuario nuevo (F-01) — X25519
* para acuerdo de claves (compartir), Ed25519 para firmar el desafío de
* login.
* @returns {Identidad}
*/
function generar_identidad() {
	const ret = wasm.generar_identidad();
	return Identidad.__wrap(ret);
}
/**
* @returns {Uint8Array}
*/
function generar_salt_kdf() {
	const ret = wasm.generar_salt_kdf();
	var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v1;
}
/**
* F-03 (PRF): reconstruye la passphrase a partir del output de PRF
* obtenido en la ceremonia de login (`getClientExtensionResults().prf`).
* @param {Uint8Array} prf_output
* @param {Uint8Array} nonce
* @param {Uint8Array} ciphertext
* @param {Uint8Array} aad
* @returns {string}
*/
function prf_desenvolver_passphrase(prf_output, nonce, ciphertext, aad) {
	let deferred6_0;
	let deferred6_1;
	try {
		const ptr0 = passArray8ToWasm0(prf_output, wasm.__wbindgen_malloc);
		const len0 = WASM_VECTOR_LEN;
		const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
		const len1 = WASM_VECTOR_LEN;
		const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
		const len2 = WASM_VECTOR_LEN;
		const ptr3 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
		const len3 = WASM_VECTOR_LEN;
		const ret = wasm.prf_desenvolver_passphrase(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
		var ptr5 = ret[0];
		var len5 = ret[1];
		if (ret[3]) {
			ptr5 = 0;
			len5 = 0;
			throw takeFromExternrefTable0(ret[2]);
		}
		deferred6_0 = ptr5;
		deferred6_1 = len5;
		return getStringFromWasm0(ptr5, len5);
	} finally {
		wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
	}
}
/**
* F-03 (PRF): envuelve la passphrase con una clave derivada (HKDF, sin
* Argon2id) del output de la extensión PRF de WebAuthn obtenido al
* registrar la passkey — el resultado se manda al backend como
* `prf_wrapped_private_key_b64`, un blob opaco que el servidor nunca
* puede descifrar.
* @param {Uint8Array} prf_output
* @param {string} passphrase
* @param {Uint8Array} aad
* @returns {Cifrado}
*/
function prf_envolver_passphrase(prf_output, passphrase, aad) {
	const ptr0 = passArray8ToWasm0(prf_output, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ret = wasm.prf_envolver_passphrase(ptr0, len0, ptr1, len1, ptr2, len2);
	if (ret[2]) throw takeFromExternrefTable0(ret[1]);
	return Cifrado.__wrap(ret[0]);
}
/**
* Cadena completa Argon2id→HKDF→XChaCha20-Poly1305 (F-01) — cifra los dos
* privados concatenados (64 bytes) con una clave derivada de la
* passphrase, nunca con el output de Argon2id directo.
* @param {string} passphrase
* @param {Uint8Array} salt
* @param {Uint8Array} x25519_private
* @param {Uint8Array} ed25519_private
* @param {Uint8Array} aad
* @returns {BlobClavePrivada}
*/
function sellar_clave_privada(passphrase, salt, x25519_private, ed25519_private, aad) {
	const ptr0 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(x25519_private, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ptr3 = passArray8ToWasm0(ed25519_private, wasm.__wbindgen_malloc);
	const len3 = WASM_VECTOR_LEN;
	const ptr4 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
	const len4 = WASM_VECTOR_LEN;
	const ret = wasm.sellar_clave_privada(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
	if (ret[2]) throw takeFromExternrefTable0(ret[1]);
	return BlobClavePrivada.__wrap(ret[0]);
}
/**
* Sella una DEK (o cualquier payload corto) para la clave pública X25519
* de un destinatario (F-05/F-06/F-11/F-16/F-36) — caja anónima
* `crypto_box`, el destinatario no necesita saber quién selló.
* @param {Uint8Array} x25519_public_destinatario
* @param {Uint8Array} payload
* @returns {Uint8Array}
*/
function sellar_para(x25519_public_destinatario, payload) {
	const ptr0 = passArray8ToWasm0(x25519_public_destinatario, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
	const len1 = WASM_VECTOR_LEN;
	const ret = wasm.sellar_para(ptr0, len0, ptr1, len1);
	if (ret[3]) throw takeFromExternrefTable0(ret[2]);
	var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v3;
}
/**
* @param {Uint8Array} secreto
* @param {bigint} ahora_unix_segundos
* @returns {number}
*/
function totp_codigo_actual(secreto, ahora_unix_segundos) {
	const ptr0 = passArray8ToWasm0(secreto, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	return wasm.totp_codigo_actual(ptr0, len0, ahora_unix_segundos) >>> 0;
}
/**
* F-38: reconstruye la passphrase a partir del código TOTP ya verificado —
* el llamador ya corrió `totp_verificar` (o el control de intentos propio)
* antes de llegar acá.
* @param {Uint8Array} secreto
* @param {Uint8Array} nonce
* @param {Uint8Array} ciphertext
* @param {Uint8Array} aad
* @returns {string}
*/
function totp_desenvolver_passphrase(secreto, nonce, ciphertext, aad) {
	let deferred6_0;
	let deferred6_1;
	try {
		const ptr0 = passArray8ToWasm0(secreto, wasm.__wbindgen_malloc);
		const len0 = WASM_VECTOR_LEN;
		const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
		const len1 = WASM_VECTOR_LEN;
		const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
		const len2 = WASM_VECTOR_LEN;
		const ptr3 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
		const len3 = WASM_VECTOR_LEN;
		const ret = wasm.totp_desenvolver_passphrase(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
		var ptr5 = ret[0];
		var len5 = ret[1];
		if (ret[3]) {
			ptr5 = 0;
			len5 = 0;
			throw takeFromExternrefTable0(ret[2]);
		}
		deferred6_0 = ptr5;
		deferred6_1 = len5;
		return getStringFromWasm0(ptr5, len5);
	} finally {
		wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
	}
}
/**
* F-38: envuelve la passphrase con una clave derivada (HKDF, sin Argon2id)
* del secreto TOTP local — el resultado se guarda cifrado sólo en este
* dispositivo (`localStorage`), nunca en el servidor.
* @param {Uint8Array} secreto
* @param {string} passphrase
* @param {Uint8Array} aad
* @returns {Cifrado}
*/
function totp_envolver_passphrase(secreto, passphrase, aad) {
	const ptr0 = passArray8ToWasm0(secreto, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	const ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
	const len1 = WASM_VECTOR_LEN;
	const ptr2 = passArray8ToWasm0(aad, wasm.__wbindgen_malloc);
	const len2 = WASM_VECTOR_LEN;
	const ret = wasm.totp_envolver_passphrase(ptr0, len0, ptr1, len1, ptr2, len2);
	if (ret[2]) throw takeFromExternrefTable0(ret[1]);
	return Cifrado.__wrap(ret[0]);
}
/**
* F-38: desbloqueo local por TOTP, alternativa a la passphrase — nunca
* toca el servidor (distinto de F-14, que sí es server-verified).
* @returns {Uint8Array}
*/
function totp_generar_secreto() {
	const ret = wasm.totp_generar_secreto();
	var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
	wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
	return v1;
}
/**
* @param {Uint8Array} secreto
* @param {number} codigo
* @param {bigint} ahora_unix_segundos
* @returns {boolean}
*/
function totp_verificar(secreto, codigo, ahora_unix_segundos) {
	const ptr0 = passArray8ToWasm0(secreto, wasm.__wbindgen_malloc);
	const len0 = WASM_VECTOR_LEN;
	return wasm.totp_verificar(ptr0, len0, codigo, ahora_unix_segundos) !== 0;
}
function __wbg_get_imports() {
	return {
		__proto__: null,
		"./ellkan_crypto_bg.js": {
			__proto__: null,
			__wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
				return typeof arg0 === "function";
			},
			__wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
				const val = arg0;
				return typeof val === "object" && val !== null;
			},
			__wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
				return typeof arg0 === "string";
			},
			__wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
				return arg0 === void 0;
			},
			__wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
				throw new Error(getStringFromWasm0(arg0, arg1));
			},
			__wbg_call_a6e5c5dce5018821: function() {
				return handleError(function(arg0, arg1, arg2) {
					return arg0.call(arg1, arg2);
				}, arguments);
			},
			__wbg_crypto_38df2bab126b63dc: function(arg0) {
				return arg0.crypto;
			},
			__wbg_getRandomValues_c44a50d8cfdaebeb: function() {
				return handleError(function(arg0, arg1) {
					arg0.getRandomValues(arg1);
				}, arguments);
			},
			__wbg_getRandomValues_cc7f052a444bb2ce: function() {
				return handleError(function(arg0, arg1) {
					globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
				}, arguments);
			},
			__wbg_length_1f0964f4a5e2c6d8: function(arg0) {
				return arg0.length;
			},
			__wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
				return arg0.msCrypto;
			},
			__wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
				return new Uint8Array(arg0 >>> 0);
			},
			__wbg_node_84ea875411254db1: function(arg0) {
				return arg0.node;
			},
			__wbg_process_44c7a14e11e9f69e: function(arg0) {
				return arg0.process;
			},
			__wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
				Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
			},
			__wbg_randomFillSync_6c25eac9869eb53c: function() {
				return handleError(function(arg0, arg1) {
					arg0.randomFillSync(arg1);
				}, arguments);
			},
			__wbg_require_b4edbdcf3e2a1ef0: function() {
				return handleError(function() {
					return module.require;
				}, arguments);
			},
			__wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
				const ret = typeof global === "undefined" ? null : global;
				return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
			},
			__wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
				const ret = typeof globalThis === "undefined" ? null : globalThis;
				return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
			},
			__wbg_static_accessor_SELF_146583524fe1469b: function() {
				const ret = typeof self === "undefined" ? null : self;
				return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
			},
			__wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
				const ret = typeof window === "undefined" ? null : window;
				return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
			},
			__wbg_subarray_3ed232c8a6baee09: function(arg0, arg1, arg2) {
				return arg0.subarray(arg1 >>> 0, arg2 >>> 0);
			},
			__wbg_versions_276b2795b1c6a219: function(arg0) {
				return arg0.versions;
			},
			__wbindgen_cast_0000000000000001: function(arg0, arg1) {
				return getArrayU8FromWasm0(arg0, arg1);
			},
			__wbindgen_cast_0000000000000002: function(arg0, arg1) {
				return getStringFromWasm0(arg0, arg1);
			},
			__wbindgen_init_externref_table: function() {
				const table = wasm.__wbindgen_externrefs;
				const offset = table.grow(4);
				table.set(0, void 0);
				table.set(offset + 0, void 0);
				table.set(offset + 1, null);
				table.set(offset + 2, true);
				table.set(offset + 3, false);
			}
		}
	};
}
var BlobClavePrivadaFinalization = typeof FinalizationRegistry === "undefined" ? {
	register: () => {},
	unregister: () => {}
} : new FinalizationRegistry((ptr) => wasm.__wbg_blobclaveprivada_free(ptr, 1));
var CifradoFinalization = typeof FinalizationRegistry === "undefined" ? {
	register: () => {},
	unregister: () => {}
} : new FinalizationRegistry((ptr) => wasm.__wbg_cifrado_free(ptr, 1));
var ClavePrivadaAbiertaFinalization = typeof FinalizationRegistry === "undefined" ? {
	register: () => {},
	unregister: () => {}
} : new FinalizationRegistry((ptr) => wasm.__wbg_claveprivadaabierta_free(ptr, 1));
var IdentidadFinalization = typeof FinalizationRegistry === "undefined" ? {
	register: () => {},
	unregister: () => {}
} : new FinalizationRegistry((ptr) => wasm.__wbg_identidad_free(ptr, 1));
function addToExternrefTable0(obj) {
	const idx = wasm.__externref_table_alloc();
	wasm.__wbindgen_externrefs.set(idx, obj);
	return idx;
}
function getArrayU8FromWasm0(ptr, len) {
	ptr = ptr >>> 0;
	return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
function getStringFromWasm0(ptr, len) {
	return decodeText(ptr >>> 0, len);
}
var cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
	if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
	return cachedUint8ArrayMemory0;
}
function handleError(f, args) {
	try {
		return f.apply(this, args);
	} catch (e) {
		const idx = addToExternrefTable0(e);
		wasm.__wbindgen_exn_store(idx);
	}
}
function isLikeNone(x) {
	return x === void 0 || x === null;
}
function passArray8ToWasm0(arg, malloc) {
	const ptr = malloc(arg.length * 1, 1) >>> 0;
	getUint8ArrayMemory0().set(arg, ptr / 1);
	WASM_VECTOR_LEN = arg.length;
	return ptr;
}
function passStringToWasm0(arg, malloc, realloc) {
	if (realloc === void 0) {
		const buf = cachedTextEncoder.encode(arg);
		const ptr = malloc(buf.length, 1) >>> 0;
		getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
		WASM_VECTOR_LEN = buf.length;
		return ptr;
	}
	let len = arg.length;
	let ptr = malloc(len, 1) >>> 0;
	const mem = getUint8ArrayMemory0();
	let offset = 0;
	for (; offset < len; offset++) {
		const code = arg.charCodeAt(offset);
		if (code > 127) break;
		mem[ptr + offset] = code;
	}
	if (offset !== len) {
		if (offset !== 0) arg = arg.slice(offset);
		ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
		const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
		const ret = cachedTextEncoder.encodeInto(arg, view);
		offset += ret.written;
		ptr = realloc(ptr, len, offset, 1) >>> 0;
	}
	WASM_VECTOR_LEN = offset;
	return ptr;
}
function takeFromExternrefTable0(idx) {
	const value = wasm.__wbindgen_externrefs.get(idx);
	wasm.__externref_table_dealloc(idx);
	return value;
}
var cachedTextDecoder = new TextDecoder("utf-8", {
	ignoreBOM: true,
	fatal: true
});
cachedTextDecoder.decode();
var MAX_SAFARI_DECODE_BYTES = 2146435072;
var numBytesDecoded = 0;
function decodeText(ptr, len) {
	numBytesDecoded += len;
	if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
		cachedTextDecoder = new TextDecoder("utf-8", {
			ignoreBOM: true,
			fatal: true
		});
		cachedTextDecoder.decode();
		numBytesDecoded = len;
	}
	return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
var cachedTextEncoder = new TextEncoder();
if (!("encodeInto" in cachedTextEncoder)) cachedTextEncoder.encodeInto = function(arg, view) {
	const buf = cachedTextEncoder.encode(arg);
	view.set(buf);
	return {
		read: arg.length,
		written: buf.length
	};
};
var WASM_VECTOR_LEN = 0;
var wasm;
function __wbg_finalize_init(instance, module) {
	wasm = instance.exports;
	cachedUint8ArrayMemory0 = null;
	wasm.__wbindgen_start();
	return wasm;
}
async function __wbg_load(module, imports) {
	if (typeof Response === "function" && module instanceof Response) {
		if (typeof WebAssembly.instantiateStreaming === "function") try {
			return await WebAssembly.instantiateStreaming(module, imports);
		} catch (e) {
			if (module.ok && expectedResponseType(module.type) && module.headers.get("Content-Type") !== "application/wasm") console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);
			else throw e;
		}
		const bytes = await module.arrayBuffer();
		return await WebAssembly.instantiate(bytes, imports);
	} else {
		const instance = await WebAssembly.instantiate(module, imports);
		if (instance instanceof WebAssembly.Instance) return {
			instance,
			module
		};
		else return instance;
	}
	function expectedResponseType(type) {
		switch (type) {
			case "basic":
			case "cors":
			case "default": return true;
		}
		return false;
	}
}
function initSync(module) {
	if (wasm !== void 0) return wasm;
	if (module !== void 0) {
		if (Object.getPrototypeOf(module) === Object.prototype) ({module} = module);
		else console.warn("using deprecated parameters for `initSync()`; pass a single object instead");
	}
	const imports = __wbg_get_imports();
	if (!(module instanceof WebAssembly.Module)) module = new WebAssembly.Module(module);
	return __wbg_finalize_init(new WebAssembly.Instance(module, imports), module);
}
async function __wbg_init(module_or_path) {
	if (wasm !== void 0) return wasm;
	if (module_or_path !== void 0) {
		if (Object.getPrototypeOf(module_or_path) === Object.prototype) ({module_or_path} = module_or_path);
		else console.warn("using deprecated parameters for the initialization function; pass a single object instead");
	}
	if (module_or_path === void 0) module_or_path = new URL("ellkan_crypto_bg.wasm", import.meta.url);
	const imports = __wbg_get_imports();
	if (typeof module_or_path === "string" || typeof Request === "function" && module_or_path instanceof Request || typeof URL === "function" && module_or_path instanceof URL) module_or_path = fetch(module_or_path);
	const { instance, module } = await __wbg_load(await module_or_path, imports);
	return __wbg_finalize_init(instance, module);
}
//#endregion
//#region src/background/wasm.ts
var listo = null;
function cargarCrypto() {
	if (!listo) listo = __wbg_init().then(() => ellkan_crypto_exports);
	return listo;
}
//#endregion
//#region src/background/storage/metadata-cache.ts
var CLAVE_EFIMERA_SESSION_KEY = "ellkan.cache.clave_efimera";
var CACHE_LOCAL_KEY = "ellkan.cache.metadata";
var AAD = new TextEncoder().encode("ellkan:extension:metadata-cache:v1");
async function leerClaveEfimeraExistente() {
	const bytes = (await BrowserApi.storageSessionGet(CLAVE_EFIMERA_SESSION_KEY))[CLAVE_EFIMERA_SESSION_KEY];
	return bytes ? new Uint8Array(bytes) : null;
}
async function obtenerOCrearClaveEfimera() {
	const existente = await leerClaveEfimeraExistente();
	if (existente) return existente;
	await BrowserApi.storageLocalRemove(CACHE_LOCAL_KEY);
	const clave = (await cargarCrypto()).generar_dek();
	await BrowserApi.storageSessionSet({ [CLAVE_EFIMERA_SESSION_KEY]: Array.from(clave) });
	return clave;
}
var MetadataCache = {
	/** Cifra `datos` (JSON-serializable) con la clave efímera de esta sesión
	* y lo persiste en `storage.local`. */
	async guardar(datos) {
		const wasm = await cargarCrypto();
		const clave = await obtenerOCrearClaveEfimera();
		const plaintext = new TextEncoder().encode(JSON.stringify(datos));
		const cifrado = wasm.cifrar_aead(clave, plaintext, AAD);
		await BrowserApi.storageLocalSet({ [CACHE_LOCAL_KEY]: {
			ciphertext: Array.from(cifrado.ciphertext),
			nonce: Array.from(cifrado.nonce)
		} });
	},
	/** `null` si no hay nada cacheado, o si la clave efímera no está
	* disponible (sesión terminada) — en ese caso ya se purgó el residuo. */
	async leer() {
		const clave = await leerClaveEfimeraExistente();
		if (!clave) {
			await BrowserApi.storageLocalRemove(CACHE_LOCAL_KEY);
			return null;
		}
		const guardado = (await BrowserApi.storageLocalGet(CACHE_LOCAL_KEY))[CACHE_LOCAL_KEY];
		if (!guardado) return null;
		const plaintext = (await cargarCrypto()).descifrar_aead(clave, new Uint8Array(guardado.nonce), new Uint8Array(guardado.ciphertext), AAD);
		return JSON.parse(new TextDecoder().decode(plaintext));
	},
	async limpiar() {
		await BrowserApi.storageSessionRemove(CLAVE_EFIMERA_SESSION_KEY);
		await BrowserApi.storageLocalRemove(CACHE_LOCAL_KEY);
	}
};
//#endregion
export { MetadataCache };
