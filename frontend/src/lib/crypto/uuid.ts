// Autor: Athan Espinoza

// F-05/F-06: el AAD del AEAD de un recurso es `resource_id || created_by`
// como bytes crudos de UUID (16+16), no como texto — mismo formato que
// `cli/src/crypto_local.rs::aad_de_recurso`, tiene que coincidir bit a bit
// con lo que el servidor esperaba cuando el cliente que creó el recurso lo
// cifró.

export function uuidABytes(uuid: string): Uint8Array {
	const hex = uuid.replace(/-/g, '');
	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
	return bytes;
}
