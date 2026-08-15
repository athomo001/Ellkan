// Autor: Athan Espinoza

export function bytesABase64(bytes: Uint8Array): string {
	let binario = '';
	for (const byte of bytes) binario += String.fromCharCode(byte);
	return btoa(binario);
}

export function base64ABytes(b64: string): Uint8Array {
	const binario = atob(b64);
	const bytes = new Uint8Array(binario.length);
	for (let i = 0; i < binario.length; i++) bytes[i] = binario.charCodeAt(i);
	return bytes;
}

/** F-26: variante URL-safe (sin `+`/`/`/`=`) para la clave que viaja en el
 * fragmento de la URL de un external share — evita cualquier ambigüedad al
 * pegar el link en un chat/email que reinterprete `/` como separador. */
export function bytesABase64Url(bytes: Uint8Array): string {
	return bytesABase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlABytes(b64url: string): Uint8Array {
	const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
	const relleno = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
	return base64ABytes(b64 + relleno);
}
