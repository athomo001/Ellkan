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
