// Autor: Athan Espinoza

// RFC 4648 base32 (mayúsculas, sin padding) — sólo para el parámetro
// `secret` de una URI `otpauth://`, que las apps autenticadoras exigen en
// ese formato (no base64). No hay ningún decoder porque nada en este
// cliente necesita leer un secreto en base32 de vuelta.

const ALFABETO = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Codificar(bytes: Uint8Array): string {
	let bits = '';
	for (const b of bytes) bits += b.toString(2).padStart(8, '0');

	let salida = '';
	for (let i = 0; i < bits.length; i += 5) {
		const trozo = bits.slice(i, i + 5).padEnd(5, '0');
		salida += ALFABETO[parseInt(trozo, 2)];
	}
	return salida;
}
