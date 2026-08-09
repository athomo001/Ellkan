// Autor: Athan Espinoza

// Generador de contraseñas (F-15) — 100% client-side, nunca viaja al
// servidor. `crypto.getRandomValues` (mismo CSPRNG que `device.ts`), con
// rejection sampling para no introducir sesgo de módulo al elegir un índice
// del charset (mismo cuidado que el CSPRNG del backend, `bytes_aleatorios`).

export interface ReglasCharset {
	uppercase: boolean;
	lowercase: boolean;
	digits: boolean;
	symbols: boolean;
	exclude_ambiguous: boolean;
}

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const UPPER_SIN_AMBIGUOS = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // sin O/I
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const LOWER_SIN_AMBIGUOS = 'abcdefghjkmnpqrstuvwxyz'; // sin l/o
const DIGITS = '0123456789';
const DIGITS_SIN_AMBIGUOS = '23456789'; // sin 0/1
const SYMBOLS = '!@#$%^&*()-_=+[]{}';

function indiceSinSesgo(rango: number): number {
	const max = Math.floor(0x100000000 / rango) * rango;
	const buf = new Uint32Array(1);
	let n: number;
	do {
		crypto.getRandomValues(buf);
		n = buf[0];
	} while (n >= max);
	return n % rango;
}

export function generarPassword(longitud: number, reglas: ReglasCharset): string {
	const grupos: string[] = [];
	if (reglas.uppercase) grupos.push(reglas.exclude_ambiguous ? UPPER_SIN_AMBIGUOS : UPPER);
	if (reglas.lowercase) grupos.push(reglas.exclude_ambiguous ? LOWER_SIN_AMBIGUOS : LOWER);
	if (reglas.digits) grupos.push(reglas.exclude_ambiguous ? DIGITS_SIN_AMBIGUOS : DIGITS);
	if (reglas.symbols) grupos.push(SYMBOLS);
	if (grupos.length === 0) grupos.push(reglas.exclude_ambiguous ? LOWER_SIN_AMBIGUOS : LOWER);

	const alfabeto = grupos.join('');
	const resultado: string[] = [];

	// Al menos un carácter de cada grupo habilitado, si entra en la longitud.
	for (const grupo of grupos) {
		if (resultado.length >= longitud) break;
		resultado.push(grupo[indiceSinSesgo(grupo.length)]);
	}
	while (resultado.length < longitud) {
		resultado.push(alfabeto[indiceSinSesgo(alfabeto.length)]);
	}

	// Fisher-Yates con el mismo CSPRNG — el orden de "al menos uno por grupo"
	// no debe quedar predecible al principio del string.
	for (let i = resultado.length - 1; i > 0; i--) {
		const j = indiceSinSesgo(i + 1);
		[resultado[i], resultado[j]] = [resultado[j], resultado[i]];
	}

	return resultado.join('');
}
