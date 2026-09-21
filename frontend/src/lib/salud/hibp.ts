// Autor: Athan Espinoza

// F-57 — Contraseñas filtradas con HIBP Pwned Passwords, modo k-anonymous: al
// servicio sólo le llegan los primeros 5 caracteres del SHA-1 de la contraseña
// (16^5 ≈ un millón de posibles), y responde con TODOS los sufijos que
// empiezan igual; la comparación se hace acá. Ni HIBP ni Ellkan ven la
// contraseña. OPT-IN: nada de este módulo se llama si el usuario no lo activó.

export const URL_HIBP = 'https://api.pwnedpasswords.com/range/';

export type Consulta = (url: string, init: { headers: Record<string, string> }) => Promise<{ ok: boolean; text(): Promise<string> }>;

/** SHA-1 hexadecimal en MAYÚSCULAS (el formato de HIBP). */
export async function sha1Hex(password: string): Promise<string> {
	const hash = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
	return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Interpreta la respuesta de HIBP: líneas `SUFIJO:VECES`. Con `Add-Padding` el
 * servicio agrega sufijos falsos con 0 veces para esconder cuántos hay de
 * verdad: esos no cuentan.
 */
export function parsearRango(cuerpo: string): Map<string, number> {
	const resultado = new Map<string, number>();
	for (const linea of cuerpo.split(/\r?\n/)) {
		const [sufijo, veces] = linea.trim().split(':');
		const n = Number(veces);
		if (sufijo && Number.isFinite(n) && n > 0) resultado.set(sufijo.toUpperCase(), n);
	}
	return resultado;
}

/**
 * Cuántas veces aparece cada contraseña en filtraciones conocidas (0 = no
 * aparece). Agrupa por prefijo: contraseñas con el mismo prefijo de 5
 * caracteres comparten una sola consulta.
 */
export async function contarFiltraciones(passwords: string[], consultar: Consulta): Promise<Map<string, number>> {
	const unicas = [...new Set(passwords.filter((p) => p.length > 0))];
	const huellas = new Map<string, string>();
	for (const p of unicas) huellas.set(p, await sha1Hex(p));

	const prefijos = new Set([...huellas.values()].map((h) => h.slice(0, 5)));
	const rangos = new Map<string, Map<string, number>>();
	for (const prefijo of prefijos) {
		const resp = await consultar(`${URL_HIBP}${prefijo}`, { headers: { 'Add-Padding': 'true' } });
		if (!resp.ok) throw new Error(`HIBP respondió con un error para el prefijo ${prefijo}`);
		rangos.set(prefijo, parsearRango(await resp.text()));
	}

	const resultado = new Map<string, number>();
	for (const [password, huella] of huellas) {
		resultado.set(password, rangos.get(huella.slice(0, 5))?.get(huella.slice(5)) ?? 0);
	}
	return resultado;
}
