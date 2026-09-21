// Autor: Athan Espinoza

// F-27: export/import personal en CSV, generado y parseado 100%
// client-side. Columnas fijas: name,username,password,uri,notes,totp_secret
// (mismos campos que `resource_types` — F-05/F-07, ver `recursos.ts`).
//
// CSV injection en el export (PBL-13-002, Cure53 2025 — hallazgo real en
// Passbolt): un campo que empieza con `= + - @` o tab/CR se interpreta
// como fórmula al abrir en Excel/Sheets. Se neutraliza acá porque este CSV
// se genera en el navegador — `backend/src/export/handlers.rs::csv_campo_seguro`
// resuelve el mismo problema pero para el export administrativo (F-29),
// que sí se arma server-side; acá hace falta la misma regla en TS.

export const COLUMNAS = ['name', 'username', 'password', 'uri', 'notes', 'totp_secret'] as const;
export type CampoCsv = (typeof COLUMNAS)[number];

export interface FilaExport {
	name: string;
	username: string;
	password: string;
	uri: string;
	notes: string;
	totp_secret: string;
}

const PREFIJOS_PELIGROSOS = ['=', '+', '-', '@', '\t', '\r'];

function neutralizarCampoCsv(valor: string): string {
	if (PREFIJOS_PELIGROSOS.some((p) => valor.startsWith(p))) return `'${valor}`;
	return valor;
}

function escaparCeldaCsv(valor: string): string {
	const neutralizado = neutralizarCampoCsv(valor);
	if (/[",\n\r]/.test(neutralizado)) {
		return `"${neutralizado.replace(/"/g, '""')}"`;
	}
	return neutralizado;
}

export function generarCsv(filas: FilaExport[]): string {
	const encabezado = COLUMNAS.join(',');
	const lineas = filas.map((fila) => COLUMNAS.map((col) => escaparCeldaCsv(fila[col] ?? '')).join(','));
	return [encabezado, ...lineas].join('\r\n') + '\r\n';
}

/** Parser RFC4180 mínimo — soporta comillas, comillas escapadas (`""`) y CRLF/LF mixtos. */
function parsearLineasCsv(texto: string): string[][] {
	const filas: string[][] = [];
	let fila: string[] = [];
	let campo = '';
	let entreComillas = false;

	for (let i = 0; i < texto.length; i++) {
		const c = texto[i];
		if (entreComillas) {
			if (c === '"') {
				if (texto[i + 1] === '"') {
					campo += '"';
					i++;
				} else {
					entreComillas = false;
				}
			} else {
				campo += c;
			}
			continue;
		}
		if (c === '"') {
			entreComillas = true;
		} else if (c === ',') {
			fila.push(campo);
			campo = '';
		} else if (c === '\r') {
			// se ignora, \n cierra la fila (soporta CRLF y LF)
		} else if (c === '\n') {
			fila.push(campo);
			filas.push(fila);
			fila = [];
			campo = '';
		} else {
			campo += c;
		}
	}
	if (campo !== '' || fila.length > 0) {
		fila.push(campo);
		filas.push(fila);
	}
	return filas.filter((f) => f.length > 1 || f[0] !== '');
}

/** Revierte la neutralización de CSV injection sólo si el prefijo `'` fue agregado por `generarCsv` de este mismo módulo (heurística: no hay forma de distinguirlo con certeza de un `'` real del usuario, así que se deja tal cual — es preferible un `'` de más a reabrir el vector de fórmula). */
export function parsearCsv(texto: string): FilaExport[] {
	const filas = parsearLineasCsv(texto.trim());
	if (filas.length === 0) return [];
	const [encabezado, ...resto] = filas;
	const indices = COLUMNAS.map((col) => encabezado.indexOf(col));

	return resto.map((fila) => {
		const obj = {} as FilaExport;
		COLUMNAS.forEach((col, idx) => {
			const i = indices[idx];
			obj[col] = i >= 0 ? (fila[i] ?? '') : '';
		});
		return obj;
	});
}

export interface CsvCrudo {
	encabezados: string[];
	filas: string[][];
}

/**
 * Parsea el CSV a encabezados + filas crudos, sin asumir los nombres fijos
 * de `COLUMNAS` — a diferencia de `parsearCsv`, no descarta ninguna columna
 * por nombre. Base del mapeo interactivo de columnas en la UI de
 * importación: un CSV exportado por otro gestor (KeePassXC, Chrome,
 * Bitwarden) no usa los mismos encabezados que `generarCsv` produce, y
 * `parsearCsv` los dejaría vacíos en silencio — acá el usuario ve las
 * columnas reales y decide a mano qué es cada una.
 */
export function parsearCsvCrudo(texto: string): CsvCrudo {
	const filas = parsearLineasCsv(texto.trim());
	if (filas.length === 0) return { encabezados: [], filas: [] };
	const [encabezado, ...resto] = filas;
	return { encabezados: encabezado, filas: resto };
}

const PISTAS_AUTODETECCION: Record<CampoCsv, string[]> = {
	name: ['name', 'title'],
	username: ['username', 'user', 'login', 'email'],
	password: ['password', 'pass'],
	uri: ['uri', 'url', 'website', 'link'],
	notes: ['notes', 'note', 'comment'],
	totp_secret: ['totp', 'otp']
};

/**
 * Sugiere a qué campo de `FilaExport` corresponde cada columna del CSV, por
 * coincidencia de nombre de encabezado (case-insensitive: exacto primero,
 * substring después) — nunca decide en silencio, es sólo la sugerencia
 * inicial que el usuario confirma o corrige en la UI antes de importar.
 */
export function autodetectarMapeoCsv(encabezados: string[]): (CampoCsv | null)[] {
	return encabezados.map((enc) => {
		const normalizado = enc.trim().toLowerCase();
		const exacto = COLUMNAS.find((col) => PISTAS_AUTODETECCION[col].includes(normalizado));
		if (exacto) return exacto;
		const parcial = COLUMNAS.find((col) => PISTAS_AUTODETECCION[col].some((pista) => normalizado.includes(pista)));
		return parcial ?? null;
	});
}

/**
 * Arma `FilaExport[]` a partir de filas crudas + el mapeo columna→campo que
 * el usuario confirmó (`null` = ignorar esa columna) — el reemplazo real del
 * matcheo por nombre exacto de `parsearCsv` para el flujo interactivo. La
 * neutralización de CSV injection (`escaparCeldaCsv`) no aplica acá porque
 * es cosa del export, no del import — los valores ya vienen tal cual del
 * archivo ajeno, y `crearRecurso` los cifra sin volver a interpretarlos como
 * CSV en ningún punto posterior.
 */
export function mapearFilasCsv(filas: string[][], mapeo: (CampoCsv | null)[]): FilaExport[] {
	return filas.map((fila) => {
		const obj: FilaExport = { name: '', username: '', password: '', uri: '', notes: '', totp_secret: '' };
		mapeo.forEach((campo, idx) => {
			if (campo) obj[campo] = fila[idx] ?? '';
		});
		return obj;
	});
}
