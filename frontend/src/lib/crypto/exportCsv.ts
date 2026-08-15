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

const COLUMNAS = ['name', 'username', 'password', 'uri', 'notes', 'totp_secret'] as const;

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
