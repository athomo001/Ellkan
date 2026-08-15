// Autor: Athan Espinoza

// F-27: orquestación de export/import personal — junta `recursos.ts`
// (F-05/F-06/F-11) con el gate de política (`POST /export-events`, la
// única fuente de verdad server-side) y el generador/parser del formato
// elegido. El import reusa `crearRecurso` una vez por entrada — nunca un
// endpoint de carga masiva separado, tal como exige la spec (mismo
// pipeline de validación/creación que la UI manual de F-07).
//
// Límite de tamaño de archivo y de cantidad de filas en el parseo, con
// error explícito en vez de colgar el cliente (PBL-13-003, hallazgo real
// de Passbolt con una librería de parseo CSV de terceros).

import { verSecreto, crearRecurso, type Recurso } from './recursos';
import { exportEventsApi } from '$lib/api/exportPolicy';
import { generarCsv, parsearCsv, type FilaExport } from './exportCsv';
import { generarKdbx, parsearKdbx } from './exportKdbx';
import { generarCxf, parsearCxf } from './exportCxf';
import type { ClavesDesbloqueadas } from '$lib/state/session';

export type FormatoExport = 'kdbx' | 'csv' | 'cxf';

export type { FilaExport };

const TAMANO_MAXIMO_BYTES = 10 * 1024 * 1024;
const MAX_FILAS = 2000;
const TIMEOUT_PARSEO_MS = 15_000;

function conTimeout<T>(promesa: Promise<T>, ms: number): Promise<T> {
	return Promise.race([
		promesa,
		new Promise<T>((_, reject) =>
			setTimeout(() => reject(new Error('El parseo del archivo tardó demasiado.')), ms)
		)
	]);
}

/**
 * Descifra los recursos dados a filas planas listas para exportar — recibe
 * la lista ya resuelta (Vault, F-30, la mantiene en memoria) en vez de
 * volver a pedirla, así el caller decide si exporta todo o sólo una
 * selección sin duplicar la carga/descifrado de metadata.
 */
export async function construirFilasExport(
	recursos: Recurso[],
	claves: ClavesDesbloqueadas
): Promise<{ filas: FilaExport[]; recursos: Recurso[] }> {
	const filas: FilaExport[] = [];
	for (const r of recursos) {
		const secreto = await verSecreto(r, claves);
		filas.push({
			name: r.nombre,
			username: r.usuario,
			password: secreto.password,
			uri: r.uri,
			notes: secreto.notes,
			totp_secret: secreto.totpSecret ?? ''
		});
	}
	return { filas, recursos };
}

export interface ArchivoGenerado {
	blob: Blob;
	filename: string;
}

/**
 * Reporta el evento antes de generar nada — si el servidor rechaza (política
 * desactivada, formato no permitido), no se arma ningún archivo.
 */
export async function exportar(
	formato: FormatoExport,
	filas: FilaExport[],
	opciones: { password?: string; cuentaEmail?: string }
): Promise<ArchivoGenerado> {
	await exportEventsApi.reportar({ event_type: 'export', format: formato, resource_count: filas.length });

	if (formato === 'kdbx') {
		if (!opciones.password) throw new Error('El export en KDBX requiere una contraseña para proteger el archivo.');
		const bytes = await generarKdbx(filas, opciones.password);
		return { blob: new Blob([bytes], { type: 'application/octet-stream' }), filename: 'ellkan-export.kdbx' };
	}
	if (formato === 'csv') {
		return { blob: new Blob([generarCsv(filas)], { type: 'text/csv' }), filename: 'ellkan-export.csv' };
	}
	return {
		blob: new Blob([generarCxf(filas, opciones.cuentaEmail ?? '')], { type: 'application/json' }),
		filename: 'ellkan-export.cxf.json'
	};
}

/** Parsea el archivo elegido a filas planas — todavía no crea nada, sólo para mostrar un preview antes de confirmar. */
export async function parsearArchivoImport(
	formato: FormatoExport,
	bytes: ArrayBuffer,
	opciones: { password?: string }
): Promise<FilaExport[]> {
	if (bytes.byteLength > TAMANO_MAXIMO_BYTES) {
		throw new Error('El archivo supera el tamaño máximo permitido (10 MB).');
	}

	let filas: FilaExport[];
	if (formato === 'kdbx') {
		if (!opciones.password) throw new Error('Este archivo KDBX requiere contraseña.');
		filas = await conTimeout(parsearKdbx(bytes, opciones.password), TIMEOUT_PARSEO_MS);
	} else if (formato === 'csv') {
		filas = await conTimeout(Promise.resolve(parsearCsv(new TextDecoder().decode(bytes))), TIMEOUT_PARSEO_MS);
	} else {
		filas = await conTimeout(Promise.resolve(parsearCxf(new TextDecoder().decode(bytes))), TIMEOUT_PARSEO_MS);
	}

	if (filas.length > MAX_FILAS) {
		throw new Error(`El archivo tiene demasiadas entradas (máximo ${MAX_FILAS}).`);
	}
	return filas;
}

/** Reporta el evento antes de crear nada, y luego crea un recurso `user_key` por fila vía el mismo pipeline que la UI manual (`crearRecurso`, F-05/F-07) — sin atajo de carga masiva. */
export async function importar(
	formato: FormatoExport,
	filas: FilaExport[],
	claves: ClavesDesbloqueadas,
	userId: string
): Promise<number> {
	await exportEventsApi.reportar({ event_type: 'import', format: formato, resource_count: filas.length });

	let creados = 0;
	for (const fila of filas) {
		await crearRecurso(
			{
				nombre: fila.name,
				usuario: fila.username,
				uri: fila.uri,
				password: fila.password,
				notas: fila.notes,
				totpSecretBase32: fila.totp_secret || undefined
			},
			claves,
			userId
		);
		creados++;
	}
	return creados;
}

export function detectarFormatoPorNombre(nombreArchivo: string): FormatoExport | undefined {
	const lower = nombreArchivo.toLowerCase();
	if (lower.endsWith('.kdbx')) return 'kdbx';
	if (lower.endsWith('.csv')) return 'csv';
	if (lower.endsWith('.json') || lower.endsWith('.cxf.json')) return 'cxf';
	return undefined;
}

export function descargarArchivo(archivo: ArchivoGenerado): void {
	const url = URL.createObjectURL(archivo.blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = archivo.filename;
	a.click();
	URL.revokeObjectURL(url);
}
