// Autor: Athan Espinoza

// Resolución del manifest fuente multi-navegador (spec 06 §1) — extraído de
// `build.mjs` para que también lo use `self-check.ts` (el test dedicado de
// `frame-ancestors 'none'` sobre las páginas propias de la extensión, spec 05
// §2.1 / PBL-08-001).
//
// Regla de los prefijos `__<browser>__foo`:
//  - si `<browser>` coincide con el destino, la clave reemplaza a `foo` (o la
//    borra si el valor es `null`);
//  - las claves de otros navegadores se descartan enteras.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const raiz = dirname(fileURLToPath(import.meta.url));

/** @param {Record<string, unknown>} fuente @param {string} navegador */
export function resolverManifest(fuente, navegador) {
	const resultado = {};
	for (const [clave, valor] of Object.entries(fuente)) {
		const match = clave.match(/^__(\w+)__(.+)$/);
		if (match) {
			const [, navegadorDeLaClave, claveReal] = match;
			if (navegadorDeLaClave !== navegador) continue;
			if (valor === null) delete resultado[claveReal];
			else resultado[claveReal] = valor;
			continue;
		}
		if (!(clave in resultado)) resultado[clave] = valor;
	}
	return resultado;
}

/** Manifest fuente sin resolver (JSON crudo de `manifest.source.json`). */
export function manifestFuente() {
	return JSON.parse(readFileSync(resolve(raiz, 'manifest.source.json'), 'utf8'));
}

/** Manifest ya resuelto para un navegador (`chrome` por default). */
export function manifestPara(navegador = 'chrome') {
	return resolverManifest(manifestFuente(), navegador);
}
