// Autor: Athan Espinoza

// Versionamiento de la extensión (2026-08-15) — a diferencia del resto del
// repo (backend/frontend, fijos hasta v1), `package.json`/`manifest.source.json`
// SÍ tienen que moverse en cada release real: es lo único que el usuario
// instala y actualiza como paquete (`.crx`/`.xpi`), ver cabecera de
// `CHANGELOG.md`. Los dos archivos se mantienen siempre en el mismo valor.
//
// Uso:
//   node version.mjs            bump del último dígito (patch): 0.1.34 -> 0.1.35
//                                — `package.mjs` ya lo llama solo antes de
//                                cada empaquetado, no hace falta correrlo a mano.
//   node version.mjs --set 0.2  fija x.y y resetea el patch a 0 -> 0.2.0
//   node version.mjs --set 1.0  -> 1.0.0

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const raiz = dirname(fileURLToPath(import.meta.url));
const rutaPackageJson = resolve(raiz, 'package.json');
const rutaManifest = resolve(raiz, 'manifest.source.json');

function leerJson(ruta) {
	return JSON.parse(readFileSync(ruta, 'utf8'));
}

// Reemplazo de texto puntual, no `JSON.parse`+`stringify` — `manifest.
// source.json` tiene arrays en una sola línea (`"scripts": ["background.js"]`)
// que `JSON.stringify` con indentación expande siempre a multilínea, lo que
// reformatearía el archivo entero por un cambio que sólo debería tocar la
// versión.
function escribirVersion(ruta, version) {
	const contenido = readFileSync(ruta, 'utf8');
	const actualizado = contenido.replace(/"version":\s*"[^"]*"/, `"version": "${version}"`);
	if (actualizado === contenido) {
		throw new Error(`no se encontró la clave "version" en ${ruta}`);
	}
	writeFileSync(ruta, actualizado);
}

function bumpPatch(version) {
	const partes = version.split('.').map(Number);
	if (partes.length !== 3 || partes.some(Number.isNaN)) {
		throw new Error(`versión actual "${version}" no tiene forma x.y.z, no se puede incrementar`);
	}
	partes[2] += 1;
	return partes.join('.');
}

function versionFijada(xy) {
	if (!/^\d+\.\d+$/.test(xy)) {
		throw new Error(`--set espera el formato "x.y" (ej. "0.2" o "1.0"), recibido "${xy}"`);
	}
	return `${xy}.0`;
}

function calcularNuevaVersion() {
	const actual = leerJson(rutaPackageJson).version;
	if (process.argv[2] === '--set') {
		const xy = process.argv[3];
		if (!xy) throw new Error('--set necesita un valor, ej. "node version.mjs --set 0.2"');
		return versionFijada(xy);
	}
	return bumpPatch(actual);
}

export function actualizarVersion() {
	const nuevaVersion = calcularNuevaVersion();
	for (const ruta of [rutaPackageJson, rutaManifest]) {
		escribirVersion(ruta, nuevaVersion);
	}
	return nuevaVersion;
}

// Sólo corre si se invoca directo (`node version.mjs`), no cuando
// `package.mjs` importa `actualizarVersion` para llamarla él mismo.
if (import.meta.url === `file://${process.argv[1]}`) {
	console.log(`Versión: ${actualizarVersion()}`);
}
