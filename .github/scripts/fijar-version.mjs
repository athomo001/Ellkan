// Autor: Athan Espinoza
//
// Releases (pendientes #128/#129): una sola versión para la app de escritorio
// y la extensión, tomada del tag `vX.Y.Z`. La escribe en los archivos de donde
// la leen los empaquetadores (Tauri para MSI/AppImage/.deb y la extensión, que
// además viaja embebida en la app).
//
// Reemplaza el texto del primer `"version": "…"` en vez de `JSON.stringify`
// para no reformatear los archivos (mismo criterio que `extension/version.mjs`),
// y después verifica que el JSON siga siendo válido y diga lo esperado.
//
//   node .github/scripts/fijar-version.mjs 0.2.0

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = process.argv[2] ?? '';
if (!/^\d+\.\d+\.\d+$/.test(version)) {
	console.error(`versión inválida: "${version}" (se espera X.Y.Z; el MSI y los navegadores no aceptan sufijos como -beta)`);
	process.exit(1);
}

const raiz = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const archivos = ['app-escritorio/src-tauri/tauri.conf.json', 'extension/package.json', 'extension/manifest.source.json'];

for (const relativo of archivos) {
	const ruta = resolve(raiz, relativo);
	const nuevo = readFileSync(ruta, 'utf8').replace(/("version"\s*:\s*")[^"]*(")/, `$1${version}$2`);
	if (JSON.parse(nuevo).version !== version) {
		console.error(`${relativo}: no se pudo fijar la versión (¿falta "version" en el primer nivel?)`);
		process.exit(1);
	}
	writeFileSync(ruta, nuevo);
	console.log(`${relativo}: ${version}`);
}
