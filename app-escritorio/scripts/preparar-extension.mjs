// Autor: Athan Espinoza
//
// Punto 9: deja la extensión de navegador lista para embeberla en el
// ejecutable de escritorio. Compila la extensión una vez para Chromium
// (Chrome/Edge/Brave/Opera) y otra para Firefox y copia cada resultado a
// `app-escritorio/src-tauri/extension-bundle/<chromium|firefox>/`, que es lo
// que `src-tauri/build.rs` convierte en `include_bytes!`.
//
//   node app-escritorio/scripts/preparar-extension.mjs
//
// Lo corren `windows/binarios/build-windows.ps1` y `linuxOS/binarios/
// build-linux.sh` antes de compilar la app, así cada build de escritorio trae
// la ÚLTIMA versión de la extensión — y como la app la refresca en cada
// arranque en las carpetas de los navegadores elegidos, una extensión nueva
// llega a los usuarios con la próxima versión de la app.
//
// Ojo: `extension/dist/` es la salida única de `build.mjs`, así que esto lo
// deja con el último build (Firefox). Está ignorado por git.

import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';

const raiz = path.resolve(import.meta.dirname, '..', '..');
const carpetaExtension = path.join(raiz, 'extension');
const bundle = path.join(raiz, 'app-escritorio', 'src-tauri', 'extension-bundle');
const wasm = path.join(raiz, 'frontend', 'src', 'lib', 'wasm', 'ellkan_crypto_bg.wasm');

function fallar(mensaje) {
	console.error(`\nERROR: ${mensaje}`);
	process.exit(1);
}

if (!existsSync(path.join(carpetaExtension, 'node_modules'))) {
	fallar('falta extension/node_modules — corré `pnpm install` dentro de extension/ antes de preparar el bundle.');
}
if (!existsSync(wasm)) {
	fallar(`falta ${path.relative(raiz, wasm)}: la extensión lo copia en cada build y hay que generarlo primero (wasm-pack de ellkan-crypto).`);
}

const objetivos = [
	{ objetivo: 'chromium', browser: 'chrome' },
	{ objetivo: 'firefox', browser: 'firefox' }
];

const versiones = new Map();

for (const { objetivo, browser } of objetivos) {
	console.log(`\n=== Compilando la extensión para ${objetivo} (BROWSER=${browser}) ===`);
	const resultado = spawnSync(process.execPath, ['build.mjs'], {
		cwd: carpetaExtension,
		env: { ...process.env, BROWSER: browser },
		stdio: 'inherit'
	});
	if (resultado.status !== 0) fallar(`la compilación de la extensión para ${objetivo} terminó con código ${resultado.status}.`);

	const dist = path.join(carpetaExtension, 'dist');
	const manifestRuta = path.join(dist, 'manifest.json');
	if (!existsSync(manifestRuta)) fallar(`no se generó ${path.relative(raiz, manifestRuta)}.`);

	const manifest = JSON.parse(readFileSync(manifestRuta, 'utf8'));

	// El manifest cambia según el navegador: un build para el objetivo
	// equivocado (p. ej. una `dist/` vieja de Safari) no se puede cargar.
	if (objetivo === 'chromium' && !manifest.background?.service_worker) {
		fallar('el build de Chromium no tiene background.service_worker — el manifest no es el de Chrome.');
	}
	if (objetivo === 'firefox' && !manifest.browser_specific_settings?.gecko?.id) {
		fallar('el build de Firefox no tiene browser_specific_settings.gecko.id — el manifest no es el de Firefox.');
	}

	const destino = path.join(bundle, objetivo);
	rmSync(destino, { recursive: true, force: true });
	mkdirSync(destino, { recursive: true });
	cpSync(dist, destino, { recursive: true });
	versiones.set(objetivo, manifest.version);
	console.log(`-> ${path.relative(raiz, destino)} (v${manifest.version})`);
}

const [primera, ...resto] = [...versiones.values()];
if (resto.some((v) => v !== primera)) {
	fallar(`las versiones no coinciden entre navegadores: ${JSON.stringify(Object.fromEntries(versiones))}`);
}

console.log(`\nExtensión v${primera} lista en app-escritorio/src-tauri/extension-bundle/. Ahora compilá la app de escritorio.`);
