// Autor: Athan Espinoza

// Empaquetado multi-navegador (2026-08-15) — hasta ahora los `.zip`/`.crx`/
// `.xpi` se armaban a mano en cada sesión, sin script. Reusa `build.mjs`
// (ya resuelve el manifest por navegador) y arma los artefactos instalables:
// - `ellkan-chrome.zip`/`ellkan-edge.zip`/`ellkan-brave.zip`/`ellkan-opera.zip`
//   desde el MISMO build de `chrome` — Edge/Brave/Opera son Chromium MV3 sin
//   ninguna clave de manifest propia hoy (spec 06 §1, sólo hay prefijos
//   `__chrome__`/`__firefox__`/`__safari__`) — no se inventa un prefijo
//   `__edge__` sin una diferencia real que resolver.
// - `ellkan-firefox.xpi` desde el build de `firefox` (un `.xpi` es sólo un
//   `.zip` renombrado).
// - `ellkan-chrome.crx` (opcional): firmado con `ellkan-chrome.pem` ya
//   existente vía `chrome --pack-extension`; si el binario no está
//   disponible en esta máquina, se avisa y se sigue — mismo criterio que
//   `build.mjs` con Safari (nunca un error duro por algo fuera de control).
// Safari sigue sin empaquetado automático (exige Xcode/Swift, spec 06 §7).
//
// Versión (2026-08-15): cada corrida bumpea sola el último dígito
// (`version.mjs`, sin argumentos) antes de construir nada — para fijar un
// x.y nuevo con reset de patch, correr `node version.mjs --set 0.2` (o
// `pnpm run version:set -- 0.2`) ANTES de `pnpm run package`, ver README.

import { execFileSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { actualizarVersion } from './version.mjs';

const raiz = dirname(fileURLToPath(import.meta.url));
const dist = resolve(raiz, 'dist');

console.log(`Versión: ${actualizarVersion()}`);

function construir(browser) {
	execFileSync('node', ['build.mjs'], { cwd: raiz, env: { ...process.env, BROWSER: browser }, stdio: 'inherit' });
}

function zipear(nombreSalida) {
	const destino = resolve(raiz, nombreSalida);
	rmSync(destino, { force: true });
	// `-r` recursivo, corrido con `cwd: dist` para que las rutas dentro del
	// zip sean relativas a la raíz de la extensión (`manifest.json` en la
	// raíz del archivo, no bajo `dist/`) — exigido por todos los navegadores.
	execFileSync('zip', ['-r', destino, '.'], { cwd: dist, stdio: 'inherit' });
	console.log(`  → ${nombreSalida}`);
}

console.log('Construyendo Chrome…');
construir('chrome');
for (const nombre of ['ellkan-chrome.zip', 'ellkan-edge.zip', 'ellkan-brave.zip', 'ellkan-opera.zip']) {
	zipear(nombre);
}

const pem = resolve(raiz, 'ellkan-chrome.pem');
const rutaChrome = process.env.ELLKAN_CHROME_BIN ?? '/usr/bin/google-chrome';
if (existsSync(pem) && existsSync(rutaChrome)) {
	try {
		execFileSync(rutaChrome, ['--headless', `--pack-extension=${dist}`, `--pack-extension-key=${pem}`], {
			stdio: 'inherit'
		});
		// Chrome empaqueta como `dist.crx` (mismo nombre que el directorio de
		// origen) — se renombra al nombre final del artefacto.
		const generado = resolve(raiz, 'dist.crx');
		if (existsSync(generado)) {
			execFileSync('mv', [generado, resolve(raiz, 'ellkan-chrome.crx')]);
			console.log('  → ellkan-chrome.crx');
		}
	} catch (e) {
		console.warn(`Aviso: no se pudo generar el .crx (${e.message}) — se sigue sin él.`);
	}
} else {
	console.warn('Aviso: sin ellkan-chrome.pem o sin Chrome instalado — se salta el .crx.');
}

console.log('\nConstruyendo Firefox…');
construir('firefox');
zipear('ellkan-firefox.xpi');

console.log('\nSafari: sin empaquetado automático (exige Xcode/Swift) — build manual desde `dist/` (BROWSER=safari).');
console.log('\nListo.');
