#!/usr/bin/env node
// Autor: Athan Espinoza

// CLI de empaquetado de la extensión (2026-09-08) — "comando + banderas" sobre
// el mismo `build.mjs`/`version.mjs` que ya existía. `pnpm run package` sin
// banderas sigue dando el mismo resultado de siempre (delega acá); lo nuevo:
//   - elegir uno o varios navegadores (`-b`), no siempre los 6
//   - control de versión: patch (default) | minor | major | x.y | x.y.z | keep
//   - `--no-crx`, `--out <dir>`, `--dry-run`, `--check`, `--list`
//
// Ejemplos:
//   node cli.mjs                          # todos, bump de patch, .crx si hay Chrome
//   node cli.mjs -b firefox               # sólo ellkan-firefox.xpi
//   node cli.mjs -b chrome,edge --no-crx  # sólo esos .zip, sin firmar .crx
//   node cli.mjs firefox chrome           # posicionales = lo mismo que -b
//   node cli.mjs --version minor          # 0.2.7 -> 0.3.0 y empaqueta todo
//   node cli.mjs --version 1.0.0 -o out   # fija 1.0.0, artefactos en ./out/
//   node cli.mjs -b all --keep --dry-run  # muestra qué haría, sin tocar nada

import { execFileSync } from 'node:child_process';
import { existsSync, rmSync, mkdirSync, renameSync, cpSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { aplicarVersion, resolverVersion, versionActual } from './version.mjs';

const raiz = dirname(fileURLToPath(import.meta.url));
const dist = resolve(raiz, 'dist');

// Familia Chromium: mismo build de `chrome`, sólo cambia el nombre del `.zip`
// (Edge/Brave/Opera no tienen ninguna clave de manifest propia hoy, spec 06 §1).
const CHROMIUM = ['chrome', 'edge', 'brave', 'opera'];
const CONOCIDOS = [...CHROMIUM, 'firefox', 'safari'];

const AYUDA = `
Uso: node cli.mjs [navegadores...] [opciones]

  -b, --browser <lista>   Navegadores a empaquetar, separados por coma o repetido.
                          Valores: ${CONOCIDOS.join(', ')}, all   (default: all)
                          También como posicionales: node cli.mjs firefox chrome
  -v, --version <spec>    patch (default) | minor | major | x.y | x.y.z | keep
      --keep              Atajo de --version keep (no toca la versión)
      --no-crx            No generar el .crx firmado de Chrome
  -o, --out <dir>         Carpeta de salida (default: la de la extensión)
  -n, --dry-run           Mostrar qué se haría, sin construir ni escribir
      --check             Correr antes 'pnpm check' + 'pnpm check:self'; abortar si fallan
  -l, --list              Listar los navegadores y cuáles se automatizan
  -h, --help              Esta ayuda

Artefactos: ellkan-<navegador>.zip  (.xpi para Firefox, .crx opcional para Chrome).
Safari no se automatiza (requiere Xcode/Swift) — sólo se recuerda el paso manual.
`;

function parsear() {
	try {
		return parseArgs({
			options: {
				browser: { type: 'string', short: 'b', multiple: true },
				version: { type: 'string', short: 'v' },
				keep: { type: 'boolean' },
				'no-crx': { type: 'boolean' },
				out: { type: 'string', short: 'o' },
				'dry-run': { type: 'boolean', short: 'n' },
				check: { type: 'boolean' },
				list: { type: 'boolean', short: 'l' },
				help: { type: 'boolean', short: 'h' },
			},
			allowPositionals: true,
		});
	} catch (e) {
		console.error(`Error de argumentos: ${e.message}`);
		console.error(AYUDA);
		process.exit(2);
	}
}

/** Aplana `-b chrome,edge -b firefox` + posicionales -> lista ordenada y sin
 * duplicados; expande `all`; valida contra CONOCIDOS. Vacío -> todos. */
function resolverTargets(entradas) {
	const pedidos = entradas
		.flatMap((x) => x.split(','))
		.map((x) => x.trim().toLowerCase())
		.filter(Boolean);
	if (pedidos.length === 0) return [...CONOCIDOS];
	const salida = [];
	for (const p of pedidos) {
		const expandido = p === 'all' ? CONOCIDOS : [p];
		for (const b of expandido) {
			if (!CONOCIDOS.includes(b)) {
				console.error(`Navegador desconocido: "${b}". Válidos: ${CONOCIDOS.join(', ')}, all`);
				process.exit(2);
			}
			if (!salida.includes(b)) salida.push(b);
		}
	}
	return salida;
}

/** Ruta al binario de Chrome para firmar el `.crx` — env explícita o los
 * lugares típicos por SO. `null` si no se encuentra (el `.crx` es opcional). */
function rutaChrome() {
	if (process.env.ELLKAN_CHROME_BIN) return process.env.ELLKAN_CHROME_BIN;
	const candidatos =
		{
			win32: [
				'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
				'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
			],
			darwin: ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'],
			linux: ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'],
		}[process.platform] ?? [];
	return candidatos.find(existsSync) ?? null;
}

const { values: opts, positionals } = parsear();

if (opts.help) {
	console.log(AYUDA);
	process.exit(0);
}
if (opts.list) {
	console.log('Navegadores:');
	for (const b of CHROMIUM) console.log(`  ${b.padEnd(9)} .zip   (build de chrome, mismo binario)`);
	console.log('  firefox   .xpi   (build propio, BROWSER=firefox)');
	console.log('  safari    —      manual: BROWSER=safari node build.mjs -> dist/ -> Xcode');
	process.exit(0);
}

const dryRun = Boolean(opts['dry-run']);
const versionSpec = opts.keep ? 'keep' : (opts.version ?? 'patch');
const salidaDir = opts.out ? resolve(process.cwd(), opts.out) : raiz;
const targets = resolverTargets([...(opts.browser ?? []), ...positionals]);

// Falla temprano (mensaje limpio, sin stack) si el spec de versión es inválido.
try {
	resolverVersion(versionActual(), versionSpec);
} catch (e) {
	console.error(`Error: ${e.message}`);
	process.exit(2);
}

const chromiumPedidos = targets.filter((t) => CHROMIUM.includes(t));
const haceFirefox = targets.includes('firefox');
const haceSafari = targets.includes('safari');
const haceCrx = chromiumPedidos.length > 0 && !opts['no-crx'];

function paso(msg) {
	console.log(`\n${dryRun ? '[dry-run] ' : ''}${msg}`);
}

function construir(browser) {
	paso(`Construyendo ${browser}…`);
	if (dryRun) {
		console.log(`  BROWSER=${browser} node build.mjs`);
		return;
	}
	execFileSync('node', ['build.mjs'], { cwd: raiz, env: { ...process.env, BROWSER: browser }, stdio: 'inherit' });
}

function zipear(nombre) {
	const destino = resolve(salidaDir, nombre);
	if (dryRun) {
		console.log(`  zip -r ${destino} .   (desde ${dist})`);
		return;
	}
	rmSync(destino, { force: true });
	execFileSync('zip', ['-r', destino, '.'], { cwd: dist, stdio: 'inherit' });
	console.log(`  → ${destino}`);
}

// --- Chequeos previos opcionales ---------------------------------------------

if (opts.check) {
	paso('Chequeos previos (pnpm check + pnpm check:self)…');
	for (const script of ['check', 'check:self']) {
		if (dryRun) {
			console.log(`  pnpm run ${script}`);
			continue;
		}
		try {
			const pnpm = process.env.npm_execpath;
			if (pnpm) execFileSync(process.execPath, [pnpm, 'run', script], { cwd: raiz, stdio: 'inherit' });
			else execFileSync(process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm', ['run', script], { cwd: raiz, stdio: 'inherit' });
		} catch {
			console.error(`\n"${script}" falló — se aborta el empaquetado (nada se escribió, ni la versión).`);
			process.exit(1);
		}
	}
}

// --- Versión ---------------------------------------------------------------

const nuevaVersion = dryRun ? resolverVersion(versionActual(), versionSpec) : aplicarVersion(versionSpec);
paso(`Versión: ${nuevaVersion}${versionSpec === 'keep' ? ' (sin cambios)' : ''}`);

if (!dryRun && salidaDir !== raiz) mkdirSync(salidaDir, { recursive: true });

// --- Chromium (chrome/edge/brave/opera) ----------------------------------

if (chromiumPedidos.length > 0) {
	construir('chrome');
	for (const t of chromiumPedidos) zipear(`ellkan-${t}.zip`);

	if (haceCrx) {
		const pem = resolve(raiz, 'ellkan-chrome.pem');
		const chrome = rutaChrome();
		if (!existsSync(pem) || !chrome) {
			console.warn('  Aviso: sin ellkan-chrome.pem o sin Chrome instalado — se salta el .crx.');
		} else if (dryRun) {
			console.log(`  ${chrome} --headless --pack-extension=${dist} --pack-extension-key=${pem}`);
		} else {
			paso('Firmando .crx de Chrome…');
			try {
				execFileSync(chrome, ['--headless', `--pack-extension=${dist}`, `--pack-extension-key=${pem}`], { stdio: 'inherit' });
				// Chrome escribe `<dir>.crx` junto al directorio de origen.
				const generado = resolve(raiz, 'dist.crx');
				if (existsSync(generado)) {
					const destino = resolve(salidaDir, 'ellkan-chrome.crx');
					rmSync(destino, { force: true });
					try {
						renameSync(generado, destino);
					} catch {
						cpSync(generado, destino);
						rmSync(generado, { force: true });
					}
					console.log(`  → ${destino}`);
				}
			} catch (e) {
				console.warn(`  Aviso: no se pudo generar el .crx (${e.message}) — se sigue sin él.`);
			}
		}
	}
}

// --- Firefox -------------------------------------------------------------

if (haceFirefox) {
	construir('firefox');
	zipear('ellkan-firefox.xpi');
}

// --- Safari (sólo recordatorio) ----------------------------------------

if (haceSafari) {
	paso('Safari: sin empaquetado automático (exige Xcode/Swift).');
	console.log('  Manual: BROWSER=safari node build.mjs  →  cargar dist/ en un proyecto Safari Web Extension (Xcode).');
}

console.log(`\n${dryRun ? 'Nada se escribió (dry-run).' : 'Listo.'}`);
