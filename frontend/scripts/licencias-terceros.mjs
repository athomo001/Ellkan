// Autor: Athan Espinoza
//
// spec/14 punto 6.9: genera `THIRD-PARTY-NOTICES.md` en la raíz del repo con
// las dependencias de terceros que viajan en Ellkan — crates de Rust del
// workspace (backend, CLI, app de escritorio, núcleo cripto) y paquetes npm de
// producción del frontend y de la extensión — y FALLA (código 1) si alguna
// tiene una licencia fuera de `COMPATIBLES` (compatibles con AGPL-3.0). No
// necesita herramientas extra: usa `cargo metadata` y `pnpm licenses`.
//
// Uso, desde la raíz:   node frontend/scripts/licencias-terceros.mjs
//       sólo revisar:   node frontend/scripts/licencias-terceros.mjs --revisar

import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const raiz = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const soloRevisar = process.argv.includes('--revisar');

/** Licencias permisivas o débiles compatibles con distribuir bajo AGPL-3.0. */
const COMPATIBLES = new Set([
	'MIT', 'MIT-0', 'Apache-2.0', 'Apache-2.0 WITH LLVM-exception', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'ISC', 'Zlib',
	'Unicode-3.0', 'Unicode-DFS-2016', 'BSL-1.0', 'CC0-1.0', 'Unlicense', 'MPL-2.0', 'OFL-1.1', 'CDLA-Permissive-2.0',
	'AGPL-3.0-only', 'AGPL-3.0-or-later', 'GPL-3.0-or-later', 'LGPL-3.0-or-later', 'Python-2.0', 'BlueOak-1.0.0'
]);

/** ¿La expresión SPDX se puede cumplir con licencias de `COMPATIBLES`? */
function esCompatible(expresion) {
	if (!expresion) return false;
	// `MIT/Apache-2.0` es la forma vieja de Cargo para `MIT OR Apache-2.0`.
	const limpia = expresion.replace(/[()]/g, ' ').replace(/\s*\/\s*/g, ' OR ').replace(/\s+/g, ' ').trim();
	// "A OR B": alcanza con una; "A AND B": hacen falta todas. Sin anidar
	// paréntesis complejos (no aparecen en este árbol).
	return limpia.split(/ OR /i).some((alternativa) =>
		alternativa.split(/ AND /i).every((l) => COMPATIBLES.has(l.trim()) || COMPATIBLES.has(l.trim().replace(/\+$/, '-or-later')))
	);
}

function ejecutar(comando, args, cwd) {
	const opciones = { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 };
	// En Windows `pnpm` es un `.cmd`: hace falta el shell. Los argumentos son
	// fijos de este script, nunca entrada del usuario.
	if (process.platform === 'win32') return execFileSync([comando, ...args].join(' '), { ...opciones, shell: true });
	return execFileSync(comando, args, opciones);
}

// --- Rust: todo el lockfile del workspace, menos los propios crates.
const meta = JSON.parse(ejecutar('cargo', ['metadata', '--format-version', '1', '--locked'], raiz));
const propios = new Set(meta.workspace_members);
const crates = meta.packages
	.filter((p) => !propios.has(p.id))
	.map((p) => ({ nombre: p.name, version: p.version, licencia: p.license ?? (p.license_file ? `ver ${p.license_file}` : ''), origen: p.repository ?? '' }))
	.sort((a, b) => a.nombre.localeCompare(b.nombre) || a.version.localeCompare(b.version));

// --- npm: sólo dependencias de producción (lo que se empaqueta).
function paquetesNpm(carpeta) {
	const porLicencia = JSON.parse(ejecutar('pnpm', ['licenses', 'list', '--prod', '--json'], resolve(raiz, carpeta)));
	const lista = [];
	for (const [licencia, paquetes] of Object.entries(porLicencia)) {
		for (const p of paquetes) {
			for (const version of p.versions) lista.push({ nombre: p.name, version, licencia, origen: p.homepage ?? '' });
		}
	}
	return lista.sort((a, b) => a.nombre.localeCompare(b.nombre));
}
const npm = [...paquetesNpm('frontend'), ...paquetesNpm('extension')].filter(
	(p, i, todos) => todos.findIndex((q) => q.nombre === p.nombre && q.version === p.version) === i
);

const incompatibles = [...crates, ...npm].filter((p) => !esCompatible(p.licencia));

if (!soloRevisar) {
	const fila = (p) => `| ${p.nombre} | ${p.version} | ${p.licencia || '—'} | ${p.origen} |`;
	const texto = `# Avisos de terceros — Ellkan

Ellkan se distribuye bajo AGPL-3.0 (ver [LICENSE](LICENSE)). Incluye o enlaza el software de terceros listado abajo, cada uno bajo su propia licencia; el texto completo de cada licencia está en el repositorio de origen de cada paquete.

Las fuentes tipográficas (Atkinson Hyperlegible, Atkinson Hyperlegible Mono, Lexend, OpenDyslexic) se distribuyen bajo la SIL Open Font License 1.1, con su texto junto a los archivos: \`frontend/static/fonts/LICENSE-*.txt\` (y \`fonts/\` dentro de la extensión).

Generado con \`node frontend/scripts/licencias-terceros.mjs\` — no editar a mano.

## Rust (${crates.length} crates)

| Crate | Versión | Licencia | Origen |
| --- | --- | --- | --- |
${crates.map(fila).join('\n')}

## npm — frontend web, app de escritorio y extensión (${npm.length} paquetes)

| Paquete | Versión | Licencia | Origen |
| --- | --- | --- | --- |
${npm.map(fila).join('\n')}
`;
	writeFileSync(resolve(raiz, 'THIRD-PARTY-NOTICES.md'), texto);
	console.log(`THIRD-PARTY-NOTICES.md: ${crates.length} crates, ${npm.length} paquetes npm.`);
}

if (incompatibles.length > 0) {
	console.error(`\n${incompatibles.length} dependencia(s) con licencia a revisar (no está en la lista de compatibles con AGPL-3.0):`);
	for (const p of incompatibles) console.error(`  ${p.nombre} ${p.version}: ${p.licencia || '(sin licencia declarada)'}`);
	process.exit(1);
}
console.log('Todas las licencias son compatibles con AGPL-3.0.');
