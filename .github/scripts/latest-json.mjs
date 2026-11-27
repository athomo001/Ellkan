// Autor: Athan Espinoza
//
// F-53 (#60): arma `latest.json`, el manifiesto que lee el actualizador de la
// app de escritorio (`tauri-plugin-updater`, formato de archivo estático).
//
// Uso: node latest-json.mjs <carpeta de artefactos> <X.Y.Z> <URL base de descarga> [sección del CHANGELOG]
//
// Busca los paquetes firmados (`<paquete>.sig`, de `tauri signer sign`):
//   - Ellkan_X.Y.Z_x64_es-ES.msi      → windows-x86_64
//   - Ellkan_X.Y.Z_amd64.AppImage     → linux-x86_64
// Si no hay ninguno (no estaba el secreto de firma), no escribe nada: la app
// instalada no ve esa versión como actualización, que es lo correcto.
// La firma se verifica en la app contra la clave pública de `tauri.conf.json`
// antes de instalar; este archivo sólo dice dónde está cada paquete.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [carpeta, version, urlBase, seccion = version] = process.argv.slice(2);
if (!carpeta || !/^\d+\.\d+\.\d+$/.test(version ?? '') || !urlBase?.startsWith('https://')) {
	console.error('uso: latest-json.mjs <carpeta> <X.Y.Z> <https://…/releases/download/vX.Y.Z> [sección]');
	process.exit(2);
}

const paquetes = {
	'windows-x86_64': `Ellkan_${version}_x64_es-ES.msi`,
	'linux-x86_64': `Ellkan_${version}_amd64.AppImage`
};

const platforms = {};
for (const [plataforma, archivo] of Object.entries(paquetes)) {
	const sig = join(carpeta, `${archivo}.sig`);
	if (!existsSync(join(carpeta, archivo)) || !existsSync(sig)) continue;
	platforms[plataforma] = {
		signature: readFileSync(sig, 'utf8').trim(),
		url: `${urlBase}/${encodeURIComponent(archivo)}`
	};
}

if (Object.keys(platforms).length === 0) {
	console.log('Sin paquetes firmados: no se publica latest.json.');
	process.exit(0);
}

// Notas: la misma sección del CHANGELOG que la Release, acotada (la app las
// muestra en Ajustes; el detalle completo está en la página de la Release).
let notas = `Ellkan ${version}`;
try {
	const cuerpo = execFileSync('bash', ['.github/scripts/notas-del-changelog.sh', seccion], { encoding: 'utf8' }).trim();
	if (cuerpo) notas = cuerpo.length > 4000 ? `${cuerpo.slice(0, 4000)}…` : cuerpo;
} catch {
	/* sin notas legibles: alcanza con la versión */
}

const manifiesto = { version, notes: notas, pub_date: new Date().toISOString(), platforms };
writeFileSync(join(carpeta, 'latest.json'), `${JSON.stringify(manifiesto, null, 2)}\n`);
console.log(`latest.json: ${Object.keys(platforms).join(', ')}`);
