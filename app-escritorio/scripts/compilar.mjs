// Autor: Athan Espinoza
//
// Punto de entrada único para compilar la app de escritorio, en Windows o en
// Linux. Detecta el sistema, traduce las opciones y delega en el script propio
// de cada uno, que deja el resultado en su carpeta:
//   Windows -> app-escritorio/windows/binarios/  (.exe + .zip, o .msi)
//   Linux   -> app-escritorio/linuxOS/binarios/  (.AppImage, o .deb + .rpm + .AppImage)
//
// Cada instalador sólo se puede generar en su propio sistema (el .msi necesita
// Windows; el .deb/.rpm/.AppImage, Linux): para tener los dos hay que correr
// esto una vez en cada uno.
//
// Uso (desde la raíz del repo, o `pnpm build:desktop -- <opciones>` desde frontend/):
//   node app-escritorio/scripts/compilar.mjs                  portable: .exe + .zip / .AppImage
//   node app-escritorio/scripts/compilar.mjs --instalador     .msi / .deb + .rpm + .AppImage
//   --version 0.2.0        fija la versión (X.Y.Z)
//   --mantener-version     Windows: no sube el parche al generar el .msi
//   --formatos deb,rpm     Linux: elige los formatos a mano
//   --sin-frontend         reusa frontend/build ya compilado
//   --sin-extension        no vuelve a preparar la extensión de navegador

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const raizEscritorio = join(dirname(fileURLToPath(import.meta.url)), '..');

function ayuda() {
	const texto = readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n');
	console.log(texto.slice(2, 20).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
}

function salirConError(mensaje) {
	console.error(`Error: ${mensaje} (ver --help)`);
	process.exit(1);
}

// --- Opciones ---
const opciones = { instalador: false, version: '', mantenerVersion: false, formatos: '', sinFrontend: false, sinExtension: false };
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
	const a = args[i];
	switch (a) {
		case '--instalador':
			opciones.instalador = true;
			break;
		case '--version':
			opciones.version = args[++i] ?? '';
			if (!/^\d+\.\d+\.\d+$/.test(opciones.version)) salirConError('--version espera X.Y.Z, ej. 0.2.0');
			break;
		case '--mantener-version':
			opciones.mantenerVersion = true;
			break;
		case '--formatos':
			opciones.formatos = args[++i] ?? '';
			if (!/^(deb|rpm|appimage)(,(deb|rpm|appimage))*$/.test(opciones.formatos)) salirConError('--formatos espera una lista como deb,rpm,appimage');
			break;
		case '--sin-frontend':
			opciones.sinFrontend = true;
			break;
		case '--sin-extension':
			opciones.sinExtension = true;
			break;
		case '-h':
		case '--help':
			ayuda();
			process.exit(0);
		default:
			salirConError(`opción desconocida: ${a}`);
	}
}

function ejecutar(programa, argumentos) {
	console.log(`> ${programa} ${argumentos.join(' ')}\n`);
	const r = spawnSync(programa, argumentos, { stdio: 'inherit' });
	if (r.error) salirConError(`no se pudo ejecutar ${programa}: ${r.error.message}`);
	process.exit(r.status ?? 1);
}

// --- Windows ---
if (process.platform === 'win32') {
	if (opciones.formatos) salirConError('--formatos es sólo para Linux');
	const ps = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(raizEscritorio, 'windows', 'binarios', 'build-windows.ps1')];
	if (opciones.instalador) ps.push('-Msi');
	if (opciones.mantenerVersion) ps.push('-MantenerVersion');
	if (opciones.version) ps.push('-Version', opciones.version);
	if (opciones.sinFrontend) ps.push('-SkipFrontend');
	if (opciones.sinExtension) ps.push('-SkipExtension');
	ejecutar('powershell', ps);
}

// --- Linux ---
if (process.platform === 'linux') {
	if (opciones.mantenerVersion) console.log('Aviso: --mantener-version no aplica en Linux (la versión no sube sola).');
	if (opciones.version) {
		// Misma fuente de verdad que en Windows: de acá la toman los paquetes y la propia app.
		const conf = join(raizEscritorio, 'src-tauri', 'tauri.conf.json');
		const texto = readFileSync(conf, 'utf8');
		writeFileSync(conf, texto.replace(/("version"\s*:\s*")[^"]*(")/, `$1${opciones.version}$2`));
		console.log(`Versión fijada en ${opciones.version} (src-tauri/tauri.conf.json).`);
	}
	// Sin --instalador, el equivalente al .exe portable de Windows es el AppImage.
	const formatos = opciones.formatos || (opciones.instalador ? 'deb,rpm,appimage' : 'appimage');
	const sh = [join(raizEscritorio, 'linuxOS', 'binarios', 'build-linux.sh'), '--bundles', formatos];
	if (opciones.sinFrontend) sh.push('--sin-frontend');
	if (opciones.sinExtension) sh.push('--sin-extension');
	ejecutar('bash', sh);
}

salirConError(`sistema no soportado todavía: ${process.platform} (macOS queda para más adelante)`);
