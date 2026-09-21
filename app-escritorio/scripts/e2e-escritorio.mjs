// Autor: Athan Espinoza
//
// Prueba de punta a punta de la app de escritorio REAL, sin herramientas
// externas: lanza el `.exe` con un perfil TEMPORAL (no toca los datos del
// usuario), abre el puerto de depuración de WebView2 y maneja la interfaz por
// el protocolo CDP (Node >= 22 trae WebSocket). Es lo que faltaba para dejar
// de marcar como "sin probar con clicks reales" lo que sólo se veía con la
// ventana abierta.
//
//   node app-escritorio/scripts/e2e-escritorio.mjs [ruta\al\ellkan-desktop.exe]
//
// Qué recorre: registro -> login -> gate del recovery kit (descarga real del
// kit) -> menú lateral (medidas, sin desfasaje) -> Ajustes -> Escritorio (la
// extensión, con navegadores FALSOS para no abrir uno real) -> cerrar sesión
// -> recuperación con el kit (sin correo) -> login con la contraseña nueva.
// Guarda capturas en %TEMP%\ellkan-e2e\ y sale con código != 0 si algo falla.
//
// Aislamiento: APPDATA/LOCALAPPDATA/ELLKAN_CONFIG_DIR apuntan a una carpeta
// temporal y ELLKAN_NAVEGADORES_DIR a una carpeta con "navegadores" falsos
// (whoami.exe renombrado). Lo único que sale del perfil temporal es el archivo del kit,
// que la app guarda en la carpeta Descargas REAL — el script lo borra al final.

import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const exe = path.resolve(process.argv[2] ?? path.join(import.meta.dirname, '..', 'windows', 'binarios', 'ellkan-desktop.exe'));
const PUERTO = 9333;
const raiz = path.join(os.tmpdir(), 'ellkan-e2e');
const perfil = path.join(raiz, `perfil-${Date.now()}`);
const capturas = path.join(raiz, 'capturas');
mkdirSync(capturas, { recursive: true });

const RAMA_REGISTRO = 'Software\\EllkanPruebas';
const EMAIL = 'prueba-e2e@ellkan.test';
const PASS1 = 'Tulipan-Azul-Nube-2026!xQ';
const PASS2 = 'Cascada-Verde-Faro-2027!zR';

const dormir = (ms) => new Promise((r) => setTimeout(r, ms));
const resultados = [];
let app;
let cdp;
const archivosABorrar = [];

function paso(nombre, ok, detalle = '') {
	resultados.push({ nombre, ok, detalle });
	console.log(`${ok ? 'OK  ' : 'FALLA'} ${nombre}${detalle ? ` — ${detalle}` : ''}`);
}

async function esperar(desc, fn, ms = 30000) {
	const inicio = Date.now();
	let ultimo;
	while (Date.now() - inicio < ms) {
		try {
			const v = await fn();
			if (v) return v;
		} catch (e) {
			ultimo = e;
		}
		await dormir(300);
	}
	throw new Error(`timeout esperando: ${desc}${ultimo ? ` (${ultimo.message})` : ''}`);
}

class Cdp {
	constructor(ws) {
		this.ws = ws;
		this.id = 0;
		this.pendientes = new Map();
		ws.onmessage = (m) => {
			const d = JSON.parse(m.data);
			const p = this.pendientes.get(d.id);
			if (p) {
				this.pendientes.delete(d.id);
				d.error ? p.reject(new Error(d.error.message)) : p.resolve(d.result);
			}
		};
	}
	send(method, params = {}) {
		const id = ++this.id;
		this.ws.send(JSON.stringify({ id, method, params }));
		return new Promise((resolve, reject) => this.pendientes.set(id, { resolve, reject }));
	}
	async ev(expresion, ms = 20000) {
		// Sin tope, una promesa de la página que nunca se resuelve (p. ej. un
		// permiso del navegador pendiente) colgaba toda la prueba en silencio.
		const espera = new Promise((_, rechazar) => setTimeout(() => rechazar(new Error(`la página no respondió en ${ms} ms: ${expresion.slice(0, 80)}`)), ms));
		const r = await Promise.race([this.send('Runtime.evaluate', { expression: expresion, awaitPromise: true, returnByValue: true }), espera]);
		if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
		return r.result.value;
	}
	async captura(nombre) {
		const r = await this.send('Page.captureScreenshot', { format: 'png' });
		const ruta = path.join(capturas, `${nombre}.png`);
		writeFileSync(ruta, Buffer.from(r.data, 'base64'));
		return ruta;
	}
}

const llenar = (sel, i, valor) =>
	`(() => { const els=[...document.querySelectorAll(${JSON.stringify(sel)})].filter(e=>e.offsetParent!==null);
	 const el=els[${i}]; if(!el) return false;
	 Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, ${JSON.stringify(valor)});
	 el.dispatchEvent(new Event('input',{bubbles:true})); return true; })()`;
const clickTexto = (txt, selector = 'button') =>
	`(() => { const b=[...document.querySelectorAll(${JSON.stringify(selector)})].find(b=>b.textContent.trim().includes(${JSON.stringify(txt)}) && !b.disabled);
	 if(!b) return false; b.click(); return true; })()`;
const llenarEtiqueta = (etiqueta, valor) =>
	`(() => { const l=[...document.querySelectorAll('label')].find(l=>l.textContent.trim().startsWith(${JSON.stringify(etiqueta)}) && l.offsetParent!==null);
	 const el=l && document.getElementById(l.htmlFor); if(!el) return false;
	 Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, ${JSON.stringify(valor)});
	 el.dispatchEvent(new Event('input',{bubbles:true})); return true; })()`;
const url = () => cdp.ev('location.pathname + location.search');
const enviarFormulario = `(() => { const f=[...document.querySelectorAll('form')].find(f=>f.offsetParent!==null); if(!f) return false; f.requestSubmit(); return true; })()`;

function prepararNavegadoresFalsos() {
	// whoami.exe termina al instante: la app "abre" el navegador falso, nunca uno
	// real. `ELLKAN_NAVEGADORES_DIR` hace que la app busque SÓLO ahí (en Windows
	// ni siquiera se puede redirigir `ProgramFiles` por entorno).
	const whoami = path.join(process.env.SystemRoot ?? 'C:/Windows', 'System32', 'whoami.exe');
	const carpeta = path.join(perfil, 'Navegadores');
	mkdirSync(carpeta, { recursive: true });
	for (const id of ['chrome', 'edge', 'firefox']) copyFileSync(whoami, path.join(carpeta, `${id}.exe`));
	return carpeta;
}

async function main() {
	if (!existsSync(exe)) throw new Error(`no existe ${exe}`);
	const navegadoresFalsos = prepararNavegadoresFalsos();
	for (const d of ['appdata', 'local', 'cfg']) mkdirSync(path.join(perfil, d), { recursive: true });

	const entorno = {
		...process.env,
		APPDATA: path.join(perfil, 'appdata'),
		LOCALAPPDATA: path.join(perfil, 'local'),
		ELLKAN_CONFIG_DIR: path.join(perfil, 'cfg'),
		ELLKAN_EXTENSION_DIR: path.join(perfil, 'Documentos'),
		ELLKAN_NAVEGADORES_DIR: navegadoresFalsos,
		// Inicio con la sesión y enlaces ellkan:// escriben en el registro: en otra rama,
		// para no tocar el del usuario (se borra al final).
		ELLKAN_REGISTRO_RAIZ: RAMA_REGISTRO,
		WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PUERTO}`
	};
	app = spawn(exe, [], { env: entorno, stdio: 'ignore' });

	const objetivo = await esperar('puerto de depuración de WebView2', async () => {
		const lista = await (await fetch(`http://127.0.0.1:${PUERTO}/json`)).json();
		return lista.find((t) => t.type === 'page' && !t.url.startsWith('devtools'));
	}, 60000);
	const ws = new WebSocket(objetivo.webSocketDebuggerUrl);
	await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = j)));
	cdp = new Cdp(ws);
	await cdp.send('Page.enable');
	paso('la app arranca y expone la ventana', true, objetivo.url);

	// --- registro ---------------------------------------------------------
	await esperar('pantalla cargada', () => cdp.ev("document.readyState === 'complete' && !!document.querySelector('form, main')"));
	// Primer uso: una instalación recién hecha (sin ninguna cuenta) tiene que llevar sola a
	// crear la cuenta, no dejar al usuario frente a un login que no puede aceptar a nadie.
	await esperar('primera pantalla de una instalación limpia', async () => (await url()).startsWith('/register'), 30000);
	paso('en una instalación limpia la app abre directo en "crear cuenta" (no en el login)', true, await url());
	// Los textos que busca este recorrido están en español: se fija el idioma
	// en vez de depender del idioma del sistema donde corra la prueba.
	await cdp.ev(`localStorage.setItem('ellkan:preferencias', JSON.stringify({locale:'es',theme:'dark',clipboardClearMinutes:1,autoLockMinutes:15}))`);
	await cdp.ev("location.assign('/register')");
	await esperar('formulario de registro', () => cdp.ev("document.querySelectorAll('form input').length >= 4"));
	await cdp.ev(llenar('form input', 0, 'Prueba E2E'));
	await cdp.ev(llenar('form input', 1, EMAIL));
	await cdp.ev(llenar('form input', 2, PASS1));
	await cdp.ev(llenar('form input', 3, PASS1));
	await cdp.ev(enviarFormulario);
	await esperar('redirección a /login tras registrar', async () => (await url()).startsWith('/login'), 90000);
	paso('registro de la cuenta local', true);

	// --- login ------------------------------------------------------------
	await esperar('formulario de login', () => cdp.ev("document.querySelectorAll('form input').length >= 2"));
	await cdp.ev(llenar('form input', 0, EMAIL));
	await cdp.ev(llenar('form input', 1, PASS1));
	await cdp.ev(enviarFormulario);
	await esperar('gate del recovery kit tras el login', async () => (await url()).startsWith('/onboarding/recovery-kit'), 120000);
	paso('login y gate del recovery kit (antes el 404 lo tragaba y nunca se ofrecía)', true);

	// --- kit + descarga real ---------------------------------------------
	const kit = await esperar('kit generado', () => cdp.ev("document.querySelector('code.kit')?.textContent?.trim() || false"), 60000);
	await cdp.captura('01-kit-antes-de-descargar');
	await cdp.ev(clickTexto('Descargar'));
	const guardado = await esperar('mensaje "Guardado en"', () => cdp.ev("document.querySelector('.guardado')?.textContent || false"), 20000);
	const ruta = guardado.replace(/^.*?:\s*/, '').trim();
	archivosABorrar.push(ruta);
	await cdp.captura('02-kit-guardado');
	paso('descargar el kit ahora guarda el archivo', existsSync(ruta), ruta);
	paso('el archivo guardado contiene el kit', existsSync(ruta) && readFileSync(ruta, 'utf8') === kit);
	await cdp.ev("(() => { const c=document.querySelector('input[type=checkbox]'); c.click(); return true; })()");
	await cdp.ev(clickTexto('Finalizar'));
	await esperar('llegada al vault', async () => (await url()).startsWith('/vault'), 30000);
	paso('finalizar el kit lo registra y entra al vault', true);

	// --- menú lateral: el desfasaje --------------------------------------
	await esperar('menú lateral', () => cdp.ev("!!document.querySelector('nav .pie')"));
	await dormir(800);
	await cdp.captura('03-vault');
	const m = await cdp.ev(`(() => {
		const nav=document.querySelector('nav'); const pie=document.querySelector('nav .pie');
		const titulo=document.querySelector('header.titlebar');
		const r=(e)=>e?e.getBoundingClientRect():null;
		return { alto:innerHeight, scrollAlto:document.documentElement.scrollHeight, hayScroll:document.documentElement.scrollHeight>innerHeight+1,
		  tituloH:titulo?titulo.getBoundingClientRect().height:null, varTitulo:getComputedStyle(document.documentElement).getPropertyValue('--titlebar-h').trim(),
		  navTop:r(nav)?.top, navBottom:r(nav)?.bottom, pieBottom:r(pie)?.bottom };
	})()`);
	console.log('   medidas:', JSON.stringify(m));
	paso('la barra de título publica su altura en --titlebar-h', m.varTitulo === '36px', `--titlebar-h=${m.varTitulo}`);
	paso('el documento no desborda la ventana (sin scroll extra de 36 px)', !m.hayScroll, `scrollHeight=${m.scrollAlto} innerHeight=${m.alto}`);
	paso('el pie del menú ("Cerrar sesión") queda dentro de la ventana', m.pieBottom <= m.alto + 0.5, `pie.bottom=${m.pieBottom} alto=${m.alto}`);

	// La barra de título es lo único de donde se arrastra la ventana: tiene que
	// seguir ahí al bajar por una página larga (antes era `sticky` dentro del
	// `body` y se iba con el contenido). Se fuerza una página larga con un bloque alto.
	const barra = await cdp.ev(`(() => {
		const relleno = document.createElement('div');
		relleno.style.height = '4000px';
		document.body.appendChild(relleno);
		window.scrollTo(0, 3000);
		const r = document.querySelector('header.titlebar').getBoundingClientRect();
		const bajo = document.elementFromPoint(300, 10)?.closest('header.titlebar') !== null;
		const y = window.scrollY;
		relleno.remove();
		window.scrollTo(0, 0);
		return { scrollY: y, top: r.top, bottom: r.bottom, arrastrable: bajo };
	})()`);
	paso('la barra de título queda fija al bajar por una página larga (se puede mover la ventana)', barra.scrollY > 0 && barra.top === 0 && barra.arrastrable, JSON.stringify(barra));

	// --- salud de la bóveda (F-57) ---------------------------------------
	// Se crean 3 recursos por la interfaz real: uno débil y dos con la MISMA
	// contraseña larga. El análisis tiene que marcar el débil y ambos repetidos.
	const CLAVE_REPETIDA = 'Cuchara-Nube-Faro-77!zqRt';
	async function crearRecurso(nombre, password) {
		await cdp.ev(clickTexto('Nuevo recurso'));
		await esperar(`formulario para ${nombre}`, () => cdp.ev("!!document.querySelector('form input[type=password]')"));
		await cdp.ev(llenarEtiqueta('Nombre', nombre));
		await cdp.ev(llenarEtiqueta('Contraseña', password));
		await cdp.ev("document.querySelector('form input[type=password]').form.requestSubmit()");
		await esperar(`${nombre} en la lista`, () => cdp.ev(`document.body.innerText.includes(${JSON.stringify(nombre)}) && !document.querySelector('form input[type=password]')`), 60000);
	}
	await crearRecurso('Sitio A', '1234');
	await crearRecurso('Sitio B', CLAVE_REPETIDA);
	await crearRecurso('Sitio C', CLAVE_REPETIDA);
	paso('se crean 3 recursos por la interfaz real', true);

	await cdp.ev("document.querySelector('a[href=\"/health\"]')?.click()");
	await esperar('página de salud', async () => (await url()).startsWith('/health'));
	paso('el menú tiene "Salud" y lleva a la pantalla', true);
	await cdp.ev(clickTexto('Analizar mi bóveda'));
	await esperar('informe de salud', () => cdp.ev("document.body.innerText.includes('Se analizaron')"), 90000);
	await dormir(400);
	await cdp.captura('04a-salud');
	const salud = await cdp.ev(`({
		texto: document.body.innerText,
		debiles: [...document.querySelectorAll('#salud-debiles > li')].map(li => li.innerText),
		repetidas: [...document.querySelectorAll('#salud-repetidas li li')].map(li => li.innerText),
		sinPedidosExternos: !performance.getEntriesByType('resource').some(e => e.name.includes('pwnedpasswords'))
	})`);
	paso('el análisis cuenta las 3 contraseñas', /Se analizaron 3 contraseñas/.test(salud.texto), '');
	paso('marca como débil sólo la contraseña "1234"', salud.debiles.length === 1 && salud.debiles[0].includes('Sitio A'), JSON.stringify(salud.debiles));
	paso('marca como repetidos a AMBOS recursos con la misma contraseña', salud.repetidas.length === 2 && salud.repetidas.some((t) => t.includes('Sitio B')) && salud.repetidas.some((t) => t.includes('Sitio C')), JSON.stringify(salud.repetidas));
	paso('con la comprobación de filtraciones apagada no se hace ningún pedido a un servicio externo', salud.sinPedidosExternos);
	paso('sin umbral configurado no se marca ninguna contraseña como vieja', /Elegí un plazo arriba/.test(salud.texto));
	await cdp.ev("document.querySelector('#salud-debiles a').click()");
	await esperar('editar lleva al recurso', async () => (await url()) === '/vault' && (await cdp.ev(`[...document.querySelectorAll('button')].some(b => b.textContent.includes('Ver secreto'))`)), 30000);
	paso('"Editar" en un hallazgo abre ese recurso en la bóveda (y limpia el parámetro)', true);

	// --- ajustes / escritorio / extensión --------------------------------
	await cdp.ev("document.querySelector('a[href=\"/settings/profile\"]')?.click()");
	await esperar('ajustes', async () => (await url()).startsWith('/settings'));
	await cdp.ev("document.querySelector('a[href=\"/settings/desktop\"]')?.click()");
	await esperar('página Escritorio', async () => (await url()).startsWith('/settings/desktop'));
	await esperar('tarjeta de la extensión', () => cdp.ev("document.body.innerText.includes('Extensión de navegador')"));
	await dormir(1200);
	await cdp.captura('04-ajustes-escritorio');
	const texto = await cdp.ev('document.body.innerText');
	const estadoExt = await cdp.ev("window.__TAURI_INTERNALS__.invoke('extension_estado')");
	const detectados = estadoExt.navegadores.filter((n) => n.instalado).map((n) => n.id);
	console.log('   detectados por la app:', detectados.join(', ') || '(ninguno)');
	paso('la app detecta exactamente los 3 navegadores falsos', JSON.stringify(detectados) === JSON.stringify(['chrome', 'edge', 'firefox']), detectados.join(','));
	paso('la pantalla ofrece sólo los detectados', ['Google Chrome', 'Microsoft Edge', 'Mozilla Firefox'].every((n) => texto.includes(n)) && !texto.includes('Opera') && !texto.includes('Brave'));
	paso('cada navegador ofrece un botón "Instalar en …"', texto.includes('Instalar en Google Chrome'));
	await cdp.ev(clickTexto('Instalar en Google Chrome'));
	await esperar('guía de instalación', () => cdp.ev("document.body.innerText.includes('Modo de desarrollador')"), 20000);
	await dormir(500);
	await cdp.captura('05-extension-guia');
	const guia = await cdp.ev('document.body.innerText');
	const carpeta = path.join(perfil, 'Documentos', 'Ellkan extensión');
	// La app extrae a Documentos (donde el diálogo del navegador abre por defecto);
	// acá `ELLKAN_EXTENSION_DIR` la redirige al perfil temporal.
	paso('la guía nombra la carpeta "Ellkan extensión" y muestra su ruta', guia.includes('Ellkan extensión') && guia.includes(carpeta), carpeta);
	paso('la extensión quedó extraída con su manifest', existsSync(path.join(carpeta, 'manifest.json')), carpeta);
	// El puerto del backend lo elige la app: la extensión tiene que traerlo
	// puesto, el usuario no tiene cómo saberlo.
	const puertoApp = await cdp.ev("window.__TAURI_INTERNALS__.invoke('puerto_backend')");
	const direccionApp = `http://127.0.0.1:${puertoApp}`;
	const conexionRuta = path.join(carpeta, 'ellkan-escritorio.json');
	const direccionEscrita = existsSync(conexionRuta) ? JSON.parse(readFileSync(conexionRuta, 'utf8')).server_url : undefined;
	paso('la extensión queda con la dirección de la app ya escrita', direccionEscrita === direccionApp, `${direccionEscrita} (esperada ${direccionApp})`);
	paso('la guía le dice al usuario que la dirección ya viene puesta', guia.includes(direccionApp));
	const popupHtml = readFileSync(path.join(carpeta, 'popup', 'index.html'), 'utf8');
	paso('el popup de la extensión trae el aviso de "Ellkan de escritorio detectado"', popupHtml.includes('hint-servidor-escritorio'));

	// --- preferencia "al cerrar la ventana" --------------------------------
	const cfgRuta = path.join(perfil, 'appdata', 'Ellkan', 'config.json');
	const alCerrarGuardado = () => (existsSync(cfgRuta) ? JSON.parse(readFileSync(cfgRuta, 'utf8')).al_cerrar : undefined);
	await cdp.ev("document.querySelector('input[name=\"al-cerrar\"][value=\"bandeja\"]').click()");
	await esperar('preferencia "bandeja" guardada', () => alCerrarGuardado() === 'bandeja');
	paso('elegir "minimizar a la bandeja" en Ajustes se guarda', true);
	await cdp.ev("document.querySelector('input[name=\"al-cerrar\"][value=\"preguntar\"]').click()");
	await esperar('preferencia "preguntar" guardada', () => alCerrarGuardado() === 'preguntar');
	paso('volver a "preguntarme cada vez" se guarda', true);

	// --- inicio con la sesión, enlaces ellkan://, bloqueo con la pantalla ------
	const reg = (...args) => spawnSync('reg', args, { encoding: 'utf8', windowsHide: true });
	const claveRun = `HKCU\\${RAMA_REGISTRO}\\Microsoft\\Windows\\CurrentVersion\\Run`;
	const claveEnlace = `HKCU\\${RAMA_REGISTRO}\\Classes\\ellkan\\shell\\open\\command`;
	const marcada = (id) => cdp.ev(`document.querySelector('${id}')?.checked`);

	await esperar('tarjeta "Inicio y sistema"', () => cdp.ev("!!document.querySelector('#opcion-autostart')"));

	await cdp.ev("document.querySelector('#opcion-autostart').click()");
	await esperar('clave de inicio escrita', () => reg('query', claveRun, '/v', 'Ellkan').status === 0);
	const valorRun = reg('query', claveRun, '/v', 'Ellkan').stdout;
	paso('activar "abrir al iniciar sesión" escribe la clave con este .exe y --minimizado', valorRun.toLowerCase().includes(exe.toLowerCase()) && valorRun.includes('--minimizado'), valorRun.trim().split('\n').pop().trim());
	await esperar('casilla marcada tras releer', () => marcada('#opcion-autostart'));
	paso('la casilla de inicio queda marcada (el estado se lee del registro, no de un flag)', true);
	await cdp.ev("document.querySelector('#opcion-autostart').click()");
	await esperar('clave de inicio borrada', () => reg('query', claveRun, '/v', 'Ellkan').status !== 0);
	paso('desactivarlo borra la clave', true);

	await cdp.ev("document.querySelector('#opcion-enlaces').click()");
	await esperar('esquema ellkan:// registrado', () => reg('query', claveEnlace, '/ve').status === 0);
	const valorEnlace = reg('query', claveEnlace, '/ve').stdout;
	paso('activar los enlaces registra ellkan:// apuntando a este .exe con "%1"', valorEnlace.toLowerCase().includes(exe.toLowerCase()) && valorEnlace.includes('%1'), valorEnlace.trim().split('\n').pop().trim());

	// Lo que corre el desinstalador (MSI): deshace inicio con Windows y ellkan:// sin abrir la app.
	await cdp.ev("document.querySelector('#opcion-autostart').click()");
	await esperar('inicio con Windows activado de nuevo', () => reg('query', claveRun, '/v', 'Ellkan').status === 0);
	const limpieza = spawnSync(exe, ['--limpiar-sistema'], { env: entorno, timeout: 20000, windowsHide: true });
	paso('--limpiar-sistema (lo que corre el desinstalador) termina bien y sin abrir la app', limpieza.status === 0, `código ${limpieza.status}`);
	paso('y deja sin rastro el inicio con Windows y ellkan://', reg('query', claveRun, '/v', 'Ellkan').status !== 0 && reg('query', claveEnlace, '/ve').status !== 0);
	paso('la app abierta sigue viva tras esa limpieza (es otro proceso)', app.exitCode === null);
	paso('bloquear con la pantalla viene activado por defecto', (await marcada('#opcion-bloqueo-pantalla')) === true);
	await cdp.ev("document.querySelector('#opcion-bloqueo-pantalla').click()");
	await esperar('bloqueo con pantalla desactivado en la config', () => JSON.parse(readFileSync(cfgRuta, 'utf8')).bloquear_con_pantalla === false);
	await cdp.ev("document.querySelector('#opcion-bloqueo-pantalla').click()");
	await esperar('bloqueo con pantalla activado en la config', () => JSON.parse(readFileSync(cfgRuta, 'utf8')).bloquear_con_pantalla === true);
	paso('cambiar "bloquear con la pantalla" se guarda', true);
	await cdp.captura('04b-ajustes-sistema');

	// --- copias de seguridad ------------------------------------------------
	const carpetaCopias = path.join(perfil, 'appdata', 'Ellkan', 'backups');
	const copias = () => (existsSync(carpetaCopias) ? readdirSync(carpetaCopias).filter((n) => n.startsWith('ellkan-manual-')) : []);
	await esperar('tarjeta de copias de seguridad', () => cdp.ev("document.body.innerText.includes('Copias de seguridad')"));
	paso('todavía no hay copias', copias().length === 0);
	await cdp.ev(clickTexto('Crear copia ahora'));
	await esperar('copia creada', () => copias().length === 1, 30000);
	await esperar('la pantalla confirma la copia', () => cdp.ev("document.body.innerText.includes('Copia creada')"));
	paso('"Crear copia ahora" guarda una copia de la bóveda en la carpeta de copias', true, copias()[0]);
	const tamano = readFileSync(path.join(carpetaCopias, copias()[0])).length;
	paso('la copia es una base SQLite completa (no un archivo vacío)', tamano > 4096, `${tamano} bytes`);
	paso('la copia arranca con la cabecera de SQLite', readFileSync(path.join(carpetaCopias, copias()[0])).subarray(0, 15).toString('latin1') === 'SQLite format 3');

	// --- el backend local sólo atiende a quien debe -------------------------
	const pedir = (headers = {}) =>
		new Promise((resolver) => {
			const r = http.request({ host: '127.0.0.1', port: puertoApp, path: '/auth/existe-usuario', method: 'GET', headers }, (resp) => {
				resp.resume();
				resolver({ status: resp.statusCode, acao: resp.headers['access-control-allow-origin'] });
			});
			r.on('error', (e) => resolver({ error: e.message }));
			r.end();
		});
	const sinOrigen = await pedir();
	paso('sin Origin (un cliente que no es un navegador) se atiende', sinOrigen.status === 200, JSON.stringify(sinOrigen));
	const deLaApp = await pedir({ Origin: 'http://tauri.localhost' });
	paso('la propia app (Origin de WebView2) se atiende y recibe su CORS', deLaApp.status === 200 && deLaApp.acao === 'http://tauri.localhost', JSON.stringify(deLaApp));
	const deExtension = await pedir({ Origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop' });
	paso('una extensión de navegador se atiende', deExtension.status === 200, JSON.stringify(deExtension));
	const deWebAjena = await pedir({ Origin: 'https://evil.example' });
	paso('una página web cualquiera recibe 403 y ningún CORS', deWebAjena.status === 403 && !deWebAjena.acao, JSON.stringify(deWebAjena));
	const rebinding = await pedir({ Host: 'evil.example' });
	paso('un Host que no es loopback (DNS rebinding) recibe 403', rebinding.status === 403, JSON.stringify(rebinding));

	// --- enlaces ellkan://: llegan a la instancia abierta -------------------
	const urlAntes = await url();
	spawnSync(exe, ['ellkan://item/../../etc/passwd'], { env: entorno, timeout: 20000 });
	await dormir(1500);
	paso('un enlace malformado no navega a ningún lado', (await url()) === urlAntes, await url());
	spawnSync(exe, ['ellkan://abrir'], { env: entorno, timeout: 20000 });
	await esperar('el enlace ellkan://abrir navega a la bóveda', async () => (await url()).startsWith('/vault'), 20000);
	paso('un enlace ellkan://abrir llega a la instancia ya abierta y lleva a la bóveda', true, await url());
	spawnSync(exe, ['ellkan://item/01a0a85d-3be1-70f1-b692-e270dd61fcf3'], { env: entorno, timeout: 20000 });
	await dormir(2500);
	paso('un enlace a un recurso que no existe deja la bóveda limpia (sin el parámetro)', (await url()) === '/vault', await url());

	// --- bloquear la bóveda cuando Windows bloquea la pantalla ---------------
	// Bloquear la pantalla de verdad sacaría al usuario de su sesión: se simula el
	// mismo aviso (WM_WTSSESSION_CHANGE / WTS_SESSION_LOCK) que manda Windows.
	const overlay = "!!document.querySelector('[role=alertdialog]')";
	paso('con la bóveda abierta no hay pantalla de bloqueo', !(await cdp.ev(overlay)));
	await cdp.ev("window.__TAURI_INTERNALS__.invoke('simular_bloqueo_de_pantalla')");
	await esperar('pantalla de bloqueo', () => cdp.ev(overlay), 10000);
	paso('cuando Windows bloquea la pantalla, la bóveda se bloquea sola', true);
	await cdp.captura('04c-bloqueada-por-pantalla');
	await cdp.ev(`(() => { const el=document.querySelector('[role=alertdialog] input[type=password]'); if(!el) return false;
		Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, ${JSON.stringify(PASS1)});
		el.dispatchEvent(new Event('input',{bubbles:true})); el.form.requestSubmit(); return true; })()`);
	await esperar('desbloqueo con la contraseña', async () => !(await cdp.ev(overlay)), 60000);
	paso('y se desbloquea con la contraseña, sin perder la sesión', true);

	// Con la opción apagada, bloquear la pantalla no toca la bóveda.
	await cdp.ev("window.__TAURI_INTERNALS__.invoke('configurar_bloqueo_pantalla', { activo: false })");
	await cdp.ev("window.__TAURI_INTERNALS__.invoke('simular_bloqueo_de_pantalla')");
	await dormir(1500);
	paso('con "bloquear con la pantalla" apagado, la bóveda no se bloquea', !(await cdp.ev(overlay)));
	await cdp.ev("window.__TAURI_INTERNALS__.invoke('configurar_bloqueo_pantalla', { activo: true })");

	await cdp.ev(clickTexto('Cerrar sesión'));
	await esperar('vuelta al login', async () => (await url()).startsWith('/login'), 20000);

	// --- recuperación sin correo ------------------------------------------
	await cdp.ev("location.assign('/recover')");
	await esperar('pantalla de recuperación', () => cdp.ev("document.querySelectorAll('form input').length >= 1"));
	await cdp.captura('06-recover');
	await cdp.ev(llenar('form input', 0, EMAIL));
	await cdp.ev(enviarFormulario);
	await esperar('paso del kit (sin correo ni link)', () => cdp.ev("document.querySelectorAll('form input').length >= 3"), 20000);
	await cdp.ev(llenar('form input', 0, kit));
	await cdp.ev(llenar('form input', 1, PASS2));
	await cdp.ev(llenar('form input', 2, PASS2));
	await cdp.ev(enviarFormulario);
	await esperar('recuperación completada', () => cdp.ev("document.body.innerText.includes('ya podés iniciar sesión') || document.body.innerText.includes('Listo')"), 90000);
	await cdp.captura('07-recover-listo');
	paso('recuperar con el kit funciona SIN correo (firma del challenge)', true);

	// --- la contraseña nueva abre la bóveda --------------------------------
	await cdp.ev("location.assign('/login')");
	await esperar('login', () => cdp.ev("document.querySelectorAll('form input').length >= 2"));
	await cdp.ev(llenar('form input', 0, EMAIL));
	await cdp.ev(llenar('form input', 1, PASS2));
	await cdp.ev(enviarFormulario);
	const destino = await esperar('entrar con la contraseña nueva', async () => {
		const u = await url();
		return u.startsWith('/onboarding/recovery-kit') || u.startsWith('/vault') ? u : false;
	}, 120000);
	paso('la contraseña nueva abre la bóveda', true, destino);
	paso('tras recuperar, el gate obliga a generar un kit nuevo', destino.startsWith('/onboarding/recovery-kit'), destino);
	await cdp.captura('08-tras-recuperar');

	// --- cerrar la ventana: ya no se esconde sola en la bandeja -------------
	const cerrarVentana = "window.__TAURI_INTERNALS__.invoke('plugin:window|close', { label: 'main' })";
	const dialogoAbierto = () => cdp.ev("document.body.innerText.includes('¿Cerrar Ellkan?')");
	await cdp.ev(cerrarVentana);
	await esperar('diálogo al cerrar la ventana', dialogoAbierto, 15000);
	await dormir(700); // que termine la animación de aparición antes de capturar
	await cdp.captura('09-dialogo-cierre');
	paso('cerrar la ventana pregunta qué hacer (antes se escondía sola en la bandeja)', true);
	await cdp.ev(clickTexto('Cancelar'));
	await esperar('el diálogo se cierra', async () => !(await dialogoAbierto()));
	paso('cancelar deja la app abierta', app.exitCode === null);

	// "Dejar en la bandeja": la ventana se esconde y una ventanita AVISA que la
	// app sigue corriendo (sin eso el usuario creía haberla cerrado).
	const paginas = async () => (await (await fetch(`http://127.0.0.1:${PUERTO}/json`)).json()).filter((t) => t.type === 'page' && !t.url.startsWith('devtools'));
	const buscarAviso = async () => (await paginas()).find((t) => t.url.includes('aviso.html'));
	await cdp.ev(cerrarVentana);
	await esperar('diálogo al cerrar (bandeja)', dialogoAbierto, 15000);
	await cdp.ev(clickTexto('Dejar en la bandeja'));
	const aviso = await esperar('aviso de la bandeja', buscarAviso, 15000);
	paso('al dejar la app en la bandeja aparece una ventanita de aviso', true, aviso.url);
	const wsAviso = new WebSocket(aviso.webSocketDebuggerUrl);
	await new Promise((r, j) => ((wsAviso.onopen = r), (wsAviso.onerror = j)));
	const cdpAviso = new Cdp(wsAviso);
	await cdpAviso.send('Page.enable');
	const textoAviso = await esperar('texto del aviso', () => cdpAviso.ev('document.body.innerText.trim()'), 10000);
	await dormir(400);
	await cdpAviso.captura('10-aviso-bandeja');
	paso('el aviso dice que Ellkan sigue abierto y dónde está', /sigue abierto/.test(textoAviso) && /bandeja/.test(textoAviso), textoAviso.replace(/\s+/g, ' '));
	paso('la app sigue corriendo tras dejarla en la bandeja', app.exitCode === null);
	await cdpAviso.ev("document.body.click()");
	await esperar('el aviso se descarta al tocarlo', async () => !(await buscarAviso()), 10000);
	paso('tocar el aviso lo descarta', true);
	wsAviso.close();

	// Abrir el .exe otra vez (la app es de instancia única) trae de vuelta la
	// ventana escondida — es lo que hace el usuario cuando ve el aviso.
	spawnSync(exe, [], { env: entorno, timeout: 20000 });
	await dormir(1500);

	await cdp.ev(cerrarVentana);
	await esperar('diálogo al cerrar (2ª vez)', dialogoAbierto, 15000);
	await cdp.ev("document.querySelector('label.recordar input').click()");
	await cdp.ev(clickTexto('Cerrar Ellkan'));
	await esperar('la aplicación termina', () => app.exitCode !== null, 15000);
	paso('"Cerrar Ellkan" cierra la aplicación de verdad (el proceso termina)', true, `código de salida ${app.exitCode}`);
	paso('"Recordar mi elección" quedó guardada', alCerrarGuardado() === 'salir', String(alCerrarGuardado()));

	await escenarioPortable();
	await escenarioBorrarDatos();
}

// Segundo recorrido, con la primera app ya cerrada: modo portable + arranque
// minimizado + puerto fijo ocupado. Corre una COPIA del .exe en una carpeta
// temporal, así los datos "junto al ejecutable" quedan en el perfil de prueba.
async function escenarioPortable() {
	const carpeta = path.join(perfil, 'portable');
	const datos = path.join(carpeta, 'ellkan-datos');
	mkdirSync(datos, { recursive: true });
	const copia = path.join(carpeta, 'ellkan-desktop.exe');
	copyFileSync(exe, copia);

	// Un puerto "fijo" que ya está ocupado: la app tiene que usar otro y avisarlo.
	const ocupante = net.createServer();
	await new Promise((r) => ocupante.listen(0, '127.0.0.1', r));
	const puertoOcupado = ocupante.address().port;
	writeFileSync(path.join(datos, 'config.json'), JSON.stringify({ puerto_fijo: puertoOcupado }));

	const appdataAjeno = path.join(perfil, 'appdata-portable');
	mkdirSync(appdataAjeno, { recursive: true });
	const entorno = {
		...process.env,
		APPDATA: appdataAjeno,
		LOCALAPPDATA: path.join(perfil, 'local-portable'),
		ELLKAN_REGISTRO_RAIZ: RAMA_REGISTRO,
		WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PUERTO + 1}`
	};
	delete entorno.ELLKAN_CONFIG_DIR;
	delete entorno.ELLKAN_EXTENSION_DIR;

	const portable = spawn(copia, ['--portable', '--minimizado'], { env: entorno, stdio: 'ignore' });
	try {
		await esperar('base de datos portable', () => existsSync(path.join(datos, 'ellkan.db')), 60000);
		paso('en modo portable la bóveda queda junto al ejecutable', true, datos);
		paso('en modo portable no se escribe nada en %APPDATA%', !existsSync(path.join(appdataAjeno, 'Ellkan')));
		await esperar('desktop.json portable', () => existsSync(path.join(datos, 'config', 'desktop.json')), 30000);
		paso('desktop.json (puerto/token) también queda en la carpeta portable, no en ~/.ellkan', true);

		const paginas = async () => (await (await fetch(`http://127.0.0.1:${PUERTO + 1}/json`)).json()).filter((t) => t.type === 'page' && !t.url.startsWith('devtools'));
		const aviso = await esperar('aviso de puerto ocupado', async () => (await paginas()).find((t) => t.url.includes('aviso.html')), 60000);
		const wsAviso = new WebSocket(aviso.webSocketDebuggerUrl);
		await new Promise((r, j) => ((wsAviso.onopen = r), (wsAviso.onerror = j)));
		const cdpAviso = new Cdp(wsAviso);
		await cdpAviso.send('Page.enable');
		const textoAviso = await esperar('texto del aviso de puerto', async () => {
			const t = await cdpAviso.ev('document.body.innerText.trim()');
			return t.length > 10 ? t : false;
		}, 10000);
		await dormir(300);
		await cdpAviso.captura('11-aviso-puerto');
		paso('si el puerto fijo está ocupado, un aviso lo dice (no falla en silencio)', textoAviso.includes(String(puertoOcupado)) && /ocupado/.test(textoAviso), textoAviso.replace(/\s+/g, ' '));
		wsAviso.close();

		const principal = (await paginas()).find((t) => !t.url.includes('aviso.html'));
		const wsPrincipal = new WebSocket(principal.webSocketDebuggerUrl);
		await new Promise((r, j) => ((wsPrincipal.onopen = r), (wsPrincipal.onerror = j)));
		const cdpPrincipal = new Cdp(wsPrincipal);
		await cdpPrincipal.send('Page.enable');
		const sistema = await esperar('estado del sistema', () => cdpPrincipal.ev("window.__TAURI_INTERNALS__.invoke('sistema_estado')"), 20000);
		paso('la app sabe que corre en modo portable y dónde están sus datos', sistema.portable === true && sistema.carpeta_de_datos.toLowerCase() === datos.toLowerCase(), sistema.carpeta_de_datos);
		const puertoUsado = await cdpPrincipal.ev("window.__TAURI_INTERNALS__.invoke('puerto_backend')");
		paso('usa otro puerto sólo en esa sesión (y no toca el fijo guardado)', puertoUsado !== puertoOcupado && JSON.parse(readFileSync(path.join(datos, 'config.json'), 'utf8')).puerto_fijo === puertoOcupado, `usa ${puertoUsado}, fijo ${puertoOcupado}`);
		const visible = await cdpPrincipal.ev("window.__TAURI_INTERNALS__.invoke('plugin:window|is_visible', { label: 'main' })");
		paso('con --minimizado la ventana no se abre (sólo la bandeja)', visible === false, `is_visible=${visible}`);
		wsPrincipal.close();
	} finally {
		portable.kill();
		ocupante.close();
	}
}

// Lo que hace el desinstalador con los datos del usuario, sin instalar nada: se corre el
// mismo argumento que le pasa el MSI sobre un perfil de mentira con archivos de mentira.
async function escenarioBorrarDatos() {
	const base = path.join(perfil, 'borrado');
	const appdata = path.join(base, 'appdata');
	const local = path.join(base, 'local');
	const cfg = path.join(base, 'cfg');
	const datos = path.join(appdata, 'Ellkan');
	const webview = path.join(local, 'com.ellkan.desktop');
	const preparar = () => {
		mkdirSync(path.join(datos, 'backups'), { recursive: true });
		writeFileSync(path.join(datos, 'ellkan.db'), 'bóveda');
		writeFileSync(path.join(datos, 'backups', 'copia.db'), 'copia');
		mkdirSync(path.join(webview, 'EBWebView'), { recursive: true });
		writeFileSync(path.join(webview, 'EBWebView', 'x'), 'x');
		mkdirSync(cfg, { recursive: true });
		writeFileSync(path.join(cfg, 'desktop.json'), '{}');
		writeFileSync(path.join(cfg, 'perfil.json'), '{}'); // lo comparte la CLI: no se toca
	};
	const entorno = { ...process.env, APPDATA: appdata, LOCALAPPDATA: local, ELLKAN_CONFIG_DIR: cfg, ELLKAN_REGISTRO_RAIZ: RAMA_REGISTRO };

	preparar();
	const solo = spawnSync(exe, ['--limpiar-sistema'], { env: entorno, timeout: 30000, windowsHide: true });
	paso('desinstalar sin pedir borrar datos CONSERVA la bóveda, las copias y los ajustes', solo.status === 0 && existsSync(path.join(datos, 'ellkan.db')) && existsSync(path.join(datos, 'backups', 'copia.db')) && existsSync(path.join(webview, 'EBWebView', 'x')));

	const todo = spawnSync(exe, ['--limpiar-sistema', '--borrar-datos'], { env: entorno, timeout: 60000, windowsHide: true });
	paso('con --borrar-datos se va la carpeta de datos (bóveda y copias)', todo.status === 0 && !existsSync(datos), `código ${todo.status}`);
	paso('y también los datos de la ventana (idioma, tema, sesión)', !existsSync(webview));
	paso('y el desktop.json, pero NO lo demás de ~/.ellkan (lo comparte la CLI)', !existsSync(path.join(cfg, 'desktop.json')) && existsSync(path.join(cfg, 'perfil.json')));
	paso('la carpeta de arriba (AppData) no se toca', existsSync(appdata));
	rmSync(base, { recursive: true, force: true });
}

let codigo = 0;
try {
	await main();
} catch (e) {
	codigo = 1;
	paso('ejecución del recorrido', false, e.message);
	try {
		await cdp?.captura('99-error');
		console.log('   texto en pantalla:', (await cdp?.ev('document.body.innerText'))?.slice(0, 600));
	} catch {
		/* sin ventana */
	}
} finally {
	try {
		cdp?.ws.close();
	} catch {
		/* ya cerrada */
	}
	if (app?.pid) spawnSync('taskkill', ['/PID', String(app.pid), '/T', '/F'], { stdio: 'ignore' });
	await dormir(1000);
	for (const f of archivosABorrar) rmSync(f, { force: true });
	spawnSync('reg', ['delete', `HKCU\\${RAMA_REGISTRO}`, '/f'], { windowsHide: true });
	rmSync(perfil, { recursive: true, force: true });
	const fallas = resultados.filter((r) => !r.ok);
	console.log(`\n${resultados.length - fallas.length}/${resultados.length} pasos OK — capturas en ${capturas}`);
	process.exit(codigo || (fallas.length ? 1 : 0));
}
