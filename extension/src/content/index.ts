// Autor: Athan Espinoza

// Autofill — content script (spec 06 §4). Detecta formularios de login en la
// página, pide al service worker las credenciales que matchean la URL activa
// (el matching real corre en el background, ver `autofill-service.ts` —
// nunca se manda la bóveda al content script) y ofrece un menú inline al
// hacer foco en el campo de contraseña.
//
// Detección de campos "de primera clase" (spec 06 §4.1): el recorrido del
// DOM de acá arma descriptores livianos y la clasificación/emparejado es
// lógica pura en `field-detection.ts` (con self-checks propios). El relleno
// se expresa como un `ScriptAutofill` de acciones por `opid` (`autofill-
// script.ts`), que se resuelven contra el DOM en el momento de la acción —
// no antes — para tolerar un form que se re-renderiza entre la colección y
// el relleno.
//
// Divergencias deliberadas respecto al diseño completo de spec 06 §4.1
// (marcadas abajo, subir cuando el uso real lo pida):
//  - Traversa shadow DOM abierto, pero NO desciende a `<iframe>`: cada frame
//    tiene su propia inyección (`all_frames: true`), así que un iframe hijo
//    ya corre este mismo código sobre su propio documento — descender desde
//    el padre sería doble trabajo (y rompe en cross-origin).
//  - Sin `IntersectionObserver`: la visibilidad se resuelve con
//    `getBoundingClientRect` + `getComputedStyle` en el momento de la
//    colección. Alcanza para descartar honeypots (display/visibility/opacity/
//    tamaño ~0); no cubre un campo tapado por otro elemento.
//
// El `<style>` del menú se inserta como `<style>` inline dentro del shadow
// root cerrado — un sitio con CSP `style-src` sin `'unsafe-inline'` podría
// dejar el menú sin formato (los botones seguirían funcionando). El fix real
// es `chrome.scripting.insertCSS`; no se hizo por no sumar esa API/permiso
// sin un caso concreto.
//
// No verificado con clicks reales sobre una página (sin browser automation
// en este entorno) — mismo límite documentado para el resto de la Fase 2.

import { PortClient } from '../shared/port-client';
import type { CoincidenciaAutofill } from '../background/services/autofill-service';
import { mismoOrigenParaFill } from './origin-guard';
import { type CampoDetectado, type ParLogin, emparejarLogins, esCampoVisible } from './field-detection';
import { type ElementoObjetivo, ejecutarScript, scriptParaLogin } from './autofill-script';
import { decidirGuardado, type CredencialCapturada } from './save-prompt';
import { TOKENS } from '../design-tokens';

const cliente = new PortClient('WebIntegration');

// --- opid: identificador sintético y estable por elemento (spec 06 §4.1) —
// nunca se direcciona por `id`/`name` HTML real (puede faltar, repetirse o
// cambiar entre colección y relleno). ---
const opidPorElemento = new WeakMap<Element, string>();
const elementoPorOpid = new Map<string, WeakRef<Element>>();
let opidSeq = 0;

function opidDe(el: Element): string {
	let id = opidPorElemento.get(el);
	if (!id) {
		id = `ellkan-opid-${++opidSeq}`;
		opidPorElemento.set(el, id);
	}
	elementoPorOpid.set(id, new WeakRef(el));
	return id;
}

/** Resuelve un `opid` al elemento vivo, o `null` si ya no está conectado al
 * DOM (el script de relleno se salta esa acción sin romper el resto). */
function resolverOpid(opid: string): Element | null {
	const el = elementoPorOpid.get(opid)?.deref() ?? null;
	return el?.isConnected ? el : null;
}

// --- recorrido del DOM: documento + shadow roots abiertos (ver cabecera
// sobre iframes). ---
function* recorrerCampos(raiz: ParentNode): Generator<HTMLInputElement | HTMLSelectElement> {
	for (const el of raiz.querySelectorAll('input, select')) {
		yield el as HTMLInputElement | HTMLSelectElement;
	}
	for (const host of raiz.querySelectorAll('*')) {
		const sr = (host as Element).shadowRoot; // sólo 'open'; 'closed' es inalcanzable a propósito
		if (sr) yield* recorrerCampos(sr);
	}
}

function descriptorDe(el: HTMLInputElement | HTMLSelectElement, orden: number): CampoDetectado {
	const rect = el.getBoundingClientRect();
	const style = getComputedStyle(el);
	const form = el instanceof HTMLInputElement || el instanceof HTMLSelectElement ? el.form : null;
	return {
		opid: opidDe(el),
		type: (el instanceof HTMLInputElement ? el.type : el.tagName).toLowerCase(),
		autocomplete: (el.getAttribute('autocomplete') ?? '').toLowerCase().trim(),
		name: el.getAttribute('name') ?? '',
		id: el.id ?? '',
		placeholder: el.getAttribute('placeholder') ?? '',
		ariaLabel: el.getAttribute('aria-label') ?? '',
		visible: esCampoVisible(
			{ width: rect.width, height: rect.height },
			{ display: style.display, visibility: style.visibility, opacity: style.opacity }
		),
		formOpid: form ? opidDe(form) : null,
		ordenDom: orden
	};
}

// --- estado de detección ---
let paresPorPasswordOpid = new Map<string, ParLogin>();
/** Pares que están dentro de un `<form>` — para engancharse al `submit` y
 * ofrecer guardar la credencial. */
let paresPorFormOpid = new Map<string, ParLogin>();
const yaConFocusHandler = new WeakSet<Element>();

function redetectar(): void {
	// Poda de `opid`s cuyo elemento ya no existe — el `Map` de opids no es
	// débil en sus claves (strings), sólo en los valores.
	for (const [opid, ref] of elementoPorOpid) {
		if (!ref.deref()?.isConnected) elementoPorOpid.delete(opid);
	}

	const campos: CampoDetectado[] = [];
	let orden = 0;
	for (const el of recorrerCampos(document)) campos.push(descriptorDe(el, orden++));

	const pares = emparejarLogins(campos);
	paresPorPasswordOpid = new Map(pares.map((p) => [p.password, p]));
	paresPorFormOpid = new Map(pares.filter((p) => p.formOpid).map((p) => [p.formOpid as string, p]));

	for (const p of pares) {
		const el = resolverOpid(p.password);
		if (!(el instanceof HTMLInputElement) || yaConFocusHandler.has(el)) continue;
		yaConFocusHandler.add(el);
		el.addEventListener('focus', () => {
			const opid = opidPorElemento.get(el);
			const par = opid ? paresPorPasswordOpid.get(opid) : undefined;
			if (par) void ofrecerAutofill(par);
		});
	}
}

// --- relleno vía setter nativo del prototipo (compatible con React y
// similares, que interceptan `.value =` directo). ---
function escribirValor(input: HTMLInputElement, valor: string): void {
	const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
	if (setter) setter.call(input, valor);
	else input.value = valor;
	input.dispatchEvent(new Event('input', { bubbles: true }));
	input.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Adaptador `opid` → objetivo del intérprete de `ScriptAutofill`. */
function objetivoDeOpid(opid: string): ElementoObjetivo | null {
	const el = resolverOpid(opid);
	if (!(el instanceof HTMLInputElement)) return null;
	return {
		focus: () => el.focus(),
		click: () => el.click(),
		rellenar: (valor: string) => escribirValor(el, valor)
	};
}

interface MenuAbierto {
	host: HTMLDivElement;
	passwordField: HTMLInputElement;
	/** `window.location.origin` cuando se pidieron las coincidencias — se
	 * revalida antes de rellenar (BWN-08-011, `origin-guard.ts`). */
	origenEnQuePidio: string;
}
let menuActual: MenuAbierto | null = null;

function cerrarMenu(): void {
	if (!menuActual) return;
	menuActual.host.remove();
	menuActual = null;
}

async function rellenar(coincidencia: CoincidenciaAutofill, par: ParLogin, origenEnQuePidio: string): Promise<void> {
	cerrarMenu();

	// Revalidación de origen en el momento exacto del fill (spec 06 §4.3.1,
	// BWN-08-011) — compara origen completo (esquema+host+puerto) y falla
	// cerrado.
	if (!mismoOrigenParaFill(origenEnQuePidio, window.location.href)) return;

	// Downgrade HTTPS→HTTP (spec 06 §4.3, punto 2): recurso guardado como
	// https:// pero página activa http:// — confirmación explícita. Una URI
	// sin esquema se asume https:// (mismo criterio que `conexion.ts`).
	const esHttpGuardado = /^http:\/\//i.test(coincidencia.uri);
	if (!esHttpGuardado && window.location.protocol === 'http:') {
		const continuar = window.confirm(
			`"${coincidencia.nombre}" se guardó para un sitio HTTPS, pero esta página es HTTP (sin cifrar). ¿Completar igual?`
		);
		if (!continuar) return;
	}

	try {
		const secreto = await cliente.request<{ password: string; totpSecret?: string }>('VAULT_REVELAR_SECRETO', {
			resourceId: coincidencia.id
		});
		const script = scriptParaLogin({
			usuario: par.usuario,
			password: par.password,
			totp: par.totp,
			valores: { usuario: coincidencia.usuario, password: secreto.password, totp: secreto.totpSecret }
		});
		ejecutarScript(script, objetivoDeOpid);
	} catch {
		// Sin sesión activa o recurso inexistente — el menú ya se cerró, no
		// hay UI de error acá.
	}
}

// Paleta de la UI inyectada — tokens compartidos con el frontend web
// (`extension/src/design-tokens.ts`, F-30). `fondo` acá = la superficie
// "tarjeta" (un escalón por encima del fondo base).
const PALETA = {
	fondo: TOKENS.fondoTarjeta,
	borde: TOKENS.borde,
	texto: TOKENS.texto,
	textoSecundario: TOKENS.textoSecundario
};

function crearMenu(
	passwordField: HTMLInputElement,
	par: ParLogin,
	coincidencias: CoincidenciaAutofill[],
	origenEnQuePidio: string
): void {
	cerrarMenu();

	const host = document.createElement('div');
	const rect = passwordField.getBoundingClientRect();
	host.style.position = 'absolute';
	host.style.left = `${rect.left + window.scrollX}px`;
	host.style.top = `${rect.bottom + window.scrollY + 4}px`;
	host.style.width = `${Math.max(rect.width, 220)}px`;
	host.style.zIndex = '2147483647';
	document.documentElement.appendChild(host);

	// Shadow root cerrado: ni el JS de la página con acceso a `host` puede
	// leer `host.shadowRoot` (`null` en modo closed) — aísla la UI y las
	// credenciales que pasan por ella del DOM/JS anfitrión.
	const shadow = host.attachShadow({ mode: 'closed' });

	const estilo = document.createElement('style');
	estilo.textContent = `
		:host { all: initial; }
		.menu { font-family: system-ui, -apple-system, sans-serif; font-size: 13px; background: ${PALETA.fondo}; border: 1px solid ${PALETA.borde}; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.35); overflow: hidden; }
		.item { display: block; width: 100%; box-sizing: border-box; text-align: left; padding: 8px 10px; background: transparent; border: none; border-bottom: 1px solid ${PALETA.borde}; color: ${PALETA.texto}; cursor: pointer; }
		.item:last-child { border-bottom: none; }
		.item:hover { background: ${PALETA.borde}; }
		.nombre { font-weight: 600; }
		.usuario { color: ${PALETA.textoSecundario}; margin-top: 2px; }
	`;
	shadow.appendChild(estilo);

	const menu = document.createElement('div');
	menu.className = 'menu';
	for (const c of coincidencias) {
		const item = document.createElement('button');
		item.type = 'button';
		item.className = 'item';
		const nombre = document.createElement('div');
		nombre.className = 'nombre';
		nombre.textContent = c.nombre || '(sin nombre)';
		const usuario = document.createElement('div');
		usuario.className = 'usuario';
		usuario.textContent = c.usuario;
		item.append(nombre, usuario);
		// `mousedown` + `preventDefault()`: dispara ANTES del `blur` del
		// password field, para no perder el foco (y con eso quizá el menú)
		// antes de leer la elección.
		item.addEventListener('mousedown', (evento) => {
			evento.preventDefault();
			void rellenar(c, par, origenEnQuePidio);
		});
		menu.appendChild(item);
	}
	shadow.appendChild(menu);

	menuActual = { host, passwordField, origenEnQuePidio };
}

// --- Notification bar "¿guardar esta credencial?" (spec 06 §5) — mismo
// aislamiento que el menú (shadow root cerrado, sin iframe, anti-BWN-08-019).
// La decisión de si ofrecer es pura (`save-prompt.ts`); acá sólo el DOM. ---
let barraGuardado: HTMLDivElement | null = null;

function cerrarBarraGuardado(): void {
	barraGuardado?.remove();
	barraGuardado = null;
}

function crearBarraGuardado(cap: CredencialCapturada): void {
	cerrarBarraGuardado();
	const host = document.createElement('div');
	host.style.position = 'fixed';
	host.style.top = '0';
	host.style.left = '0';
	host.style.right = '0';
	host.style.zIndex = '2147483647';
	document.documentElement.appendChild(host);
	const shadow = host.attachShadow({ mode: 'closed' });

	const estilo = document.createElement('style');
	estilo.textContent = `
		:host { all: initial; }
		.barra { font-family: system-ui, -apple-system, sans-serif; font-size: 13px; display: flex; align-items: center; gap: 12px; padding: 10px 14px; background: ${PALETA.fondo}; color: ${PALETA.texto}; border-bottom: 1px solid ${PALETA.borde}; box-shadow: 0 4px 16px rgba(0,0,0,0.3); }
		.texto { flex: 1; }
		button { font: inherit; padding: 6px 12px; border-radius: 6px; border: 1px solid ${PALETA.borde}; cursor: pointer; }
		.guardar { background: ${PALETA.textoSecundario}; color: ${PALETA.fondo}; font-weight: 600; border-color: transparent; }
		.descartar { background: transparent; color: ${PALETA.textoSecundario}; }
	`;
	shadow.appendChild(estilo);

	const barra = document.createElement('div');
	barra.className = 'barra';
	const texto = document.createElement('span');
	texto.className = 'texto';
	texto.textContent = `¿Guardar la contraseña de "${window.location.hostname}" en Ellkan?`;
	const guardar = document.createElement('button');
	guardar.className = 'guardar';
	guardar.type = 'button';
	guardar.textContent = 'Guardar';
	const descartar = document.createElement('button');
	descartar.className = 'descartar';
	descartar.type = 'button';
	descartar.textContent = 'Ahora no';

	guardar.addEventListener('click', () => {
		void cliente
			.request('VAULT_CREAR', {
				datos: {
					tipo: 'login-password',
					nombre: window.location.hostname,
					usuario: cap.usuario,
					uri: window.location.origin,
					password: cap.password,
					notas: ''
				}
			})
			.catch(() => {
				// Sin sesión activa u otro error — no hay UI de error acá, se
				// cierra igual (el usuario puede guardarla desde el popup).
			});
		cerrarBarraGuardado();
	});
	descartar.addEventListener('click', cerrarBarraGuardado);

	barra.append(texto, guardar, descartar);
	shadow.appendChild(barra);
	barraGuardado = host;
}

async function ofrecerGuardado(cap: CredencialCapturada): Promise<void> {
	if (!cap.password) return;
	try {
		const coincidencias = await cliente.request<CoincidenciaAutofill[]>('AUTOFILL_BUSCAR', {
			href: window.location.href
		});
		const decision = decidirGuardado(cap, coincidencias.map((c) => ({ usuario: c.usuario })));
		if (decision.ofrecer) crearBarraGuardado(cap);
	} catch {
		// Sin sesión activa → no se ofrece guardar (no tendríamos con qué crear).
	}
}

async function ofrecerAutofill(par: ParLogin): Promise<void> {
	const passwordEl = resolverOpid(par.password);
	if (!(passwordEl instanceof HTMLInputElement)) return;

	// Se manda el `href` completo (no sólo el hostname): la estrategia `exact`
	// de un recurso compara también el path. El matching corre en el
	// background — la página nunca recibe la bóveda (spec 06 §4.2).
	const origenAlPedir = window.location.origin;
	try {
		const coincidencias = await cliente.request<CoincidenciaAutofill[]>('AUTOFILL_BUSCAR', {
			href: window.location.href
		});
		if (coincidencias.length === 0) return;
		if (document.activeElement !== passwordEl) return; // perdió el foco mientras esperábamos
		if (window.location.origin !== origenAlPedir) return; // la SPA navegó mientras esperábamos
		crearMenu(passwordEl, par, coincidencias, origenAlPedir);
	} catch {
		// Sin sesión activa u otro error — no interrumpe la navegación normal.
	}
}

// --- arranque + re-detección ante cambios del DOM (SPAs, forms diferidos) ---
redetectar();

let redeteccionPendiente = 0;
const observador = new MutationObserver(() => {
	if (redeteccionPendiente) return;
	redeteccionPendiente = window.setTimeout(() => {
		redeteccionPendiente = 0;
		redetectar();
	}, 150);
});
observador.observe(document.documentElement, { childList: true, subtree: true });

document.addEventListener(
	'pointerdown',
	(evento) => {
		if (!menuActual) return;
		const objetivo = evento.target as Node;
		if (objetivo === menuActual.host || menuActual.host.contains(objetivo) || objetivo === menuActual.passwordField) return;
		cerrarMenu();
	},
	true
);

document.addEventListener('keydown', (evento) => {
	if (evento.key === 'Escape') {
		cerrarMenu();
		cerrarBarraGuardado();
	}
});

// `submit` en captura: si el form es un login detectado, se capturan los
// valores tipeados ANTES de que la página navegue y se decide (async, en el
// background) si ofrecer guardarlos. Limitación MVP: si el submit provoca
// una navegación completa, el content script se destruye antes de que la
// barra alcance a mostrarse — funciona en SPAs y en submits con validación
// client-side. Sólo cubre formularios con `<form>` real (un login sin
// `<form>` no dispara `submit`).
document.addEventListener(
	'submit',
	(evento) => {
		const form = evento.target;
		if (!(form instanceof HTMLFormElement)) return;
		const formOpid = opidPorElemento.get(form);
		const par = formOpid ? paresPorFormOpid.get(formOpid) : undefined;
		if (!par) return;
		const passwordEl = resolverOpid(par.password);
		const usuarioEl = par.usuario ? resolverOpid(par.usuario) : null;
		if (!(passwordEl instanceof HTMLInputElement)) return;
		const cap: CredencialCapturada = {
			usuario: usuarioEl instanceof HTMLInputElement ? usuarioEl.value : '',
			password: passwordEl.value
		};
		void ofrecerGuardado(cap);
	},
	true
);
