// Autor: Athan Espinoza

// Autofill (spec 06 §4, spec 05 §2.2) — detecta campos de login en la
// página, pide al service worker las credenciales que matchean el hostname
// activo (matching real vive ahí, ver `autofill-service.ts`), y ofrece un
// menú inline al hacer foco en el campo de contraseña. Sin framework acá
// (spec 06 §5: "no se usa SvelteKit en un content script") — DOM vanilla,
// shadow root **cerrado** creado directamente por este content script (sin
// iframe hacia una página propia de la extensión): simplificación
// deliberada respecto al diseño original de spec 06 §5 (que preveía un
// iframe con `use_dynamic_url` para el menú inline, distinto del criterio
// de la notification bar) — se adoptó acá el mismo patrón sin-iframe que ya
// se había fijado para la notification bar, porque cubre el mismo riesgo
// (BWN-08-019: nunca hay una URL `chrome-extension://.../menu.html` cargable
// por cualquier página) con menos superficie nueva (no hace falta declarar
// un HTML de extensión aparte ni `web_accessible_resources`). Revisar si
// hace falta reintroducir el iframe cuando el menú necesite algo más
// elaborado que una lista de botones.
//
// `ellkan-cli`/scripts de test no llegan hasta acá — verificar interacción
// real con un DOM de página (`chrome://extensions` bloqueado para browser
// automation en este entorno, mismo límite ya documentado en
// `docs/activeContext.md`) queda pendiente de una sesión con navegador real.
//
// Gap conocido, no resuelto: el `<style>` inline de `crearMenu()` se inserta
// en el DOM de la página anfitriona (el shadow root cuelga de un elemento
// de esa página) — un sitio con CSP propia `style-src` estricta (sin
// `'unsafe-inline'`) podría bloquear esos estilos y dejar el menú sin
// formato (los botones seguirían funcionando, sólo se verían sin estilo).
// El fix real es `chrome.scripting.insertCSS` con una hoja de estilos
// declarada en el manifest en vez de un `<style>` inline — no se hizo en
// esta pasada por no agregar esa API/permiso sin un caso real que lo pida.

import { PortClient } from '../shared/port-client';
import type { CoincidenciaAutofill } from '../background/services/autofill-service';

const cliente = new PortClient('WebIntegration');

const CAMPOS_USUARIO_VALIDOS = new Set(['text', 'email', 'tel']);

const yaProcesados = new WeakSet<HTMLInputElement>();

interface MenuAbierto {
	host: HTMLDivElement;
	passwordField: HTMLInputElement;
	hostnameEnQuePidio: string;
}
let menuActual: MenuAbierto | null = null;

/** El input de usuario más probable: el último input de texto/email/tel que
 * aparece ANTES del password field en el DOM, dentro del mismo `<form>` si
 * existe (si el campo no está en ningún form, se busca en todo el
 * documento) — heurística simple, no la detección exhaustiva por
 * `MutationObserver`+`IntersectionObserver`+shadow/iframe que describe spec
 * 06 §4.1 completo (esa es la próxima vuelta de esta misma sección; ver
 * `ponytail:` abajo). */
function campoUsuarioPara(passwordField: HTMLInputElement): HTMLInputElement | null {
	const contenedor: ParentNode = passwordField.form ?? document;
	const inputs = Array.from(contenedor.querySelectorAll('input')) as HTMLInputElement[];
	const idx = inputs.indexOf(passwordField);
	for (let i = idx - 1; i >= 0; i--) {
		if (CAMPOS_USUARIO_VALIDOS.has((inputs[i].type || 'text').toLowerCase())) return inputs[i];
	}
	return null;
}

function cerrarMenu(): void {
	if (!menuActual) return;
	menuActual.host.remove();
	menuActual = null;
}

/** Escribe el valor pasando por el setter nativo del prototipo — algunos
 * frameworks (React y similares) interceptan `.value =` directo y no
 * detectan el cambio si se lo pisa sin pasar por su propio setter
 * sintético; usar el setter del prototipo nativo + disparar `input`/
 * `change` reales es el patrón que sí dispara la detección de cambios de
 * esos frameworks. */
function escribirValor(input: HTMLInputElement, valor: string): void {
	const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
	if (setter) setter.call(input, valor);
	else input.value = valor;
	input.dispatchEvent(new Event('input', { bubbles: true }));
	input.dispatchEvent(new Event('change', { bubbles: true }));
}

async function rellenar(
	coincidencia: CoincidenciaAutofill,
	usuarioField: HTMLInputElement | null,
	passwordField: HTMLInputElement,
	hostnameEnQuePidio: string
): Promise<void> {
	cerrarMenu();

	// Revalidación de origen en el momento exacto del fill (spec 06 §4.3.1,
	// hallazgo real BWN-08-011) — si la página navegó mientras el menú
	// estaba abierto (ej. una SPA cambiando de ruta), no rellenar sobre un
	// origin distinto al que se usó para pedir las coincidencias.
	if (window.location.hostname.toLowerCase() !== hostnameEnQuePidio) return;

	// Downgrade HTTPS→HTTP (spec 06 §4.3, punto 2): el recurso guardado es
	// https:// pero la página activa es http:// — confirmación explícita
	// antes de escribir nada. Mismo criterio que `conexion.ts::urlAbrible`:
	// una URI sin esquema explícito se asume https://, nunca http://.
	const esHttpGuardado = /^http:\/\//i.test(coincidencia.uri);
	if (!esHttpGuardado && window.location.protocol === 'http:') {
		const continuar = window.confirm(
			`"${coincidencia.nombre}" se guardó para un sitio HTTPS, pero esta página es HTTP (sin cifrar). ¿Completar igual?`
		);
		if (!continuar) return;
	}

	try {
		const secreto = await cliente.request<{ password: string }>('VAULT_REVELAR_SECRETO', { resourceId: coincidencia.id });
		if (usuarioField) escribirValor(usuarioField, coincidencia.usuario);
		escribirValor(passwordField, secreto.password);
	} catch {
		// Sin sesión activa, o el recurso ya no existe — no hay UI de error
		// acá (el menú ya se cerró), simplemente no completa nada.
	}
}

const PALETA = {
	fondo: '#16314a',
	borde: '#1f3f5c',
	texto: '#e6edf3',
	textoSecundario: '#9db2c4',
	teal: '#187890'
};

function crearMenu(
	passwordField: HTMLInputElement,
	usuarioField: HTMLInputElement | null,
	coincidencias: CoincidenciaAutofill[],
	hostnameEnQuePidio: string
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

	// Shadow root cerrado: ni siquiera código JS de la página con acceso a
	// `host` puede leer `host.shadowRoot` (devuelve `null` en modo closed) —
	// aísla la UI y las credenciales que pasan por ella del DOM/JS anfitrión.
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
		// `mousedown` (no `click`) + `preventDefault()`: dispara ANTES del
		// `blur` del password field, evitando que el campo pierda foco (y
		// con eso, potencialmente, que la página oculte el propio menú) antes
		// de poder leer la elección del usuario.
		item.addEventListener('mousedown', (evento) => {
			evento.preventDefault();
			void rellenar(c, usuarioField, passwordField, hostnameEnQuePidio);
		});
		menu.appendChild(item);
	}
	shadow.appendChild(menu);

	menuActual = { host, passwordField, hostnameEnQuePidio };
}

async function ofrecerAutofill(passwordField: HTMLInputElement): Promise<void> {
	const hostname = window.location.hostname.toLowerCase();
	try {
		const coincidencias = await cliente.request<CoincidenciaAutofill[]>('AUTOFILL_BUSCAR', { hostname });
		if (coincidencias.length === 0) return;
		// El campo pudo perder el foco mientras esperábamos la respuesta.
		if (document.activeElement !== passwordField) return;
		crearMenu(passwordField, campoUsuarioPara(passwordField), coincidencias, hostname);
	} catch {
		// Sin sesión activa (usuario no logueado en la extensión) u otro
		// error — no interrumpe la navegación normal de la página, no hay
		// nada que mostrar.
	}
}

function procesarCampo(input: HTMLInputElement): void {
	if (yaProcesados.has(input)) return;
	if ((input.type || '').toLowerCase() !== 'password') return;
	yaProcesados.add(input);
	input.addEventListener('focus', () => void ofrecerAutofill(input));
}

function escanear(raiz: ParentNode): void {
	for (const input of raiz.querySelectorAll('input[type="password"]')) {
		procesarCampo(input as HTMLInputElement);
	}
}

escanear(document);

// ponytail: sin IntersectionObserver para filtrar campos invisibles
// (honeypots anti-bot) y sin travesía explícita de shadow DOM/iframes
// anidados (spec 06 §4.1 completo) — cubre el caso común (formulario
// visible en el documento principal), no el caso adversarial de un
// honeypot oculto ofreciéndose como sugerencia. Subir si aparece un caso
// real donde importe.
const observador = new MutationObserver((mutaciones) => {
	for (const mutacion of mutaciones) {
		for (const nodo of mutacion.addedNodes) {
			if (!(nodo instanceof HTMLElement)) continue;
			if (nodo.matches('input[type="password"]')) procesarCampo(nodo as HTMLInputElement);
			escanear(nodo);
		}
	}
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
	if (evento.key === 'Escape') cerrarMenu();
});
