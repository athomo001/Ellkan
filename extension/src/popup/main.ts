// Autor: Athan Espinoza

// Popup: login/desbloqueo real contra el backend de Ellkan. Toda la
// criptografía (Argon2id vía wasm) y las llamadas HTTP corren en el
// service worker (`background/services/auth-service.ts`) — acá sólo se
// arma el pedido y se muestra el resultado, mismo criterio que el resto de
// la arquitectura (Pagemod→Event→Controller→Service, spec 06 §2).

import { PortClient } from '../shared/port-client';
import type { ResultadoLogin } from '../background/services/auth-service';
import type { ItemVault } from '../background/services/vault-service';

const cliente = new PortClient('QuickAccess');

const vistas = {
	cargando: document.getElementById('vista-cargando') as HTMLElement,
	login: document.getElementById('vista-login') as HTMLElement,
	dispositivo: document.getElementById('vista-dispositivo') as HTMLElement,
	desbloqueada: document.getElementById('vista-desbloqueada') as HTMLElement,
	noSoportado: document.getElementById('vista-no-soportado') as HTMLElement
};

function mostrarVista(nombre: keyof typeof vistas): void {
	for (const [clave, el] of Object.entries(vistas)) {
		el.classList.toggle('oculto', clave !== nombre);
	}
}

const formLogin = document.getElementById('form-login') as HTMLFormElement;
const campoServidor = document.getElementById('campo-servidor') as HTMLInputElement;
const campoEmail = document.getElementById('campo-email') as HTMLInputElement;
const campoPassphrase = document.getElementById('campo-passphrase') as HTMLInputElement;
const botonMostrarPassphrase = document.getElementById('boton-mostrar-passphrase') as HTMLButtonElement;
const errorLogin = document.getElementById('error-login') as HTMLElement;
const botonLogin = document.getElementById('boton-login') as HTMLButtonElement;

botonMostrarPassphrase.addEventListener('click', () => {
	const oculto = campoPassphrase.type === 'password';
	campoPassphrase.type = oculto ? 'text' : 'password';
	botonMostrarPassphrase.textContent = oculto ? '🙈' : '👁';
	botonMostrarPassphrase.setAttribute('aria-label', oculto ? 'Ocultar contraseña' : 'Mostrar contraseña');
});

const formDispositivo = document.getElementById('form-dispositivo') as HTMLFormElement;
const campoCodigo = document.getElementById('campo-codigo') as HTMLInputElement;
const errorDispositivo = document.getElementById('error-dispositivo') as HTMLElement;
const botonVerificar = document.getElementById('boton-verificar') as HTMLButtonElement;
const botonCancelarDispositivo = document.getElementById('boton-cancelar-dispositivo') as HTMLButtonElement;

const tarjetaSesion = document.querySelector('.tarjeta-sesion-compacta') as HTMLElement;
const emailActivo = document.getElementById('email-activo') as HTMLElement;
const botonLogout = document.getElementById('boton-logout') as HTMLButtonElement;

const campoBuscar = document.getElementById('campo-buscar') as HTMLInputElement;
const listaVault = document.getElementById('lista-vault') as HTMLElement;
const vaultVacio = document.getElementById('vault-vacio') as HTMLElement;
const vaultError = document.getElementById('vault-error') as HTMLElement;

const mensajeNoSoportado = document.getElementById('mensaje-no-soportado') as HTMLElement;
const botonVolver = document.getElementById('boton-volver') as HTMLButtonElement;

const ICONO_POR_TIPO: Record<string, string> = {
	'login-password': '🔑',
	ssh: '💻',
	ftp: '📁',
	vnc: '🖥️',
	telnet: '📟'
};

let itemsVault: ItemVault[] = [];

function renderizarLista(filtro: string): void {
	listaVault.innerHTML = '';
	vaultVacio.classList.toggle('oculto', itemsVault.length > 0);
	if (itemsVault.length === 0) return;

	const q = filtro.trim().toLowerCase();
	const filtrados = q
		? itemsVault.filter(
				(i) => i.nombre.toLowerCase().includes(q) || i.usuario.toLowerCase().includes(q) || i.uri.toLowerCase().includes(q)
			)
		: itemsVault;

	if (filtrados.length === 0) {
		const p = document.createElement('p');
		p.className = 'texto-secundario';
		p.textContent = 'Sin resultados para esa búsqueda.';
		listaVault.appendChild(p);
		return;
	}

	for (const item of filtrados) {
		const fila = document.createElement('div');
		fila.className = 'item-vault';

		const icono = document.createElement('span');
		icono.className = 'item-vault-icono';
		icono.textContent = ICONO_POR_TIPO[item.resourceTypeSlug] ?? '🔒';
		icono.setAttribute('aria-hidden', 'true');

		const info = document.createElement('div');
		info.className = 'item-vault-info';
		const nombre = document.createElement('p');
		nombre.className = 'item-vault-nombre';
		nombre.textContent = item.nombre || '(sin nombre)';
		const usuario = document.createElement('p');
		usuario.className = 'item-vault-usuario';
		usuario.textContent = item.usuario || item.uri || '';
		info.append(nombre, usuario);

		const botonCopiar = document.createElement('button');
		botonCopiar.type = 'button';
		botonCopiar.className = 'item-vault-copiar';
		botonCopiar.textContent = '📋';
		botonCopiar.setAttribute('aria-label', `Copiar contraseña de ${item.nombre || 'este recurso'}`);
		botonCopiar.addEventListener('click', () => copiarPassword(item, botonCopiar));

		fila.append(icono, info, botonCopiar);
		listaVault.appendChild(fila);
	}
}

// ponytail: sin limpieza automática del portapapeles tras copiar (a
// diferencia de `frontend/src/lib/clipboard.ts::copiarConLimpieza`) — un
// `setTimeout` acá no sirve, el popup se cierra apenas el usuario cambia de
// pestaña para pegar, matando este contexto antes de que corra. La limpieza
// real necesitaría un `chrome.offscreen` document driven por `chrome.alarms`
// desde el service worker (el único contexto que sobrevive al cierre del
// popup) — subir cuando el uso real lo pida.
async function copiarPassword(item: ItemVault, boton: HTMLButtonElement): Promise<void> {
	boton.disabled = true;
	try {
		const resultado = await cliente.request<{ password: string }>('VAULT_REVELAR_PASSWORD', { resourceId: item.id });
		await navigator.clipboard.writeText(resultado.password);
		boton.textContent = '✅';
	} catch {
		boton.textContent = '⚠';
	} finally {
		setTimeout(() => {
			boton.textContent = '📋';
			boton.disabled = false;
		}, 1200);
	}
}

async function cargarVault(): Promise<void> {
	ocultarError(vaultError);
	try {
		itemsVault = await cliente.request<ItemVault[]>('VAULT_LISTAR');
		renderizarLista(campoBuscar.value);
	} catch (error) {
		mostrarError(vaultError, error instanceof Error ? error.message : 'No se pudo cargar la bóveda.');
	}
}

campoBuscar.addEventListener('input', () => renderizarLista(campoBuscar.value));

/** Estado intermedio entre `login()` (devuelve `pendiente_dispositivo`) y
 * `verificarDispositivo()` — vive sólo en memoria del popup mientras el
 * usuario escribe el código; si cierra el popup antes de terminar, tiene
 * que volver a iniciar sesión (comportamiento esperado, no un bug). */
let servidorEnCurso = '';
let deviceChallengeIdEnCurso = '';

function mostrarError(el: HTMLElement, mensaje: string): void {
	el.textContent = mensaje;
	el.classList.remove('oculto');
}
function ocultarError(el: HTMLElement): void {
	el.classList.add('oculto');
}

const MENSAJE_POR_ESTADO_NO_SOPORTADO: Record<string, string> = {
	pendiente_mfa: 'Esta cuenta tiene un segundo factor (MFA) configurado — completá el login desde la web por ahora.',
	requiere_configurar_mfa: 'Esta organización exige configurar un segundo factor (MFA) — hacelo desde la web antes de usar la extensión.',
	requiere_cambiar_passphrase: 'Tu contraseña es provisoria y hay que cambiarla — hacelo desde la web antes de usar la extensión.'
};

function manejarResultadoLogin(resultado: ResultadoLogin, serverUrl: string): void {
	if (resultado.estado === 'completo') {
		mostrarSesionActiva(campoEmail.value, serverUrl);
		return;
	}
	if (resultado.estado === 'pendiente_dispositivo' && resultado.deviceChallengeId) {
		servidorEnCurso = serverUrl;
		deviceChallengeIdEnCurso = resultado.deviceChallengeId;
		campoCodigo.value = '';
		ocultarError(errorDispositivo);
		mostrarVista('dispositivo');
		return;
	}
	const mensaje = MENSAJE_POR_ESTADO_NO_SOPORTADO[resultado.estado] ?? `Estado de login no manejado por la extensión todavía: "${resultado.estado}".`;
	mensajeNoSoportado.textContent = mensaje;
	mostrarVista('noSoportado');
}

function mostrarSesionActiva(email: string, serverUrl: string): void {
	emailActivo.textContent = email;
	tarjetaSesion.title = `${email} — ${serverUrl}`;
	mostrarVista('desbloqueada');
	void cargarVault();
}

formLogin.addEventListener('submit', async (evento) => {
	evento.preventDefault();
	ocultarError(errorLogin);

	const serverUrl = campoServidor.value.trim();
	const email = campoEmail.value.trim();
	const passphrase = campoPassphrase.value;

	botonLogin.disabled = true;
	botonLogin.textContent = 'Iniciando sesión…';
	try {
		const resultado = await cliente.request<ResultadoLogin>('AUTH_LOGIN', { serverUrl, email, passphrase });
		manejarResultadoLogin(resultado, serverUrl);
	} catch (error) {
		mostrarError(errorLogin, error instanceof Error ? error.message : 'No se pudo iniciar sesión.');
	} finally {
		botonLogin.disabled = false;
		botonLogin.textContent = 'Iniciar sesión';
	}
});

formDispositivo.addEventListener('submit', async (evento) => {
	evento.preventDefault();
	ocultarError(errorDispositivo);

	botonVerificar.disabled = true;
	botonVerificar.textContent = 'Verificando…';
	try {
		const resultado = await cliente.request<{ estado: string }>('AUTH_VERIFICAR_DISPOSITIVO', {
			serverUrl: servidorEnCurso,
			deviceChallengeId: deviceChallengeIdEnCurso,
			codigo: campoCodigo.value.trim()
		});
		if (resultado.estado === 'completo') {
			mostrarSesionActiva(campoEmail.value.trim(), servidorEnCurso);
		} else {
			const mensaje =
				MENSAJE_POR_ESTADO_NO_SOPORTADO[resultado.estado] ?? `Estado no manejado por la extensión todavía: "${resultado.estado}".`;
			mensajeNoSoportado.textContent = mensaje;
			mostrarVista('noSoportado');
		}
	} catch (error) {
		mostrarError(errorDispositivo, error instanceof Error ? error.message : 'Código incorrecto o vencido.');
	} finally {
		botonVerificar.disabled = false;
		botonVerificar.textContent = 'Verificar';
	}
});

botonLogout.addEventListener('click', async () => {
	botonLogout.disabled = true;
	try {
		await cliente.request('AUTH_LOGOUT');
	} finally {
		botonLogout.disabled = false;
		formLogin.reset();
		campoServidor.value = 'http://localhost:8080';
		itemsVault = [];
		campoBuscar.value = '';
		listaVault.innerHTML = '';
		ocultarError(vaultError);
		mostrarVista('login');
	}
});

botonVolver.addEventListener('click', () => {
	mostrarVista('login');
});

botonCancelarDispositivo.addEventListener('click', async () => {
	botonCancelarDispositivo.disabled = true;
	try {
		await cliente.request('AUTH_CANCELAR_PENDIENTE_DISPOSITIVO');
	} finally {
		botonCancelarDispositivo.disabled = false;
		formLogin.reset();
		campoServidor.value = 'http://localhost:8080';
		mostrarVista('login');
	}
});

// --- Estado inicial: ¿ya hay una sesión activa, o quedó una verificación de
// dispositivo a mitad de camino? El popup se cierra solo al perder el foco
// (ej. cambiar de pestaña para leer el código del email) — sin este segundo
// chequeo, reabrirlo forzaba a repetir el login entero aunque el desafío
// siguiera vigente en el servidor (bug real reportado por el usuario). ---
(async () => {
	try {
		const sesion = await cliente.request<{ sessionId: string; email: string; serverUrl: string } | null>('AUTH_ESTADO_SESION');
		if (sesion) {
			mostrarSesionActiva(sesion.email, sesion.serverUrl);
			return;
		}

		const pendiente = await cliente.request<{ serverUrl: string; email: string; deviceChallengeId: string } | null>(
			'AUTH_ESTADO_PENDIENTE_DISPOSITIVO'
		);
		if (pendiente) {
			servidorEnCurso = pendiente.serverUrl;
			deviceChallengeIdEnCurso = pendiente.deviceChallengeId;
			campoServidor.value = pendiente.serverUrl;
			campoEmail.value = pendiente.email;
			campoCodigo.value = '';
			ocultarError(errorDispositivo);
			mostrarVista('dispositivo');
			return;
		}

		mostrarVista('login');
	} catch {
		// Sin sesión/desafío previo legible (o el service worker recién está
		// arrancando) — arrancar igual desde el login es la salida segura.
		mostrarVista('login');
	}
})();
