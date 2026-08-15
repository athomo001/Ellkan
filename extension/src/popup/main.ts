// Autor: Athan Espinoza

// Popup: login/desbloqueo real contra el backend de Ellkan. Toda la
// criptografía (Argon2id vía wasm) y las llamadas HTTP corren en el
// service worker (`background/services/auth-service.ts`) — acá sólo se
// arma el pedido y se muestra el resultado, mismo criterio que el resto de
// la arquitectura (Pagemod→Event→Controller→Service, spec 06 §2).

import { PortClient } from '../shared/port-client';
import type { ResultadoLogin } from '../background/services/auth-service';
import type { ItemVault, SecretoRevelado, DatosRecurso } from '../background/services/vault-service';
import { comandoDeConexion, urlAbrible, hostnameParaFavicon } from './conexion';
import { generarPassword, type ReglasCharset } from '../../../frontend/src/lib/crypto/passwordGenerator';
import { evaluarFortaleza } from '../../../frontend/src/lib/crypto/passwordStrength';
import { generarFraseDePaso, type OpcionesFraseDePaso } from './passphrase-generator';

const cliente = new PortClient('QuickAccess');

const vistas = {
	cargando: document.getElementById('vista-cargando') as HTMLElement,
	login: document.getElementById('vista-login') as HTMLElement,
	dispositivo: document.getElementById('vista-dispositivo') as HTMLElement,
	desbloqueo: document.getElementById('vista-desbloqueo') as HTMLElement,
	mfa: document.getElementById('vista-mfa') as HTMLElement,
	desbloqueada: document.getElementById('vista-desbloqueada') as HTMLElement,
	detalle: document.getElementById('vista-detalle-item') as HTMLElement,
	formulario: document.getElementById('vista-form-recurso') as HTMLElement,
	cuenta: document.getElementById('vista-cuenta') as HTMLElement,
	noSoportado: document.getElementById('vista-no-soportado') as HTMLElement
};

/** Layout de dos columnas (spec 06 §5bis, comparado contra capturas reales
 * de Proton Pass) — de una sola vez, con un solo clic en el ícono de la
 * extensión, sin ventana aparte ni paso extra: Chrome permite un popup de
 * hasta 800px de ancho (`styles.css`, `body` a 780px), suficiente para
 * lista + detalle lado a lado como en la referencia real. La lista
 * (`desbloqueada`) queda siempre visible en la columna izquierda — nunca se
 * oculta al abrir detalle/formulario/cuenta, que pasan a la columna derecha
 * vía CSS. */
function mostrarVista(nombre: keyof typeof vistas): void {
	const mantenerListaVisible = nombre === 'detalle' || nombre === 'formulario' || nombre === 'cuenta';
	for (const [clave, el] of Object.entries(vistas)) {
		if (mantenerListaVisible && clave === 'desbloqueada') {
			el.classList.remove('oculto');
			continue;
		}
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

// Sesión inteligente (2026-08-15): bloqueo por inactividad/reinicio.
const desbloqueoEmail = document.getElementById('desbloqueo-email') as HTMLElement;
const desbloqueoServidor = document.getElementById('desbloqueo-servidor') as HTMLElement;
const formDesbloqueo = document.getElementById('form-desbloqueo') as HTMLFormElement;
const campoDesbloqueoPassphrase = document.getElementById('campo-desbloqueo-passphrase') as HTMLInputElement;
const botonMostrarDesbloqueoPassphrase = document.getElementById('boton-mostrar-desbloqueo-passphrase') as HTMLButtonElement;
const errorDesbloqueo = document.getElementById('error-desbloqueo') as HTMLElement;
const botonDesbloquear = document.getElementById('boton-desbloquear') as HTMLButtonElement;
const botonOtraCuenta = document.getElementById('boton-otra-cuenta') as HTMLButtonElement;

botonMostrarDesbloqueoPassphrase.addEventListener('click', () => {
	const oculto = campoDesbloqueoPassphrase.type === 'password';
	campoDesbloqueoPassphrase.type = oculto ? 'text' : 'password';
	botonMostrarDesbloqueoPassphrase.textContent = oculto ? '🙈' : '👁';
});

const formMfa = document.getElementById('form-mfa') as HTMLFormElement;
const campoMfaCodigo = document.getElementById('campo-mfa-codigo') as HTMLInputElement;
const errorMfa = document.getElementById('error-mfa') as HTMLElement;
const botonVerificarMfa = document.getElementById('boton-verificar-mfa') as HTMLButtonElement;

const botonLogout = document.getElementById('boton-logout') as HTMLButtonElement;
const botonCuenta = document.getElementById('boton-cuenta') as HTMLButtonElement;
let emailActual = '';

const campoBuscar = document.getElementById('campo-buscar') as HTMLInputElement;
const listaVault = document.getElementById('lista-vault') as HTMLElement;
const vaultVacio = document.getElementById('vault-vacio') as HTMLElement;
const vaultError = document.getElementById('vault-error') as HTMLElement;
const botonNuevo = document.getElementById('boton-nuevo') as HTMLButtonElement;

const mensajeNoSoportado = document.getElementById('mensaje-no-soportado') as HTMLElement;
const botonVolver = document.getElementById('boton-volver') as HTMLButtonElement;

const botonVolverLista = document.getElementById('boton-volver-lista') as HTMLButtonElement;
const detalleTitulo = document.getElementById('detalle-titulo') as HTMLElement;
const detalleUsuario = document.getElementById('detalle-usuario') as HTMLElement;
const botonCopiarUsuario = document.getElementById('boton-copiar-usuario') as HTMLButtonElement;
const detallePassword = document.getElementById('detalle-password') as HTMLElement;
const detallePasswordFortaleza = document.getElementById('detalle-password-fortaleza') as HTMLElement;
const botonRevelarPassword = document.getElementById('boton-revelar-password') as HTMLButtonElement;
const botonCopiarPassword = document.getElementById('boton-copiar-password') as HTMLButtonElement;
const detalleSitioBloque = document.getElementById('detalle-sitio-bloque') as HTMLElement;
const detalleSitioLink = document.getElementById('detalle-sitio-link') as HTMLAnchorElement;
const detalleComandoBloque = document.getElementById('detalle-comando-bloque') as HTMLElement;
const detalleComando = document.getElementById('detalle-comando') as HTMLElement;
const botonCopiarComando = document.getElementById('boton-copiar-comando') as HTMLButtonElement;
const detalleTotpBloque = document.getElementById('detalle-totp-bloque') as HTMLElement;
const detalleTotp = document.getElementById('detalle-totp') as HTMLElement;
const botonCopiarTotp = document.getElementById('boton-copiar-totp') as HTMLButtonElement;
const detalleNotaBloque = document.getElementById('detalle-nota-bloque') as HTMLElement;
const detalleNota = document.getElementById('detalle-nota') as HTMLElement;
const detalleAbrirWeb = document.getElementById('detalle-abrir-web') as HTMLAnchorElement;
const detalleCreado = document.getElementById('detalle-creado') as HTMLElement;
const detalleModificado = document.getElementById('detalle-modificado') as HTMLElement;

const FORMATO_FECHA = new Intl.DateTimeFormat('es', { day: 'numeric', month: 'short', year: 'numeric' });
const botonEditarItem = document.getElementById('boton-editar-item') as HTMLButtonElement;

const formRecurso = document.getElementById('form-recurso') as HTMLFormElement;
const formTitulo = document.getElementById('form-titulo') as HTMLElement;
const formTipo = document.getElementById('form-tipo') as HTMLSelectElement;
const formNombre = document.getElementById('form-nombre') as HTMLInputElement;
const formUsuario = document.getElementById('form-usuario') as HTMLInputElement;
const formUri = document.getElementById('form-uri') as HTMLInputElement;
const formPassword = document.getElementById('form-password') as HTMLInputElement;
const botonGenerarPassword = document.getElementById('boton-generar-password') as HTMLButtonElement;
const botonMostrarFormPassword = document.getElementById('boton-mostrar-form-password') as HTMLButtonElement;
const formTotp = document.getElementById('form-totp') as HTMLInputElement;
const formNotas = document.getElementById('form-notas') as HTMLTextAreaElement;
const errorForm = document.getElementById('error-form') as HTMLElement;
const botonGuardarForm = document.getElementById('boton-guardar-form') as HTMLButtonElement;
const botonCancelarForm = document.getElementById('boton-cancelar-form') as HTMLButtonElement;

const botonVolverCuenta = document.getElementById('boton-volver-cuenta') as HTMLButtonElement;
const cuentaEmail = document.getElementById('cuenta-email') as HTMLElement;
const cuentaServidor = document.getElementById('cuenta-servidor') as HTMLElement;
const cuentaAbrirWeb = document.getElementById('cuenta-abrir-web') as HTMLAnchorElement;

const ICONO_POR_TIPO: Record<string, string> = {
	'login-password': '🔑',
	ssh: '💻',
	ftp: '📁',
	vnc: '🖥️',
	telnet: '📟'
};

let itemsVault: ItemVault[] = [];
let pestanaActiva: 'todos' | 'reciente' = 'todos';

const MS_14_DIAS = 14 * 24 * 60 * 60 * 1000;

function crearFilaItem(item: ItemVault): HTMLElement {
	const fila = document.createElement('div');
	fila.className = 'item-vault';
	if (itemDetalleActual?.id === item.id) fila.classList.add('item-vault-activo');
	fila.setAttribute('role', 'button');
	fila.setAttribute('tabindex', '0');
	fila.addEventListener('click', () => abrirDetalle(item));
	fila.addEventListener('keydown', (e) => {
		if (e.key === 'Enter' || e.key === ' ') abrirDetalle(item);
	});

	const icono = document.createElement('span');
	icono.className = 'item-vault-icono';
	icono.setAttribute('aria-hidden', 'true');
	const glifo = ICONO_POR_TIPO[item.resourceTypeSlug] ?? '🔒';
	const host = hostnameParaFavicon(item.resourceTypeSlug, item.uri);
	if (host) {
		// Favicon real del sitio (spec 06 §5bis) — mismo criterio visual que
		// Proton Pass. Trade-off documentado, no oculto: esto manda el
		// hostname (nunca la credencial) a un servicio externo de favicons
		// cuando se renderiza la lista — aceptado a propósito por el pedido
		// explícito de paridad visual; si `onerror` dispara (sin red, sin
		// favicon, servicio caído), cae al glifo genérico sin dejar un
		// ícono roto.
		const img = document.createElement('img');
		img.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=64`;
		img.alt = '';
		img.addEventListener('error', () => {
			img.remove();
			icono.textContent = glifo;
		});
		icono.appendChild(img);
	} else {
		icono.textContent = glifo;
	}

	const info = document.createElement('div');
	info.className = 'item-vault-info';
	const nombre = document.createElement('p');
	nombre.className = 'item-vault-nombre';
	nombre.textContent = item.nombre || '(sin nombre)';
	const usuario = document.createElement('p');
	usuario.className = 'item-vault-usuario';
	usuario.textContent = item.usuario || item.uri || '';
	info.append(nombre, usuario);

	const chevron = document.createElement('span');
	chevron.className = 'item-vault-chevron';
	chevron.textContent = '›';
	chevron.setAttribute('aria-hidden', 'true');

	fila.append(icono, info, chevron);
	return fila;
}

/** "Hoy" / "Últimos 14 días" / "Más antiguo", por `updatedAt` — mismo
 * espíritu que el agrupado cronológico de Proton Pass ("Hoy", "Últimas 2
 * semanas", "Más de un mes"), sin copiar los cortes exactos porque no hay
 * ningún significado especial en esos números puntuales para Ellkan. */
function grupoDeFecha(item: ItemVault): string {
	const fecha = new Date(item.updatedAt);
	const ahora = new Date();
	const esHoy = fecha.toDateString() === ahora.toDateString();
	if (esHoy) return 'Hoy';
	const dias = (ahora.getTime() - fecha.getTime()) / (24 * 60 * 60 * 1000);
	if (dias <= 14) return 'Últimos 14 días';
	return 'Más antiguo';
}

function renderizarLista(filtro: string): void {
	listaVault.innerHTML = '';
	vaultVacio.classList.toggle('oculto', itemsVault.length > 0);
	if (itemsVault.length === 0) return;

	const q = filtro.trim().toLowerCase();
	let filtrados = q
		? itemsVault.filter(
				(i) => i.nombre.toLowerCase().includes(q) || i.usuario.toLowerCase().includes(q) || i.uri.toLowerCase().includes(q)
			)
		: itemsVault;

	if (pestanaActiva === 'reciente') {
		const ahora = Date.now();
		filtrados = filtrados.filter((i) => ahora - new Date(i.updatedAt).getTime() <= MS_14_DIAS);
	}
	filtrados = [...filtrados].sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());

	if (filtrados.length === 0) {
		const p = document.createElement('p');
		p.className = 'texto-secundario';
		p.textContent = 'Sin resultados para esa búsqueda.';
		listaVault.appendChild(p);
		return;
	}

	let grupoAnterior = '';
	for (const item of filtrados) {
		const grupo = grupoDeFecha(item);
		if (grupo !== grupoAnterior) {
			const encabezado = document.createElement('p');
			encabezado.className = 'lista-vault-grupo';
			encabezado.textContent = grupo;
			listaVault.appendChild(encabezado);
			grupoAnterior = grupo;
		}
		listaVault.appendChild(crearFilaItem(item));
	}
}

// ponytail: sin limpieza automática del portapapeles tras copiar (a
// diferencia de `frontend/src/lib/clipboard.ts::copiarConLimpieza`) — un
// `setTimeout` acá no sirve, el popup se cierra apenas el usuario cambia de
// pestaña para pegar, matando este contexto antes de que corra. La limpieza
// real necesitaría un `chrome.offscreen` document driven por `chrome.alarms`
// desde el service worker (el único contexto que sobrevive al cierre del
// popup) — subir cuando el uso real lo pida.
async function copiarTexto(texto: string, boton: HTMLButtonElement): Promise<void> {
	boton.disabled = true;
	try {
		await navigator.clipboard.writeText(texto);
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

// spec 06 §5bis: click en una fila de la lista abre esta vista con los
// campos identificados/copiables por separado (usuario, contraseña oculta
// con revelar aparte, sitio o comando de conexión según el tipo) — en vez
// de un único botón de "copiar contraseña" a ciegas, patrón tomado de las
// capturas de Proton Pass que mandó el usuario.
let itemDetalleActual: ItemVault | null = null;
let secretoRevelado: SecretoRevelado | null = null;
let servidorActual = '';

function abrirDetalle(item: ItemVault): void {
	itemDetalleActual = item;
	secretoRevelado = null;

	detalleTitulo.textContent = item.nombre || '(sin nombre)';
	detalleUsuario.textContent = item.usuario || '—';
	detallePassword.textContent = '••••••••';
	detallePasswordFortaleza.classList.add('oculto');
	botonRevelarPassword.textContent = '👁';
	botonRevelarPassword.setAttribute('aria-label', 'Mostrar contraseña');
	detalleTotpBloque.classList.add('oculto');
	detalleNotaBloque.classList.add('oculto');

	const comando = comandoDeConexion(item.resourceTypeSlug, item.usuario, item.uri);
	const url = urlAbrible(item.resourceTypeSlug, item.uri);
	detalleComandoBloque.classList.toggle('oculto', !comando);
	if (comando) detalleComando.textContent = comando;
	detalleSitioBloque.classList.toggle('oculto', !url);
	if (url) {
		detalleSitioLink.href = url;
		detalleSitioLink.textContent = item.uri;
	}
	// F-11: no hay ruta de deep-link a un recurso puntual en el frontend web
	// todavía (sólo `/vault` general) — igual sirve como salida real a
	// compartir/editar/borrar, que Quick Access no hace (sigue siendo sólo
	// lectura, spec 06 §5bis).
	detalleAbrirWeb.href = `${servidorActual}/vault`;

	detalleCreado.textContent = FORMATO_FECHA.format(new Date(item.createdAt));
	detalleModificado.textContent = FORMATO_FECHA.format(new Date(item.updatedAt));

	mostrarVista('detalle');
	// La lista sigue visible en la columna izquierda (ver `mostrarVista`) —
	// re-renderiza para mover el resaltado al ítem recién abierto.
	renderizarLista(campoBuscar.value);
}

async function obtenerSecretoRevelado(): Promise<SecretoRevelado> {
	if (secretoRevelado) return secretoRevelado;
	if (!itemDetalleActual) throw new Error('no hay ningún ítem abierto');
	secretoRevelado = await cliente.request<SecretoRevelado>('VAULT_REVELAR_SECRETO', { resourceId: itemDetalleActual.id });
	return secretoRevelado;
}

botonRevelarPassword.addEventListener('click', async () => {
	const yaRevelada = botonRevelarPassword.getAttribute('aria-label') === 'Ocultar contraseña';
	if (yaRevelada) {
		detallePassword.textContent = '••••••••';
		detalleTotp.textContent = '••••••••';
		detallePasswordFortaleza.classList.add('oculto');
		botonRevelarPassword.textContent = '👁';
		botonRevelarPassword.setAttribute('aria-label', 'Mostrar contraseña');
		return;
	}
	botonRevelarPassword.disabled = true;
	try {
		const secreto = await obtenerSecretoRevelado();
		detallePassword.textContent = secreto.password;
		botonRevelarPassword.textContent = '🙈';
		botonRevelarPassword.setAttribute('aria-label', 'Ocultar contraseña');

		const { score } = evaluarFortaleza(secreto.password);
		const etiqueta = ETIQUETA_FORTALEZA[score];
		detallePasswordFortaleza.textContent = `· ${etiqueta.texto}`;
		detallePasswordFortaleza.className = `fortaleza-inline ${etiqueta.clase}`;

		detalleTotpBloque.classList.toggle('oculto', !secreto.totpSecret);
		if (secreto.totpSecret) detalleTotp.textContent = secreto.totpSecret;

		detalleNotaBloque.classList.toggle('oculto', !secreto.notes);
		if (secreto.notes) detalleNota.textContent = secreto.notes;
	} catch (error) {
		mostrarError(vaultError, error instanceof Error ? error.message : 'No se pudo revelar la contraseña.');
	} finally {
		botonRevelarPassword.disabled = false;
	}
});

botonCopiarUsuario.addEventListener('click', () => {
	if (itemDetalleActual) void copiarTexto(itemDetalleActual.usuario, botonCopiarUsuario);
});

botonCopiarPassword.addEventListener('click', async () => {
	botonCopiarPassword.disabled = true;
	try {
		await copiarTexto((await obtenerSecretoRevelado()).password, botonCopiarPassword);
	} catch (error) {
		botonCopiarPassword.disabled = false;
		mostrarError(vaultError, error instanceof Error ? error.message : 'No se pudo copiar la contraseña.');
	}
});

botonCopiarComando.addEventListener('click', () => {
	void copiarTexto(detalleComando.textContent ?? '', botonCopiarComando);
});

botonCopiarTotp.addEventListener('click', async () => {
	botonCopiarTotp.disabled = true;
	try {
		const secreto = await obtenerSecretoRevelado();
		await copiarTexto(secreto.totpSecret ?? '', botonCopiarTotp);
	} catch (error) {
		botonCopiarTotp.disabled = false;
		mostrarError(vaultError, error instanceof Error ? error.message : 'No se pudo copiar la clave TOTP.');
	}
});

botonVolverLista.addEventListener('click', () => {
	itemDetalleActual = null;
	secretoRevelado = null;
	mostrarVista('desbloqueada');
});

// --- Crear/editar (pedido explícito del usuario, con capturas de Proton
// Pass: "puedo agregar cuentas nuevas... modificar contraseñas... generar
// contraseñas aleatorias con opciones") — mismo formulario para los dos
// casos, sólo cambia qué mensaje manda (VAULT_CREAR/VAULT_EDITAR) al
// guardar. ---
let modoFormulario: 'crear' | 'editar' = 'crear';

function abrirFormularioCrear(): void {
	modoFormulario = 'crear';
	formTitulo.textContent = 'Nueva contraseña';
	formRecurso.reset();
	formTipo.value = 'login-password';
	formPassword.type = 'password';
	botonMostrarFormPassword.textContent = '👁';
	ocultarError(errorForm);
	mostrarVista('formulario');
}

async function abrirFormularioEditar(): Promise<void> {
	if (!itemDetalleActual) return;
	const item = itemDetalleActual;
	modoFormulario = 'editar';
	formTitulo.textContent = 'Editar contraseña';
	ocultarError(errorForm);

	botonEditarItem.disabled = true;
	try {
		const secreto = await obtenerSecretoRevelado();
		formTipo.value = item.resourceTypeSlug;
		formNombre.value = item.nombre;
		formUsuario.value = item.usuario;
		formUri.value = item.uri;
		formPassword.value = secreto.password;
		formPassword.type = 'password';
		botonMostrarFormPassword.textContent = '👁';
		formTotp.value = secreto.totpSecret ?? '';
		formNotas.value = secreto.notes;
		mostrarVista('formulario');
	} catch (error) {
		mostrarError(vaultError, error instanceof Error ? error.message : 'No se pudo cargar el recurso para editar.');
	} finally {
		botonEditarItem.disabled = false;
	}
}

botonNuevo.addEventListener('click', abrirFormularioCrear);
botonEditarItem.addEventListener('click', () => void abrirFormularioEditar());

botonMostrarFormPassword.addEventListener('click', () => {
	const oculto = formPassword.type === 'password';
	formPassword.type = oculto ? 'text' : 'password';
	botonMostrarFormPassword.textContent = oculto ? '🙈' : '👁';
});

botonGenerarPassword.addEventListener('click', () => abrirGenerador(false));

botonCancelarForm.addEventListener('click', () => {
	mostrarVista(modoFormulario === 'editar' && itemDetalleActual ? 'detalle' : 'desbloqueada');
});

formRecurso.addEventListener('submit', async (evento) => {
	evento.preventDefault();
	ocultarError(errorForm);

	const datos: DatosRecurso = {
		tipo: formTipo.value as DatosRecurso['tipo'],
		nombre: formNombre.value.trim(),
		usuario: formUsuario.value.trim(),
		uri: formUri.value.trim(),
		password: formPassword.value,
		notas: formNotas.value,
		totpSecretBase32: formTotp.value.trim() || undefined
	};

	botonGuardarForm.disabled = true;
	botonGuardarForm.textContent = 'Guardando…';
	try {
		if (modoFormulario === 'crear') {
			await cliente.request('VAULT_CREAR', { datos });
		} else {
			if (!itemDetalleActual) throw new Error('no hay ningún ítem para editar');
			await cliente.request('VAULT_EDITAR', { item: itemDetalleActual, datos });
		}
		itemDetalleActual = null;
		secretoRevelado = null;
		mostrarVista('desbloqueada');
		await cargarVault();
	} catch (error) {
		mostrarError(errorForm, error instanceof Error ? error.message : 'No se pudo guardar.');
	} finally {
		botonGuardarForm.disabled = false;
		botonGuardarForm.textContent = 'Guardar';
	}
});

// --- Generador de contraseñas: modal con largo/reglas ajustables, vista
// previa coloreada por tipo de carácter, y fortaleza real (`zxcvbn`, mismo
// medidor que usa el registro de cuenta en la app web) — pedido explícito
// del usuario con esta especificación exacta. ---
const modalGenerador = document.getElementById('modal-generador') as HTMLElement;
const botonCerrarGenerador = document.getElementById('boton-cerrar-generador') as HTMLButtonElement;
const botonGeneradorHeader = document.getElementById('boton-generador-header') as HTMLButtonElement;
const generadorValor = document.getElementById('generador-valor') as HTMLElement;
const botonRegenerar = document.getElementById('boton-regenerar') as HTMLButtonElement;
const generadorFortaleza = document.getElementById('generador-fortaleza') as HTMLElement;
const generadorLargo = document.getElementById('generador-largo') as HTMLInputElement;
const generadorLargoValor = document.getElementById('generador-largo-valor') as HTMLElement;
const generadorMayus = document.getElementById('generador-mayus') as HTMLInputElement;
const generadorNumeros = document.getElementById('generador-numeros') as HTMLInputElement;
const generadorSimbolos = document.getElementById('generador-simbolos') as HTMLInputElement;
const generadorSinAmbiguos = document.getElementById('generador-sin-ambiguos') as HTMLInputElement;
const botonCopiarCerrarGenerador = document.getElementById('boton-copiar-cerrar-generador') as HTMLButtonElement;

// Modo 2: frases de paso memorizables en español (2026-08-15).
const tabModoAleatoria = document.getElementById('tab-modo-aleatoria') as HTMLButtonElement;
const tabModoFrase = document.getElementById('tab-modo-frase') as HTMLButtonElement;
const controlesModoAleatoria = document.getElementById('controles-modo-aleatoria') as HTMLElement;
const controlesModoFrase = document.getElementById('controles-modo-frase') as HTMLElement;
const generadorCantidadPalabras = document.getElementById('generador-cantidad-palabras') as HTMLInputElement;
const generadorCantidadPalabrasValor = document.getElementById('generador-cantidad-palabras-valor') as HTMLElement;
const generadorFraseMayus = document.getElementById('generador-frase-mayus') as HTMLInputElement;
const generadorFraseNumeros = document.getElementById('generador-frase-numeros') as HTMLInputElement;
const generadorSeparador = document.getElementById('generador-separador') as HTMLSelectElement;

let passwordGenerada = '';
let modoGenerador: 'aleatoria' | 'frase' = 'aleatoria';
// El modal se abre desde dos lugares distintos: el ícono del header (spec
// 2026-08-15, sin formulario detrás — "Copiar y cerrar" sólo copia) y el
// 🎲 dentro del formulario de crear/editar (comportamiento de siempre —
// carga el valor en `formPassword` además de copiar).
let generadorOrigenStandalone = false;

function reglasActuales(): ReglasCharset {
	return {
		uppercase: generadorMayus.checked,
		lowercase: true,
		digits: generadorNumeros.checked,
		symbols: generadorSimbolos.checked,
		exclude_ambiguous: generadorSinAmbiguos.checked
	};
}

function opcionesFraseActuales(): OpcionesFraseDePaso {
	return {
		wordCount: Number(generadorCantidadPalabras.value),
		capitalize: generadorFraseMayus.checked,
		includeNumbers: generadorFraseNumeros.checked,
		separator: generadorSeparador.value as OpcionesFraseDePaso['separator']
	};
}

/** Un `<span>` por carácter con su propia clase (letra/número/símbolo) —
 * pedido explícito: "colores diferenciados por tipo de carácter". */
function pintarPassword(valor: string): void {
	generadorValor.innerHTML = '';
	for (const char of valor) {
		const span = document.createElement('span');
		span.className = /[0-9]/.test(char) ? 'numero' : /[a-zA-Z]/.test(char) ? 'letra' : 'simbolo';
		span.textContent = char;
		generadorValor.appendChild(span);
	}
}

const ETIQUETA_FORTALEZA: Record<number, { texto: string; clase: string }> = {
	0: { texto: 'Muy débil', clase: 'debil' },
	1: { texto: 'Débil', clase: 'debil' },
	2: { texto: 'Media', clase: 'media' },
	3: { texto: 'Segura', clase: 'fuerte' },
	4: { texto: 'Muy segura', clase: 'fuerte' }
};

function regenerar(): void {
	passwordGenerada =
		modoGenerador === 'aleatoria'
			? generarPassword(Number(generadorLargo.value), reglasActuales())
			: generarFraseDePaso(opcionesFraseActuales());
	pintarPassword(passwordGenerada);
	const { score } = evaluarFortaleza(passwordGenerada);
	const etiqueta = ETIQUETA_FORTALEZA[score];
	generadorFortaleza.textContent = `${modoGenerador === 'aleatoria' ? 'Contraseña' : 'Frase'} · ${etiqueta.texto}`;
	generadorFortaleza.className = `generador-fortaleza ${etiqueta.clase}`;
}

function cambiarModoGenerador(nuevo: 'aleatoria' | 'frase'): void {
	modoGenerador = nuevo;
	tabModoAleatoria.classList.toggle('tab-vault-activo', nuevo === 'aleatoria');
	tabModoAleatoria.setAttribute('aria-selected', String(nuevo === 'aleatoria'));
	tabModoFrase.classList.toggle('tab-vault-activo', nuevo === 'frase');
	tabModoFrase.setAttribute('aria-selected', String(nuevo === 'frase'));
	controlesModoAleatoria.classList.toggle('oculto', nuevo !== 'aleatoria');
	controlesModoFrase.classList.toggle('oculto', nuevo !== 'frase');
	regenerar();
}
tabModoAleatoria.addEventListener('click', () => cambiarModoGenerador('aleatoria'));
tabModoFrase.addEventListener('click', () => cambiarModoGenerador('frase'));

function abrirGenerador(standalone: boolean): void {
	generadorOrigenStandalone = standalone;
	generadorLargoValor.textContent = generadorLargo.value;
	generadorCantidadPalabrasValor.textContent = generadorCantidadPalabras.value;
	cambiarModoGenerador('aleatoria');
	modalGenerador.classList.remove('oculto');
}

function cerrarGenerador(): void {
	modalGenerador.classList.add('oculto');
}

generadorLargo.addEventListener('input', () => {
	generadorLargoValor.textContent = generadorLargo.value;
	regenerar();
});
generadorMayus.addEventListener('change', regenerar);
generadorNumeros.addEventListener('change', regenerar);
generadorSimbolos.addEventListener('change', regenerar);
generadorSinAmbiguos.addEventListener('change', regenerar);
generadorCantidadPalabras.addEventListener('input', () => {
	generadorCantidadPalabrasValor.textContent = generadorCantidadPalabras.value;
	regenerar();
});
generadorFraseMayus.addEventListener('change', regenerar);
generadorFraseNumeros.addEventListener('change', regenerar);
generadorSeparador.addEventListener('change', regenerar);
botonRegenerar.addEventListener('click', regenerar);
botonCerrarGenerador.addEventListener('click', cerrarGenerador);
botonGeneradorHeader.addEventListener('click', () => abrirGenerador(true));
modalGenerador.addEventListener('click', (evento) => {
	if (evento.target === modalGenerador) cerrarGenerador(); // click en el backdrop, fuera de la tarjeta
});
document.addEventListener('keydown', (evento) => {
	if (evento.key === 'Escape' && !modalGenerador.classList.contains('oculto')) cerrarGenerador();
});

botonCopiarCerrarGenerador.addEventListener('click', async () => {
	// Abierto desde el ícono del header (spec 2026-08-15): no hay ningún
	// formulario detrás, sólo copia. Abierto desde el 🎲 del formulario de
	// recurso: comportamiento de siempre, también carga el campo.
	if (!generadorOrigenStandalone) {
		formPassword.value = passwordGenerada;
		formPassword.type = 'text';
		botonMostrarFormPassword.textContent = '🙈';
	}
	try {
		await navigator.clipboard.writeText(passwordGenerada);
	} catch {
		// portapapeles sin permiso — en el modo de formulario la contraseña
		// ya quedó cargada en el campo igual, no es un fallo bloqueante.
	}
	cerrarGenerador();
});

// --- Mi cuenta: sólo lo esencial (email/servidor) + salida real a los
// ajustes completos de la app web — Quick Access no reimplementa cambio de
// passphrase/avatar/MFA, eso sigue siendo trabajo de la app completa. ---
botonCuenta.addEventListener('click', () => {
	cuentaEmail.textContent = emailActual;
	cuentaServidor.textContent = servidorActual;
	cuentaAbrirWeb.href = `${servidorActual}/settings`;
	mostrarVista('cuenta');
});

botonVolverCuenta.addEventListener('click', () => {
	mostrarVista('desbloqueada');
});

async function cargarVault(): Promise<void> {
	ocultarError(vaultError);
	try {
		itemsVault = await cliente.request<ItemVault[]>('VAULT_LISTAR');
		renderizarLista(campoBuscar.value);
		// Auto-abre el primer ítem — mismo comportamiento que Proton Pass, sin
		// esto la columna derecha queda vacía hasta el primer clic.
		if (!itemDetalleActual && itemsVault.length > 0) abrirDetalle(itemsVault[0]);
	} catch (error) {
		mostrarError(vaultError, error instanceof Error ? error.message : 'No se pudo cargar la bóveda.');
	}
}

campoBuscar.addEventListener('input', () => renderizarLista(campoBuscar.value));

const tabTodos = document.getElementById('tab-todos') as HTMLButtonElement;
const tabReciente = document.getElementById('tab-reciente') as HTMLButtonElement;
function cambiarPestana(nueva: 'todos' | 'reciente'): void {
	pestanaActiva = nueva;
	tabTodos.classList.toggle('tab-vault-activo', nueva === 'todos');
	tabTodos.setAttribute('aria-selected', String(nueva === 'todos'));
	tabReciente.classList.toggle('tab-vault-activo', nueva === 'reciente');
	tabReciente.setAttribute('aria-selected', String(nueva === 'reciente'));
	renderizarLista(campoBuscar.value);
}
tabTodos.addEventListener('click', () => cambiarPestana('todos'));
tabReciente.addEventListener('click', () => cambiarPestana('reciente'));

/** Estado intermedio entre `login()` (devuelve `pendiente_dispositivo`) y
 * `verificarDispositivo()` — vive sólo en memoria del popup mientras el
 * usuario escribe el código; si cierra el popup antes de terminar, tiene
 * que volver a iniciar sesión (comportamiento esperado, no un bug). */
let servidorEnCurso = '';
let deviceChallengeIdEnCurso = '';

/** Mismo criterio para `pendiente_mfa` (2026-08-15) — la sesión PARCIAL que
 * hay que confirmar con `AUTH_VERIFICAR_MFA`. Se llega acá desde el login
 * normal (`vista-login`) o desde el desbloqueo tras un lock (`vista-
 * desbloqueo`) — mismo `estado` del backend en los dos casos, una sola
 * vista reusada. */
let sessionIdParcialEnCurso = '';
let emailEnCurso = '';

function mostrarError(el: HTMLElement, mensaje: string): void {
	el.textContent = mensaje;
	el.classList.remove('oculto');
}
function ocultarError(el: HTMLElement): void {
	el.classList.add('oculto');
}

const MENSAJE_POR_ESTADO_NO_SOPORTADO: Record<string, string> = {
	requiere_configurar_mfa: 'Esta organización exige configurar un segundo factor (MFA) — hacelo desde la web antes de usar la extensión.',
	requiere_cambiar_passphrase: 'Tu contraseña es provisoria y hay que cambiarla — hacelo desde la web antes de usar la extensión.'
};

function manejarResultadoLogin(resultado: ResultadoLogin, serverUrl: string, email: string): void {
	if (resultado.estado === 'completo') {
		mostrarSesionActiva(email, serverUrl);
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
	if (resultado.estado === 'pendiente_mfa' && resultado.sessionId) {
		servidorEnCurso = serverUrl;
		emailEnCurso = email;
		sessionIdParcialEnCurso = resultado.sessionId;
		campoMfaCodigo.value = '';
		ocultarError(errorMfa);
		mostrarVista('mfa');
		return;
	}
	const mensaje = MENSAJE_POR_ESTADO_NO_SOPORTADO[resultado.estado] ?? `Estado de login no manejado por la extensión todavía: "${resultado.estado}".`;
	mensajeNoSoportado.textContent = mensaje;
	mostrarVista('noSoportado');
}

function mostrarSesionActiva(email: string, serverUrl: string): void {
	emailActual = email;
	servidorActual = serverUrl;
	mostrarVista('desbloqueada');
	void cargarVault();
	// Se llegó a una sesión activa por cualquier camino (login normal,
	// desbloqueo tras inactividad/reinicio, o MFA) — si había una marca de
	// bloqueo por inactividad, ya no aplica. No-op si no había ninguna.
	void cliente.request('AUTH_LIMPIAR_MARCA_BLOQUEO');
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
		manejarResultadoLogin(resultado, serverUrl, email);
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

formMfa.addEventListener('submit', async (evento) => {
	evento.preventDefault();
	ocultarError(errorMfa);

	botonVerificarMfa.disabled = true;
	botonVerificarMfa.textContent = 'Verificando…';
	try {
		await cliente.request('AUTH_VERIFICAR_MFA', {
			serverUrl: servidorEnCurso,
			sessionIdParcial: sessionIdParcialEnCurso,
			codigo: campoMfaCodigo.value.trim()
		});
		mostrarSesionActiva(emailEnCurso, servidorEnCurso);
	} catch (error) {
		mostrarError(errorMfa, error instanceof Error ? error.message : 'Código incorrecto o vencido.');
	} finally {
		botonVerificarMfa.disabled = false;
		botonVerificarMfa.textContent = 'Verificar';
	}
});

/** Reglas de sesión inteligentes (2026-08-15): reinicio de navegador pide
 * sólo la Contraseña Master (`forceMfa: false` — si el dispositivo ya está
 * confiado, el servidor no vuelve a pedir MFA); un lock por >6h de
 * inactividad fuerza un código MFA real si la cuenta lo tiene configurado
 * (`forceMfa: true`, ver `backend/src/auth/service.rs::resolver_tras_f02`).
 * Servidor/email nunca se piden acá — ya vienen de `AUTH_ESTADO_CUENTA`. */
let cuentaBloqueadaPorInactividad = false;

formDesbloqueo.addEventListener('submit', async (evento) => {
	evento.preventDefault();
	ocultarError(errorDesbloqueo);

	const serverUrl = desbloqueoServidor.textContent ?? '';
	const email = desbloqueoEmail.textContent ?? '';
	const passphrase = campoDesbloqueoPassphrase.value;

	botonDesbloquear.disabled = true;
	botonDesbloquear.textContent = 'Desbloqueando…';
	try {
		const resultado = await cliente.request<ResultadoLogin>('AUTH_LOGIN', {
			serverUrl,
			email,
			passphrase,
			forceMfa: cuentaBloqueadaPorInactividad
		});
		campoDesbloqueoPassphrase.value = '';
		manejarResultadoLogin(resultado, serverUrl, email);
	} catch (error) {
		mostrarError(errorDesbloqueo, error instanceof Error ? error.message : 'No se pudo desbloquear.');
	} finally {
		botonDesbloquear.disabled = false;
		botonDesbloquear.textContent = 'Desbloquear';
	}
});

async function cerrarSesionYVolverALogin(): Promise<void> {
	try {
		await cliente.request('AUTH_LOGOUT');
	} finally {
		formLogin.reset();
		campoServidor.value = 'http://localhost:8080';
		itemsVault = [];
		campoBuscar.value = '';
		listaVault.innerHTML = '';
		ocultarError(vaultError);
		itemDetalleActual = null;
		secretoRevelado = null;
		mostrarVista('login');
	}
}

botonLogout.addEventListener('click', async () => {
	botonLogout.disabled = true;
	try {
		await cerrarSesionYVolverALogin();
	} finally {
		botonLogout.disabled = false;
	}
});

// "Usar otra cuenta" desde la pantalla de desbloqueo (spec 2026-08-15) —
// equivale a un cierre de sesión explícito: purga servidor/email/token de
// dispositivo persistidos, porque el usuario está eligiendo activamente
// entrar con una cuenta distinta, no reanudar la actual.
botonOtraCuenta.addEventListener('click', async () => {
	botonOtraCuenta.disabled = true;
	try {
		await cerrarSesionYVolverALogin();
	} finally {
		botonOtraCuenta.disabled = false;
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

// --- Estado inicial: ¿ya hay una sesión activa, quedó una verificación de
// dispositivo a mitad de camino, o hay una cuenta persistida esperando
// desbloqueo (sesión inteligente, 2026-08-15)? El popup se cierra solo al
// perder el foco (ej. cambiar de pestaña para leer el código del email) —
// sin este chequeo, reabrirlo forzaba a repetir flujos enteros aunque el
// estado siguiera vigente (bug real reportado por el usuario, para el caso
// de dispositivo). ---
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

		const cuenta = await cliente.request<{ serverUrl: string; email: string; lockedPorInactividad: boolean } | null>(
			'AUTH_ESTADO_CUENTA'
		);
		if (cuenta) {
			cuentaBloqueadaPorInactividad = cuenta.lockedPorInactividad;
			desbloqueoEmail.textContent = cuenta.email;
			desbloqueoServidor.textContent = cuenta.serverUrl;
			campoDesbloqueoPassphrase.value = '';
			ocultarError(errorDesbloqueo);
			mostrarVista('desbloqueo');
			return;
		}

		mostrarVista('login');
	} catch {
		// Sin sesión/desafío/cuenta previa legible (o el service worker recién
		// está arrancando) — arrancar igual desde el login es la salida segura.
		mostrarVista('login');
	}
})();
