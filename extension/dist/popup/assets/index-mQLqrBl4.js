//#region \0vite/modulepreload-polyfill.js
(function polyfill() {
	const relList = document.createElement("link").relList;
	if (relList && relList.supports && relList.supports("modulepreload")) return;
	for (const link of document.querySelectorAll("link[rel=\"modulepreload\"]")) processPreload(link);
	new MutationObserver((mutations) => {
		for (const mutation of mutations) {
			if (mutation.type !== "childList") continue;
			for (const node of mutation.addedNodes) if (node.tagName === "LINK" && node.rel === "modulepreload") processPreload(node);
		}
	}).observe(document, {
		childList: true,
		subtree: true
	});
	function getFetchOpts(link) {
		const fetchOpts = {};
		if (link.integrity) fetchOpts.integrity = link.integrity;
		if (link.referrerPolicy) fetchOpts.referrerPolicy = link.referrerPolicy;
		if (link.crossOrigin === "use-credentials") fetchOpts.credentials = "include";
		else if (link.crossOrigin === "anonymous") fetchOpts.credentials = "omit";
		else fetchOpts.credentials = "same-origin";
		return fetchOpts;
	}
	function processPreload(link) {
		if (link.ep) return;
		link.ep = true;
		const fetchOpts = getFetchOpts(link);
		fetch(link.href, fetchOpts);
	}
})();
//#endregion
//#region src/shared/port-client.ts
var MAX_REINTENTOS_RECONEXION = 50;
var INTERVALO_REINTENTO_MS = 100;
var PortClient = class {
	nombre;
	port = null;
	workerId = crypto.randomUUID();
	pendientes = /* @__PURE__ */ new Map();
	listo = null;
	constructor(nombre) {
		this.nombre = nombre;
	}
	async conectar() {
		if (this.listo) return this.listo;
		this.listo = this.abrirYHandshake();
		return this.listo;
	}
	abrirYHandshake() {
		return new Promise((resolve, reject) => {
			const port = chrome.runtime.connect({ name: this.workerId });
			this.port = port;
			const timeout = setTimeout(() => reject(/* @__PURE__ */ new Error("timeout esperando ellkan.port.ready")), 500);
			port.onMessage.addListener((mensaje) => {
				if (Array.isArray(mensaje) && mensaje[0] === "ellkan.port.ready") {
					clearTimeout(timeout);
					resolve();
					return;
				}
				if (Array.isArray(mensaje) && mensaje[0] === "ellkan.port.connect") {
					this.reconectarConReintentos();
					return;
				}
				this.despacharRespuesta(mensaje);
			});
			port.onDisconnect.addListener(() => {
				this.port = null;
				this.listo = null;
			});
			const handshake = {
				requestId: crypto.randomUUID(),
				tipo: "HANDSHAKE",
				payload: { name: this.nombre }
			};
			port.postMessage(handshake);
		});
	}
	async reconectarConReintentos() {
		for (let intento = 0; intento < MAX_REINTENTOS_RECONEXION; intento++) try {
			this.listo = null;
			await this.conectar();
			return;
		} catch {
			await new Promise((r) => setTimeout(r, INTERVALO_REINTENTO_MS));
		}
	}
	despacharRespuesta(mensaje) {
		if (!Array.isArray(mensaje) || mensaje.length < 2) return;
		const [requestId, estado] = mensaje;
		const pendiente = this.pendientes.get(requestId);
		if (!pendiente) return;
		this.pendientes.delete(requestId);
		if (estado === "SUCCESS") pendiente.resolve(mensaje[2]);
		else pendiente.reject(new Error(typeof mensaje[2] === "string" ? mensaje[2] : "error desconocido"));
	}
	async request(tipo, payload) {
		await this.conectar();
		const requestId = crypto.randomUUID();
		const mensaje = {
			requestId,
			tipo,
			payload
		};
		return new Promise((resolve, reject) => {
			this.pendientes.set(requestId, {
				resolve,
				reject
			});
			this.port.postMessage(mensaje);
		});
	}
};
//#endregion
//#region src/popup/main.ts
var cliente = new PortClient("QuickAccess");
var vistas = {
	cargando: document.getElementById("vista-cargando"),
	login: document.getElementById("vista-login"),
	dispositivo: document.getElementById("vista-dispositivo"),
	desbloqueada: document.getElementById("vista-desbloqueada"),
	noSoportado: document.getElementById("vista-no-soportado")
};
function mostrarVista(nombre) {
	for (const [clave, el] of Object.entries(vistas)) el.classList.toggle("oculto", clave !== nombre);
}
var formLogin = document.getElementById("form-login");
var campoServidor = document.getElementById("campo-servidor");
var campoEmail = document.getElementById("campo-email");
var campoPassphrase = document.getElementById("campo-passphrase");
var botonMostrarPassphrase = document.getElementById("boton-mostrar-passphrase");
var errorLogin = document.getElementById("error-login");
var botonLogin = document.getElementById("boton-login");
botonMostrarPassphrase.addEventListener("click", () => {
	const oculto = campoPassphrase.type === "password";
	campoPassphrase.type = oculto ? "text" : "password";
	botonMostrarPassphrase.textContent = oculto ? "🙈" : "👁";
	botonMostrarPassphrase.setAttribute("aria-label", oculto ? "Ocultar contraseña" : "Mostrar contraseña");
});
var formDispositivo = document.getElementById("form-dispositivo");
var campoCodigo = document.getElementById("campo-codigo");
var errorDispositivo = document.getElementById("error-dispositivo");
var botonVerificar = document.getElementById("boton-verificar");
var botonCancelarDispositivo = document.getElementById("boton-cancelar-dispositivo");
var tarjetaSesion = document.querySelector(".tarjeta-sesion-compacta");
var emailActivo = document.getElementById("email-activo");
var botonLogout = document.getElementById("boton-logout");
var campoBuscar = document.getElementById("campo-buscar");
var listaVault = document.getElementById("lista-vault");
var vaultVacio = document.getElementById("vault-vacio");
var vaultError = document.getElementById("vault-error");
var mensajeNoSoportado = document.getElementById("mensaje-no-soportado");
var botonVolver = document.getElementById("boton-volver");
var ICONO_POR_TIPO = {
	"login-password": "🔑",
	ssh: "💻",
	ftp: "📁",
	vnc: "🖥️",
	telnet: "📟"
};
var itemsVault = [];
function renderizarLista(filtro) {
	listaVault.innerHTML = "";
	vaultVacio.classList.toggle("oculto", itemsVault.length > 0);
	if (itemsVault.length === 0) return;
	const q = filtro.trim().toLowerCase();
	const filtrados = q ? itemsVault.filter((i) => i.nombre.toLowerCase().includes(q) || i.usuario.toLowerCase().includes(q) || i.uri.toLowerCase().includes(q)) : itemsVault;
	if (filtrados.length === 0) {
		const p = document.createElement("p");
		p.className = "texto-secundario";
		p.textContent = "Sin resultados para esa búsqueda.";
		listaVault.appendChild(p);
		return;
	}
	for (const item of filtrados) {
		const fila = document.createElement("div");
		fila.className = "item-vault";
		const icono = document.createElement("span");
		icono.className = "item-vault-icono";
		icono.textContent = ICONO_POR_TIPO[item.resourceTypeSlug] ?? "🔒";
		icono.setAttribute("aria-hidden", "true");
		const info = document.createElement("div");
		info.className = "item-vault-info";
		const nombre = document.createElement("p");
		nombre.className = "item-vault-nombre";
		nombre.textContent = item.nombre || "(sin nombre)";
		const usuario = document.createElement("p");
		usuario.className = "item-vault-usuario";
		usuario.textContent = item.usuario || item.uri || "";
		info.append(nombre, usuario);
		const botonCopiar = document.createElement("button");
		botonCopiar.type = "button";
		botonCopiar.className = "item-vault-copiar";
		botonCopiar.textContent = "📋";
		botonCopiar.setAttribute("aria-label", `Copiar contraseña de ${item.nombre || "este recurso"}`);
		botonCopiar.addEventListener("click", () => copiarPassword(item, botonCopiar));
		fila.append(icono, info, botonCopiar);
		listaVault.appendChild(fila);
	}
}
async function copiarPassword(item, boton) {
	boton.disabled = true;
	try {
		const resultado = await cliente.request("VAULT_REVELAR_PASSWORD", { resourceId: item.id });
		await navigator.clipboard.writeText(resultado.password);
		boton.textContent = "✅";
	} catch {
		boton.textContent = "⚠";
	} finally {
		setTimeout(() => {
			boton.textContent = "📋";
			boton.disabled = false;
		}, 1200);
	}
}
async function cargarVault() {
	ocultarError(vaultError);
	try {
		itemsVault = await cliente.request("VAULT_LISTAR");
		renderizarLista(campoBuscar.value);
	} catch (error) {
		mostrarError(vaultError, error instanceof Error ? error.message : "No se pudo cargar la bóveda.");
	}
}
campoBuscar.addEventListener("input", () => renderizarLista(campoBuscar.value));
/** Estado intermedio entre `login()` (devuelve `pendiente_dispositivo`) y
* `verificarDispositivo()` — vive sólo en memoria del popup mientras el
* usuario escribe el código; si cierra el popup antes de terminar, tiene
* que volver a iniciar sesión (comportamiento esperado, no un bug). */
var servidorEnCurso = "";
var deviceChallengeIdEnCurso = "";
function mostrarError(el, mensaje) {
	el.textContent = mensaje;
	el.classList.remove("oculto");
}
function ocultarError(el) {
	el.classList.add("oculto");
}
var MENSAJE_POR_ESTADO_NO_SOPORTADO = {
	pendiente_mfa: "Esta cuenta tiene un segundo factor (MFA) configurado — completá el login desde la web por ahora.",
	requiere_configurar_mfa: "Esta organización exige configurar un segundo factor (MFA) — hacelo desde la web antes de usar la extensión.",
	requiere_cambiar_passphrase: "Tu contraseña es provisoria y hay que cambiarla — hacelo desde la web antes de usar la extensión."
};
function manejarResultadoLogin(resultado, serverUrl) {
	if (resultado.estado === "completo") {
		mostrarSesionActiva(campoEmail.value, serverUrl);
		return;
	}
	if (resultado.estado === "pendiente_dispositivo" && resultado.deviceChallengeId) {
		servidorEnCurso = serverUrl;
		deviceChallengeIdEnCurso = resultado.deviceChallengeId;
		campoCodigo.value = "";
		ocultarError(errorDispositivo);
		mostrarVista("dispositivo");
		return;
	}
	mensajeNoSoportado.textContent = MENSAJE_POR_ESTADO_NO_SOPORTADO[resultado.estado] ?? `Estado de login no manejado por la extensión todavía: "${resultado.estado}".`;
	mostrarVista("noSoportado");
}
function mostrarSesionActiva(email, serverUrl) {
	emailActivo.textContent = email;
	tarjetaSesion.title = `${email} — ${serverUrl}`;
	mostrarVista("desbloqueada");
	cargarVault();
}
formLogin.addEventListener("submit", async (evento) => {
	evento.preventDefault();
	ocultarError(errorLogin);
	const serverUrl = campoServidor.value.trim();
	const email = campoEmail.value.trim();
	const passphrase = campoPassphrase.value;
	botonLogin.disabled = true;
	botonLogin.textContent = "Iniciando sesión…";
	try {
		manejarResultadoLogin(await cliente.request("AUTH_LOGIN", {
			serverUrl,
			email,
			passphrase
		}), serverUrl);
	} catch (error) {
		mostrarError(errorLogin, error instanceof Error ? error.message : "No se pudo iniciar sesión.");
	} finally {
		botonLogin.disabled = false;
		botonLogin.textContent = "Iniciar sesión";
	}
});
formDispositivo.addEventListener("submit", async (evento) => {
	evento.preventDefault();
	ocultarError(errorDispositivo);
	botonVerificar.disabled = true;
	botonVerificar.textContent = "Verificando…";
	try {
		const resultado = await cliente.request("AUTH_VERIFICAR_DISPOSITIVO", {
			serverUrl: servidorEnCurso,
			deviceChallengeId: deviceChallengeIdEnCurso,
			codigo: campoCodigo.value.trim()
		});
		if (resultado.estado === "completo") mostrarSesionActiva(campoEmail.value.trim(), servidorEnCurso);
		else {
			mensajeNoSoportado.textContent = MENSAJE_POR_ESTADO_NO_SOPORTADO[resultado.estado] ?? `Estado no manejado por la extensión todavía: "${resultado.estado}".`;
			mostrarVista("noSoportado");
		}
	} catch (error) {
		mostrarError(errorDispositivo, error instanceof Error ? error.message : "Código incorrecto o vencido.");
	} finally {
		botonVerificar.disabled = false;
		botonVerificar.textContent = "Verificar";
	}
});
botonLogout.addEventListener("click", async () => {
	botonLogout.disabled = true;
	try {
		await cliente.request("AUTH_LOGOUT");
	} finally {
		botonLogout.disabled = false;
		formLogin.reset();
		campoServidor.value = "http://localhost:8080";
		itemsVault = [];
		campoBuscar.value = "";
		listaVault.innerHTML = "";
		ocultarError(vaultError);
		mostrarVista("login");
	}
});
botonVolver.addEventListener("click", () => {
	mostrarVista("login");
});
botonCancelarDispositivo.addEventListener("click", async () => {
	botonCancelarDispositivo.disabled = true;
	try {
		await cliente.request("AUTH_CANCELAR_PENDIENTE_DISPOSITIVO");
	} finally {
		botonCancelarDispositivo.disabled = false;
		formLogin.reset();
		campoServidor.value = "http://localhost:8080";
		mostrarVista("login");
	}
});
(async () => {
	try {
		const sesion = await cliente.request("AUTH_ESTADO_SESION");
		if (sesion) {
			mostrarSesionActiva(sesion.email, sesion.serverUrl);
			return;
		}
		const pendiente = await cliente.request("AUTH_ESTADO_PENDIENTE_DISPOSITIVO");
		if (pendiente) {
			servidorEnCurso = pendiente.serverUrl;
			deviceChallengeIdEnCurso = pendiente.deviceChallengeId;
			campoServidor.value = pendiente.serverUrl;
			campoEmail.value = pendiente.email;
			campoCodigo.value = "";
			ocultarError(errorDispositivo);
			mostrarVista("dispositivo");
			return;
		}
		mostrarVista("login");
	} catch {
		mostrarVista("login");
	}
})();
//#endregion
