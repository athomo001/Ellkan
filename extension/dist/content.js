(function() {
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
	//#region src/content/index.ts
	var cliente = new PortClient("WebIntegration");
	var CAMPOS_USUARIO_VALIDOS = /* @__PURE__ */ new Set([
		"text",
		"email",
		"tel"
	]);
	var yaProcesados = /* @__PURE__ */ new WeakSet();
	var menuActual = null;
	/** El input de usuario más probable: el último input de texto/email/tel que
	* aparece ANTES del password field en el DOM, dentro del mismo `<form>` si
	* existe (si el campo no está en ningún form, se busca en todo el
	* documento) — heurística simple, no la detección exhaustiva por
	* `MutationObserver`+`IntersectionObserver`+shadow/iframe que describe spec
	* 06 §4.1 completo (esa es la próxima vuelta de esta misma sección; ver
	* `ponytail:` abajo). */
	function campoUsuarioPara(passwordField) {
		const contenedor = passwordField.form ?? document;
		const inputs = Array.from(contenedor.querySelectorAll("input"));
		const idx = inputs.indexOf(passwordField);
		for (let i = idx - 1; i >= 0; i--) if (CAMPOS_USUARIO_VALIDOS.has((inputs[i].type || "text").toLowerCase())) return inputs[i];
		return null;
	}
	function cerrarMenu() {
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
	function escribirValor(input, valor) {
		const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
		if (setter) setter.call(input, valor);
		else input.value = valor;
		input.dispatchEvent(new Event("input", { bubbles: true }));
		input.dispatchEvent(new Event("change", { bubbles: true }));
	}
	async function rellenar(coincidencia, usuarioField, passwordField, hostnameEnQuePidio) {
		cerrarMenu();
		if (window.location.hostname.toLowerCase() !== hostnameEnQuePidio) return;
		if (!/^http:\/\//i.test(coincidencia.uri) && window.location.protocol === "http:") {
			if (!window.confirm(`"${coincidencia.nombre}" se guardó para un sitio HTTPS, pero esta página es HTTP (sin cifrar). ¿Completar igual?`)) return;
		}
		try {
			const secreto = await cliente.request("VAULT_REVELAR_SECRETO", { resourceId: coincidencia.id });
			if (usuarioField) escribirValor(usuarioField, coincidencia.usuario);
			escribirValor(passwordField, secreto.password);
		} catch {}
	}
	var PALETA = {
		fondo: "#16314a",
		borde: "#1f3f5c",
		texto: "#e6edf3",
		textoSecundario: "#9db2c4",
		teal: "#187890"
	};
	function crearMenu(passwordField, usuarioField, coincidencias, hostnameEnQuePidio) {
		cerrarMenu();
		const host = document.createElement("div");
		const rect = passwordField.getBoundingClientRect();
		host.style.position = "absolute";
		host.style.left = `${rect.left + window.scrollX}px`;
		host.style.top = `${rect.bottom + window.scrollY + 4}px`;
		host.style.width = `${Math.max(rect.width, 220)}px`;
		host.style.zIndex = "2147483647";
		document.documentElement.appendChild(host);
		const shadow = host.attachShadow({ mode: "closed" });
		const estilo = document.createElement("style");
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
		const menu = document.createElement("div");
		menu.className = "menu";
		for (const c of coincidencias) {
			const item = document.createElement("button");
			item.type = "button";
			item.className = "item";
			const nombre = document.createElement("div");
			nombre.className = "nombre";
			nombre.textContent = c.nombre || "(sin nombre)";
			const usuario = document.createElement("div");
			usuario.className = "usuario";
			usuario.textContent = c.usuario;
			item.append(nombre, usuario);
			item.addEventListener("mousedown", (evento) => {
				evento.preventDefault();
				rellenar(c, usuarioField, passwordField, hostnameEnQuePidio);
			});
			menu.appendChild(item);
		}
		shadow.appendChild(menu);
		menuActual = {
			host,
			passwordField,
			hostnameEnQuePidio
		};
	}
	async function ofrecerAutofill(passwordField) {
		const hostname = window.location.hostname.toLowerCase();
		try {
			const coincidencias = await cliente.request("AUTOFILL_BUSCAR", { hostname });
			if (coincidencias.length === 0) return;
			if (document.activeElement !== passwordField) return;
			crearMenu(passwordField, campoUsuarioPara(passwordField), coincidencias, hostname);
		} catch {}
	}
	function procesarCampo(input) {
		if (yaProcesados.has(input)) return;
		if ((input.type || "").toLowerCase() !== "password") return;
		yaProcesados.add(input);
		input.addEventListener("focus", () => void ofrecerAutofill(input));
	}
	function escanear(raiz) {
		for (const input of raiz.querySelectorAll("input[type=\"password\"]")) procesarCampo(input);
	}
	escanear(document);
	new MutationObserver((mutaciones) => {
		for (const mutacion of mutaciones) for (const nodo of mutacion.addedNodes) {
			if (!(nodo instanceof HTMLElement)) continue;
			if (nodo.matches("input[type=\"password\"]")) procesarCampo(nodo);
			escanear(nodo);
		}
	}).observe(document.documentElement, {
		childList: true,
		subtree: true
	});
	document.addEventListener("pointerdown", (evento) => {
		if (!menuActual) return;
		const objetivo = evento.target;
		if (objetivo === menuActual.host || menuActual.host.contains(objetivo) || objetivo === menuActual.passwordField) return;
		cerrarMenu();
	}, true);
	document.addEventListener("keydown", (evento) => {
		if (evento.key === "Escape") cerrarMenu();
	});
	//#endregion
})();
