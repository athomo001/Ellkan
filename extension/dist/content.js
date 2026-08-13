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
	new PortClient("WebIntegration").request("PING").then((respuesta) => {
		console.debug("[ellkan] mensajería background↔content OK", respuesta);
	}).catch((error) => {
		console.error("[ellkan] fallo el round-trip de mensajería", error);
	});
	//#endregion
})();
