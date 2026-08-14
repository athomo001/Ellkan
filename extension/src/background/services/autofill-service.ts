// Autor: Athan Espinoza

// Autofill (spec 06 §4.2): el matching corre acá, en el service worker, no
// en el content script — el content script sólo manda el hostname de la
// pestaña activa y recibe ya resuelta la lista de coincidencias (nunca la
// bóveda completa, que sí viaja para Quick Access porque el popup ES una
// superficie de confianza de la extensión; un content script vive inyectado
// en la página anfitriona, superficie mucho menos confiable).
//
// Estrategia de matching implementada: sólo `host` (mismo hostname exacto,
// cualquier path) — es el único caso que no depende de una librería de
// Public Suffix List con tests dedicados contra dominios multi-tenant
// (`exact`/`base_domain`, hallazgo real BWN-08-020 en Bitwarden, spec 06
// §4.2/05 sección 2.2) — implementar esas dos estrategias sin esa
// verificación repetiría el mismo bug real que ya está documentado como
// hallazgo. `never` tampoco existe todavía (necesitaría una preferencia por
// recurso que hoy no existe en el modelo de datos). Subir cuando el uso
// real lo pida.

import { VaultService } from './vault-service';

export interface CoincidenciaAutofill {
	id: string;
	nombre: string;
	usuario: string;
	/** El content script la necesita para el chequeo anti-downgrade HTTPS→HTTP
	 * (spec 06 §4.3, punto 2) — comparar el esquema guardado contra el de la
	 * página activa en el momento exacto del fill. */
	uri: string;
}

export function hostnameDeUri(uri: string): string | null {
	if (!uri) return null;
	try {
		const conEsquema = /^[a-z]+:\/\//i.test(uri) ? uri : `https://${uri}`;
		return new URL(conEsquema).hostname.toLowerCase();
	} catch {
		return null;
	}
}

export const AutofillService = {
	async buscarCoincidencias(hostname: string): Promise<CoincidenciaAutofill[]> {
		const items = await VaultService.listar();
		const host = hostname.toLowerCase();
		return items
			.filter((i) => i.resourceTypeSlug === 'login-password') // SSH/FTP/VNC/Telnet no tienen sentido para un form web
			.filter((i) => hostnameDeUri(i.uri) === host)
			.map((i) => ({ id: i.id, nombre: i.nombre, usuario: i.usuario, uri: i.uri }));
	}
};
