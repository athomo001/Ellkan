// Autor: Athan Espinoza

// Autofill (spec 06 §4.2): el matching corre acá, en el service worker, no
// en el content script — el content script sólo manda el `href` de la
// pestaña/frame activo y recibe ya resuelta la lista de coincidencias (nunca
// la bóveda completa, que sí viaja para Quick Access porque el popup ES una
// superficie de confianza de la extensión; un content script vive inyectado
// en la página anfitriona, superficie mucho menos confiable).
//
// Las cuatro estrategias de matching (`exact`/`host`/`base_domain`/`never`)
// se configuran por recurso y viven en `uri-match.ts` — `base_domain` usa la
// Public Suffix List real (`tldts`) para no repetir el hallazgo BWN-08-020.
// El default de un recurso sin `matching` en su metadata es `host` (mismo
// comportamiento que antes de agregar las estrategias).

import { VaultService } from './vault-service';
import { coincideUri, partesDeUri } from './uri-match';

export interface CoincidenciaAutofill {
	id: string;
	nombre: string;
	usuario: string;
	/** El content script la necesita para el chequeo anti-downgrade HTTPS→HTTP
	 * (spec 06 §4.3, punto 2) — comparar el esquema guardado contra el de la
	 * página activa en el momento exacto del fill. */
	uri: string;
}

/** Hostname en minúsculas de una URI (sin esquema se asume https). `null` si
 * no parsea. Se mantiene exportada porque `self-check.ts` y otros consumidores
 * la usan como helper de bajo nivel. */
export function hostnameDeUri(uri: string): string | null {
	return partesDeUri(uri)?.hostname ?? null;
}

export const AutofillService = {
	/**
	 * @param paginaHref `window.location.href` real del frame que pidió — se
	 * usa tal cual para las 4 estrategias (incluye path, que `exact` compara).
	 */
	async buscarCoincidencias(paginaHref: string): Promise<CoincidenciaAutofill[]> {
		const items = await VaultService.listar();
		return items
			.filter((i) => i.resourceTypeSlug === 'login-password' || i.resourceTypeSlug === 'login-password-totp')
			.filter((i) => coincideUri(i.matching, i.uri, paginaHref))
			.map((i) => ({ id: i.id, nombre: i.nombre, usuario: i.usuario, uri: i.uri }));
	}
};
