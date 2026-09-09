// Autor: Athan Espinoza

// Estrategias de matching URI↔recurso para autofill (spec 06 §4.2, spec 05
// §2.2). Cuatro modos, configurables por recurso (se guardan en la metadata
// cifrada del recurso, campo `matching` — el servidor nunca lo ve):
//
//   - `exact`       — origen + path exactos (ignora query/hash y la barra
//                     final). El más estricto: sirve para un recurso atado a
//                     una ruta de login puntual.
//   - `host`        — mismo hostname y puerto, cualquier path. Es el default
//                     (comportamiento histórico) y el razonable para la
//                     mayoría de los sitios.
//   - `base_domain` — mismo dominio registrable (eTLD+1) resuelto contra la
//                     Public Suffix List real. `app.ejemplo.com` matchea
//                     `www.ejemplo.com`, pero `a.github.io` NUNCA matchea
//                     `b.github.io` (hallazgo real BWN-08-020, Cure53 2023 en
//                     Bitwarden: tratar `*.github.io` como un solo dominio
//                     autocompletaba credenciales de un usuario de GitHub
//                     Pages en el sitio de cualquier otro). Por eso se usa
//                     `tldts` con `allowPrivateDomains: true` — sin esa
//                     opción, la sección PRIVATE de la PSL (`github.io`,
//                     `vercel.app`, …) se ignora y volvés a tener el bug.
//   - `never`       — nunca ofrece autofill para este recurso (lo tenés
//                     guardado pero no querés que se sugiera en ninguna
//                     página).
//
// El test dedicado contra dominios multi-tenant reales que exige spec 05
// §2.2 vive en `extension/self-check.ts` (sección de `uri-match`).

import { getDomain } from 'tldts';

// El tipo, la lista y `normalizarEstrategia` se comparten con el frontend web
// (mismo criterio que `b64`/`uuid`/`passwordGenerator`) — sólo la evaluación
// con PSL (`coincideUri` y sus helpers) vive acá, porque `tldts` sólo tiene
// sentido en la extensión.
export {
	type EstrategiaMatch,
	ESTRATEGIAS_MATCH,
	ESTRATEGIA_MATCH_DEFAULT,
	normalizarEstrategia
} from '../../../../frontend/src/lib/crypto/matching';
import type { EstrategiaMatch } from '../../../../frontend/src/lib/crypto/matching';

interface PartesUri {
	hostname: string;
	/** `''` si la URL no trae puerto explícito. */
	port: string;
	/** Sin barra final (salvo que el path sea sólo `/`). */
	pathNormalizado: string;
}

/** Parte una URI guardada o el `href` de una página en las piezas que las
 * estrategias comparan. Una URI sin esquema se asume `https://` (mismo
 * criterio que `conexion.ts::urlAbrible` y el chequeo anti-downgrade del
 * content script). `null` si no parsea. */
export function partesDeUri(uri: string): PartesUri | null {
	if (!uri) return null;
	try {
		// Esquema RFC 3986 acotado (evita backtracking): letra + hasta 31 de
		// [a-z0-9+.-], seguido de `://`.
		const conEsquema = /^[a-z][a-z0-9+.-]{0,31}:\/\//i.test(uri) ? uri : `https://${uri}`;
		const u = new URL(conEsquema);
		const path = u.pathname.length > 1 ? u.pathname.replace(/\/+$/, '') : u.pathname;
		return { hostname: u.hostname.toLowerCase(), port: u.port, pathNormalizado: path };
	} catch {
		return null;
	}
}

/** Dominio registrable (eTLD+1) con la sección PRIVATE de la PSL activada —
 * ver la nota de cabecera sobre BWN-08-020. `null` para IPs, `localhost`, un
 * sufijo público a secas, o cualquier cosa que `tldts` no resuelva. */
export function dominioRegistrable(hostname: string): string | null {
	return getDomain(hostname, { allowPrivateDomains: true });
}

/**
 * ¿El recurso guardado en `uriGuardada` debe ofrecerse como autofill para la
 * página `paginaHref`, según `estrategia`?
 *
 * `paginaHref` es el `window.location.href` real de la pestaña/frame activo
 * (lo manda el content script). Nunca se widening: ante cualquier ambigüedad
 * de la PSL, `base_domain` cae a comparación estricta de hostname.
 */
export function coincideUri(estrategia: EstrategiaMatch, uriGuardada: string, paginaHref: string): boolean {
	if (estrategia === 'never') return false;

	const guardada = partesDeUri(uriGuardada);
	const pagina = partesDeUri(paginaHref);
	if (!guardada || !pagina) return false;

	switch (estrategia) {
		case 'exact':
			return (
				guardada.hostname === pagina.hostname &&
				guardada.port === pagina.port &&
				guardada.pathNormalizado === pagina.pathNormalizado
			);
		case 'host':
			return guardada.hostname === pagina.hostname && guardada.port === pagina.port;
		case 'base_domain': {
			const dg = dominioRegistrable(guardada.hostname);
			const dp = dominioRegistrable(pagina.hostname);
			// Si la PSL no resuelve alguno de los dos (IP, localhost, sufijo
			// público solo), no se arriesga a ampliar: hostname exacto.
			if (!dg || !dp) return guardada.hostname === pagina.hostname;
			return dg === dp;
		}
	}
}
