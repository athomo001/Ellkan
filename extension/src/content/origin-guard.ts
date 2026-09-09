// Autor: Athan Espinoza

// Revalidación de origen en el momento exacto del fill (spec 06 §4.3.1,
// hallazgo real BWN-08-011, Medium, Cure53 2023 en Bitwarden): el chequeo de
// que la pestaña/frame sigue siendo el MISMO origen para el que se pidieron
// las credenciales tiene que hacerse como última operación antes de escribir
// en el DOM, no sólo como precondición río arriba cuando se abrió el menú.
// Una navegación de por medio (típico de una SPA cambiando de ruta, o un
// redirect) entre "pedí las coincidencias" y "el usuario hizo click en una"
// permitió en Bitwarden filtrar credenciales a un origen distinto.
//
// Se compara el ORIGEN completo (esquema + host + puerto), no sólo el
// hostname: un cambio http→https, o a otro puerto, también es un cambio de
// origen y también aborta. Falla cerrado: si alguno de los dos href no
// parsea, no se rellena.

/** `true` sólo si `hrefActual` tiene exactamente el mismo origen que
 * `origenPedido` (que es el `location.origin` capturado cuando se pidieron
 * las coincidencias). */
export function mismoOrigenParaFill(origenPedido: string, hrefActual: string): boolean {
	if (!origenPedido || !hrefActual) return false;
	let actual: string;
	try {
		actual = new URL(hrefActual).origin;
	} catch {
		return false;
	}
	// `origenPedido` ya es un `location.origin` (string canónico) — comparación
	// directa, sin re-parsear (re-parsear un origin como URL puede fallar para
	// esquemas opacos tipo `null`).
	return actual === origenPedido && origenPedido !== 'null';
}
