// Autor: Athan Espinoza

// Estrategia de matching URI↔recurso para el autofill de la extensión (spec
// 06 §4.2, spec 05 §2.2). Vive en `crypto/` porque se guarda DENTRO de la
// metadata cifrada del recurso (el servidor nunca la ve) y la comparten el
// frontend web (que la deja elegir y persistir) y la extensión (que además
// la evalúa — la lógica de comparación real, con Public Suffix List, está en
// `extension/src/background/services/uri-match.ts`, que importa este mismo
// tipo).
//
//   - `exact`       origen + path exactos
//   - `host`        mismo hostname y puerto, cualquier path (DEFAULT)
//   - `base_domain` mismo dominio registrable (eTLD+1) vía PSL real
//   - `never`       nunca ofrecer autofill para este recurso

export type EstrategiaMatch = 'exact' | 'host' | 'base_domain' | 'never';

export const ESTRATEGIAS_MATCH = ['exact', 'host', 'base_domain', 'never'] as const;

/** Recursos sin `matching` en su metadata (todos los creados antes de esta
 * feature) se comportan como `host` — el comportamiento histórico. */
export const ESTRATEGIA_MATCH_DEFAULT: EstrategiaMatch = 'host';

/** Acota cualquier valor entrante (la metadata de un recurso es JSON libre
 * client-side) a una estrategia válida — nunca confía en el string crudo. */
export function normalizarEstrategia(valor: unknown): EstrategiaMatch {
	return (ESTRATEGIAS_MATCH as readonly string[]).includes(valor as string)
		? (valor as EstrategiaMatch)
		: ESTRATEGIA_MATCH_DEFAULT;
}
