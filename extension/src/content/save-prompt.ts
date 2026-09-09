// Autor: Athan Espinoza

// Notification bar "¿guardar esta credencial?" (spec 06 §5) — la decisión de
// SI ofrecer guardar, como lógica pura (el DOM y la barra en sí viven en
// `content/index.ts`, dentro de un shadow root cerrado SIN iframe, misma
// mitigación de BWN-08-019 que el menú de autofill).
//
// MVP deliberado: se ofrece guardar SÓLO cuando es una credencial nueva para
// el sitio (no hay ninguna entrada en la bóveda con ese mismo usuario para
// ese hostname). No se ofrece "actualizar contraseña" todavía: sin revelar
// la guardada no se puede saber si cambió, y ofrecerlo en cada login sería
// un nag. Queda anotado como próxima vuelta.

export interface CredencialCapturada {
	/** Valor del campo de usuario en el momento del submit (`''` si no había
	 * campo de usuario en el par). */
	usuario: string;
	/** Valor del campo de contraseña en el submit. */
	password: string;
}

/** Coincidencia de autofill ya resuelta por el background para el `href`
 * actual — sólo interesa `usuario` para decidir si esto ya está guardado. */
export interface CoincidenciaConocida {
	usuario: string;
}

export interface DecisionGuardado {
	ofrecer: boolean;
	/** `'nuevo'` = crear un recurso; `null` = no ofrecer nada. */
	modo: 'nuevo' | null;
}

function norm(s: string): string {
	return s.trim().toLowerCase();
}

export function decidirGuardado(cap: CredencialCapturada, coincidencias: CoincidenciaConocida[]): DecisionGuardado {
	// Sin contraseña no hay nada que guardar (un submit de "olvidé mi
	// contraseña", un form de sólo-usuario, etc.).
	if (!cap.password) return { ofrecer: false, modo: null };

	// Si ya hay una entrada para este sitio con el mismo usuario, se asume
	// que la credencial ya está en la bóveda — no se ofrece (ver nota MVP).
	const yaGuardada = coincidencias.some((c) => norm(c.usuario) === norm(cap.usuario));
	if (yaGuardada) return { ofrecer: false, modo: null };

	return { ofrecer: true, modo: 'nuevo' };
}
