// Autor: Athan Espinoza

// Medidor de fortaleza único del frontend — hasta ahora no existía ninguno
// (ni acá ni en el registro de cuenta, F-01). F-27 exige que la contraseña
// de un archivo exportado (KDBX) pase "por el mismo medidor que la
// passphrase de cuenta" — como F-01 tampoco lo tenía, se agrega acá una
// sola vez y se conecta a ambos lugares (`(anon)/register` y el panel de
// exportar dentro de `(app)/vault`). Wrapper fino sobre `zxcvbn`, sin lógica
// de scoring propia.
//
// `zxcvbn` se carga recién la primera vez que se mide una contraseña: son
// ~800 KB de diccionarios que, al importarse, arman en memoria tablas de
// unas 100 mil palabras. Antes se cargaba con la página del Vault aunque no
// se midiera nada. Mientras carga, `evaluarFortaleza` devuelve score 0 y
// `cargando: true`. TypeScript común a propósito: lo importa también la
// extensión de navegador. En la app se usa a través de
// `passwordStrength.svelte.ts`, que re-evalúa sola cuando termina de cargar.

type Zxcvbn = typeof import('zxcvbn');

export interface Fortaleza {
	score: 0 | 1 | 2 | 3 | 4;
	feedback: string[];
	/** El medidor todavía se está cargando: el score no es definitivo. */
	cargando?: boolean;
}

const SCORE_MINIMO = 3;

let motor: Zxcvbn | null = null;
let cargandoMotor: Promise<Zxcvbn> | null = null;

/** Carga el medidor (una sola vez). Para quien necesita el score real ya, como Salud. */
export function cargarMedidor(): Promise<Zxcvbn> {
	cargandoMotor ??= import('zxcvbn').then((m) => {
		motor = m.default;
		return m.default;
	});
	return cargandoMotor;
}

export function evaluarFortaleza(password: string): Fortaleza {
	if (!password) return { score: 0, feedback: [] };
	if (!motor) {
		void cargarMedidor();
		return { score: 0, feedback: [], cargando: true };
	}
	const resultado = motor(password);
	const feedback = [resultado.feedback.warning, ...resultado.feedback.suggestions].filter(
		(s): s is string => !!s
	);
	return { score: resultado.score as 0 | 1 | 2 | 3 | 4, feedback };
}

export function esSuficientementeFuerte(password: string): boolean {
	return evaluarFortaleza(password).score >= SCORE_MINIMO;
}
