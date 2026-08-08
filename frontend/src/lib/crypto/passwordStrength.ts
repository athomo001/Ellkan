// Autor: Athan Espinoza

// Medidor de fortaleza único del frontend — hasta ahora no existía ninguno
// (ni acá ni en el registro de cuenta, F-01). F-27 exige que la contraseña
// de un archivo exportado (KDBX) pase "por el mismo medidor que la
// passphrase de cuenta" — como F-01 tampoco lo tenía, se agrega acá una
// sola vez y se conecta a ambos lugares (`(anon)/register` y
// `(app)/settings/export-import`). Wrapper fino sobre `zxcvbn`, sin lógica
// de scoring propia.

import zxcvbn from 'zxcvbn';

export interface Fortaleza {
	score: 0 | 1 | 2 | 3 | 4;
	feedback: string[];
}

const SCORE_MINIMO = 3;

export function evaluarFortaleza(password: string): Fortaleza {
	if (!password) return { score: 0, feedback: [] };
	const resultado = zxcvbn(password);
	const feedback = [resultado.feedback.warning, ...resultado.feedback.suggestions].filter(
		(s): s is string => !!s
	);
	return { score: resultado.score as 0 | 1 | 2 | 3 | 4, feedback };
}

export function esSuficientementeFuerte(password: string): boolean {
	return evaluarFortaleza(password).score >= SCORE_MINIMO;
}
