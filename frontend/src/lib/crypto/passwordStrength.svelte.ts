// Autor: Athan Espinoza

// Versión reactiva del medidor para la app: llamada dentro de un `$derived`,
// se vuelve a calcular sola cuando `zxcvbn` termina de cargar (ver
// `passwordStrength.ts`, que carga el medidor recién al primer uso).

import { cargarMedidor, evaluarFortaleza as evaluar, type Fortaleza } from './passwordStrength';

export { cargarMedidor, esSuficientementeFuerte, type Fortaleza } from './passwordStrength';

let listo = $state(false);

export function evaluarFortaleza(password: string): Fortaleza {
	// Leer `listo` registra la dependencia: al cambiar, el `$derived` se recalcula.
	void listo;
	const resultado = evaluar(password);
	if (resultado.cargando) {
		void cargarMedidor().then(() => {
			listo = true;
		});
	}
	return resultado;
}
