// Autor: Athan Espinoza

// Script de relleno con acciones tipadas por `opid` (spec 06 §4.3), adoptado
// de Bitwarden sobre el `{username, password, totp}` plano de Passbolt. El
// problema real que resuelve: direccionar de forma estable un campo que
// pudo cambiar de posición en el DOM entre la colección y el relleno (un
// form que se re-renderiza tras cargar JS diferido). El background/content
// arma una secuencia de acciones y el intérprete las ejecuta una por una,
// resolviendo cada `opid` contra el DOM EN EL MOMENTO de la acción — no
// antes.
//
// El intérprete recibe `resolver` inyectado (opid → elemento) para poder
// testearse sin DOM real (ver `extension/self-check.ts`).

export type AccionAutofill =
	| { tipo: 'fill_by_opid'; opid: string; valor: string }
	| { tipo: 'click_on_opid'; opid: string }
	| { tipo: 'focus_by_opid'; opid: string };

export type ScriptAutofill = AccionAutofill[];

/** Lo mínimo que el intérprete necesita de un elemento — el content script
 * pasa un adaptador real sobre el `HTMLElement` (con el relleno vía setter
 * nativo del prototipo, compatible con React); un test pasa un doble que
 * registra las llamadas. */
export interface ElementoObjetivo {
	focus(): void;
	click(): void;
	/** Escribe `valor` y dispara los eventos que un framework necesita para
	 * enterarse del cambio — la implementación real vive en el content script. */
	rellenar(valor: string): void;
}

export interface ResultadoEjecucion {
	ejecutadas: number;
	/** Acciones cuyo `opid` ya no resolvía a ningún elemento — se saltean sin
	 * romper el resto del script. */
	salteadas: number;
}

/** Ejecuta el script en orden. Un `opid` que no resuelve se saltea (no tira).
 * Cualquier excepción de un paso individual (un `fill` sobre un elemento en
 * estado raro) tampoco corta el resto. */
export function ejecutarScript(
	script: ScriptAutofill,
	resolver: (opid: string) => ElementoObjetivo | null
): ResultadoEjecucion {
	let ejecutadas = 0;
	let salteadas = 0;
	for (const accion of script) {
		const el = resolver(accion.opid);
		if (!el) {
			salteadas++;
			continue;
		}
		try {
			switch (accion.tipo) {
				case 'fill_by_opid':
					el.rellenar(accion.valor);
					break;
				case 'click_on_opid':
					el.click();
					break;
				case 'focus_by_opid':
					el.focus();
					break;
			}
			ejecutadas++;
		} catch {
			salteadas++;
		}
	}
	return { ejecutadas, salteadas };
}

/** Arma el script para un par de login ya emparejado (`field-detection.ts`).
 * Orden: foco+relleno del usuario (si hay), después foco+relleno del
 * password, después el TOTP (si hay). El `focus` antes de cada `fill` imita
 * a un usuario tipeando — algunos forms sólo validan/activan el submit si el
 * campo recibió foco. */
export function scriptParaLogin(par: {
	usuario: string | null;
	password: string;
	totp: string | null;
	valores: { usuario: string; password: string; totp?: string };
}): ScriptAutofill {
	const script: ScriptAutofill = [];
	if (par.usuario && par.valores.usuario) {
		script.push({ tipo: 'focus_by_opid', opid: par.usuario });
		script.push({ tipo: 'fill_by_opid', opid: par.usuario, valor: par.valores.usuario });
	}
	script.push({ tipo: 'focus_by_opid', opid: par.password });
	script.push({ tipo: 'fill_by_opid', opid: par.password, valor: par.valores.password });
	if (par.totp && par.valores.totp) {
		script.push({ tipo: 'focus_by_opid', opid: par.totp });
		script.push({ tipo: 'fill_by_opid', opid: par.totp, valor: par.valores.totp });
	}
	return script;
}
