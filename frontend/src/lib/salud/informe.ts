// Autor: Athan Espinoza

// F-57 — Salud de la bóveda: qué contraseñas conviene cambiar. Lógica pura
// (sin red, sin wasm, sin DOM) para poder probarla con Node. Todo se calcula en
// el cliente: ningún secreto sale de acá.

export interface ItemSalud {
	id: string;
	nombre: string;
	usuario: string;
	password: string;
	/** ISO 8601 — última edición del recurso. */
	actualizadoEn: string;
}

export interface Debil {
	item: ItemSalud;
	/** zxcvbn 0..4 */
	score: number;
}

export interface Vieja {
	item: ItemSalud;
	dias: number;
}

export interface Informe {
	/** Recursos con contraseña que se analizaron (los que no tienen, no cuentan). */
	analizados: number;
	debiles: Debil[];
	/** Cada grupo son 2+ recursos con LA MISMA contraseña — todos quedan marcados. */
	repetidas: ItemSalud[][];
	/** Vacío si no se configuró umbral (por defecto no se fuerza rotación, NIST SP 800-63B). */
	viejas: Vieja[];
}

export interface OpcionesInforme {
	ahora: Date;
	/** `null` = no se marca ninguna como vieja. */
	umbralDias: number | null;
	/** Score de zxcvbn hasta el cual (inclusive) una contraseña es débil. */
	scoreDebilHasta?: number;
	/** Fortaleza de una contraseña, 0..4 (en la app: `evaluarFortaleza`). */
	puntuar: (password: string) => number;
	/** Huella LOCAL de una contraseña para detectar repetidas sin comparar texto plano. */
	huella: (password: string) => Promise<string>;
}

const MS_POR_DIA = 24 * 60 * 60 * 1000;

/** SHA-256 hexadecimal (sólo se usa localmente, para agrupar repetidas). */
export async function huellaLocal(password: string): Promise<string> {
	const bytes = new TextEncoder().encode(password);
	const hash = await crypto.subtle.digest('SHA-256', bytes);
	return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function analizar(items: ItemSalud[], opciones: OpcionesInforme): Promise<Informe> {
	const { ahora, umbralDias, puntuar, huella } = opciones;
	const scoreDebilHasta = opciones.scoreDebilHasta ?? 2;
	const conPassword = items.filter((i) => i.password.length > 0);

	const debiles: Debil[] = [];
	const viejas: Vieja[] = [];
	const porHuella = new Map<string, ItemSalud[]>();

	for (const item of conPassword) {
		const score = puntuar(item.password);
		if (score <= scoreDebilHasta) debiles.push({ item, score });

		if (umbralDias !== null) {
			const dias = Math.floor((ahora.getTime() - new Date(item.actualizadoEn).getTime()) / MS_POR_DIA);
			if (dias > umbralDias) viejas.push({ item, dias });
		}

		const h = await huella(item.password);
		porHuella.set(h, [...(porHuella.get(h) ?? []), item]);
	}

	const repetidas = [...porHuella.values()].filter((grupo) => grupo.length > 1);
	// Lo más urgente primero.
	debiles.sort((a, b) => a.score - b.score);
	viejas.sort((a, b) => b.dias - a.dias);

	return { analizados: conPassword.length, debiles, repetidas, viejas };
}
