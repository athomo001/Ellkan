// Autor: Athan Espinoza

// Accesibilidad / lectura: fuente, espaciado, interlineado y tamaño de texto.
// Preferencia LOCAL por dispositivo (no viaja a `/me/preferences`: es una
// necesidad de quien está frente a esta pantalla, y `cargarPreferencias`
// reemplaza ese objeto entero con lo que devuelve el servidor).

import { declararStore } from './declarative-store';

export type FuenteLectura = 'opendyslexic' | 'atkinson' | 'lexend';
export const FUENTES_LECTURA: FuenteLectura[] = ['opendyslexic', 'atkinson', 'lexend'];

export interface PreferenciasLectura {
	/** Se prende y apaga con el botón «Aa» del menú; `fuente` es cuál usa. */
	activa: boolean;
	fuente: FuenteLectura;
	espaciado: 'normal' | 'amplio';
	interlineado: 'normal' | 'amplio';
	/** Porcentaje del tamaño base de texto, 90–150. */
	escala: number;
}

export const ESCALA_MIN = 90;
export const ESCALA_MAX = 150;
export const ESCALA_PASO = 5;

const POR_DEFECTO: PreferenciasLectura = { activa: false, fuente: 'opendyslexic', espaciado: 'normal', interlineado: 'normal', escala: 100 };

export const preferenciasLectura = declararStore<PreferenciasLectura>('preferenciasLectura', POR_DEFECTO, {
	ubicacion: 'disk',
	clearOn: []
});

/** Normaliza lo leído de `localStorage` (puede venir de otra versión o editado a mano). */
export function normalizarLectura(p: Partial<PreferenciasLectura> | null | undefined): PreferenciasLectura {
	const escala = Number(p?.escala);
	const fuenteValida = FUENTES_LECTURA.includes(p?.fuente as FuenteLectura);
	return {
		// Sin `activa` guardada (versión anterior, que tenía 'predeterminada'
		// como fuente): se considera activa si ya había una fuente elegida.
		activa: typeof p?.activa === 'boolean' ? p.activa : fuenteValida,
		fuente: fuenteValida ? (p!.fuente as FuenteLectura) : 'opendyslexic',
		espaciado: p?.espaciado === 'amplio' ? 'amplio' : 'normal',
		interlineado: p?.interlineado === 'amplio' ? 'amplio' : 'normal',
		escala: Number.isFinite(escala)
			? Math.min(ESCALA_MAX, Math.max(ESCALA_MIN, Math.round(escala / ESCALA_PASO) * ESCALA_PASO))
			: 100
	};
}

/** Botón «Aa» del menú: prende/apaga la fuente de lectura elegida. */
export function alternarFuenteLectura(): void {
	preferenciasLectura.update((p) => {
		const n = normalizarLectura(p);
		return { ...n, activa: !n.activa };
	});
}

/** Lo aplica sobre `<html>`; `lib/styles/fuentes.css` hace el resto. */
export function aplicarLectura(p: PreferenciasLectura): void {
	if (typeof document === 'undefined') return;
	const n = normalizarLectura(p);
	const raiz = document.documentElement;
	raiz.dataset.fuente = n.activa ? n.fuente : 'predeterminada';
	raiz.dataset.espaciado = n.espaciado;
	raiz.dataset.interlineado = n.interlineado;
	raiz.style.setProperty('--escala-texto', String(n.escala / 100));
}
