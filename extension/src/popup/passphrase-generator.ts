// Autor: Athan Espinoza

// Modo 2 del generador dual (2026-08-15) — frases de paso memorizables en
// español, 100% local (decisión confirmada con el usuario: misma seguridad
// real que un endpoint de servidor — CSPRNG client-side —, sin round-trip
// de red ni un segundo diccionario que mantener sincronizado en el
// backend). Mismo muestreo sin sesgo que `passwordGenerator.ts`
// (`indiceSinSesgo`), reusado en vez de reimplementado. El diccionario en sí
// vive en `diccionario-frases.ts` (archivo aparte, para poder agregar/sacar
// palabras sin tocar esta lógica) — ~490 palabras únicas, suficiente para
// una frase memorable con entropía real (log2(490) ≈ 8.9 bits/palabra; 5
// palabras ≈ 44 bits). El modo "Aleatoria" sigue siendo la opción de mayor
// entropía, éste prioriza lo memorizable — mismo trade-off que cualquier
// diceware corto.

import { indiceSinSesgo } from '../../../frontend/src/lib/crypto/passwordGenerator';
import { DICCIONARIO } from './diccionario-frases';

const DICCIONARIO_UNICO = [...new Set(DICCIONARIO)];

const SIMBOLOS_ALEATORIOS = '#$!@%&*';

export interface OpcionesFraseDePaso {
	wordCount: number; // 3-10
	capitalize: boolean;
	includeNumbers: boolean;
	separator: ' ' | '-' | '.' | ',' | '_' | 'aleatorio';
}

function palabraAleatoria(): string {
	return DICCIONARIO_UNICO[indiceSinSesgo(DICCIONARIO_UNICO.length)];
}

function separadorPara(opciones: OpcionesFraseDePaso): string {
	if (opciones.separator !== 'aleatorio') return opciones.separator;
	return SIMBOLOS_ALEATORIOS[indiceSinSesgo(SIMBOLOS_ALEATORIOS.length)];
}

export function generarFraseDePaso(opciones: OpcionesFraseDePaso): string {
	const cantidad = Math.min(10, Math.max(3, Math.round(opciones.wordCount)));

	const palabras: string[] = [];
	for (let i = 0; i < cantidad; i++) {
		let palabra = palabraAleatoria();
		if (opciones.capitalize) palabra = palabra[0].toUpperCase() + palabra.slice(1);
		if (opciones.includeNumbers) palabra += String(indiceSinSesgo(10));
		palabras.push(palabra);
	}

	// Separador propio por unión (no uno fijo global) cuando es "aleatorio",
	// para que cada palabra quede separada por un símbolo distinto — más
	// entropía visual, mismo criterio que Proton/Bitwarden con Diceware.
	if (opciones.separator === 'aleatorio') {
		return palabras.map((p, i) => (i === 0 ? p : separadorPara(opciones) + p)).join('');
	}
	return palabras.join(opciones.separator);
}
