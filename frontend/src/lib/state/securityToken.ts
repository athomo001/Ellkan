// Autor: Athan Espinoza

// F-01: "token de seguridad" — versión simple, 100% client-side. Color +
// palabra guardados en `localStorage`, scoped por origin del navegador: una
// página de phishing en otro dominio no puede leerlo, ésa es la propiedad
// de seguridad real (mismo principio que el "SiteKey" de banca online de
// los 2000s). Se muestra antes de pedir la passphrase (login, LockOverlay);
// si no hay nada guardado para ese email en este navegador, no se muestra
// nada — es el estado esperado en un dispositivo nuevo, no un error. Sin
// esto, cualquier variante server-side tendría que resolver "¿cómo lo
// muestro antes de loguearme sin filtrar si el email existe?" (anti
// user-enumeration) — la versión client-side no tiene ese problema porque
// nunca hay una llamada de red.

export interface TokenSeguridad {
	color: string;
	palabra: string;
}

/** Nombres propios, no reutiliza `--danger`/`--success`/`--warning` (son
 * semánticos de estado, no de identidad) — paleta chica y cerrada sólo para
 * esta feature. */
export const COLOR_HEX: Record<string, string> = {
	rojo: '#c0392b',
	naranja: '#c2703d',
	dorado: '#b08838',
	verde: '#1f7a4d',
	turquesa: '#187890',
	azul: '#2f5fa8',
	violeta: '#7b4fa6',
	rosa: '#b3467c'
};
const COLORES = Object.keys(COLOR_HEX);

const PALABRAS = [
	'roble', 'río', 'monte', 'faro', 'puente', 'valle', 'nube', 'piedra',
	'brisa', 'sendero', 'bosque', 'estrella', 'arena', 'cascada', 'colina',
	'laguna', 'sol', 'luna', 'trueno', 'nieve', 'coral', 'jade', 'ámbar',
	'perla', 'cedro', 'olivo', 'lirio', 'roca', 'niebla', 'marea'
];

function clave(email: string): string {
	return `ellkan:security-token:${email}`;
}

export function obtenerTokenSeguridad(email: string): TokenSeguridad | null {
	if (typeof localStorage === 'undefined' || !email) return null;
	const crudo = localStorage.getItem(clave(email));
	if (!crudo) return null;
	try {
		const token = JSON.parse(crudo) as TokenSeguridad;
		return token.color && token.palabra ? token : null;
	} catch {
		return null;
	}
}

export function guardarTokenSeguridad(email: string, token: TokenSeguridad): void {
	if (typeof localStorage === 'undefined') return;
	localStorage.setItem(clave(email), JSON.stringify(token));
}

export function generarTokenSeguridad(email: string): TokenSeguridad {
	const token: TokenSeguridad = {
		color: COLORES[Math.floor(Math.random() * COLORES.length)],
		palabra: PALABRAS[Math.floor(Math.random() * PALABRAS.length)]
	};
	guardarTokenSeguridad(email, token);
	return token;
}
