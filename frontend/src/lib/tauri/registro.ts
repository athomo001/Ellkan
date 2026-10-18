// Autor: Athan Espinoza

// Modo escritorio: manda los errores y avisos de la interfaz al mismo
// `Ellkan.log` que el backend (comando `registrar_desde_web` del shell). En
// release la consola de WebView2 no está abierta, así que un `console.error`
// (ej. «[vault] no se pudo cargar la lista») se perdía y no quedaba con qué
// diagnosticar (pedido 2026-10-18). En el navegador no hace nada.
//
// Nunca se mandan secretos: los `console.error` del código sólo llevan ids y
// mensajes de error, y el shell recorta el largo y saca caracteres de control.

import { enModoEscritorio } from './conectar';

let instalado = false;

function aTexto(valor: unknown): string {
	if (valor instanceof Error) return `${valor.name}: ${valor.message}`;
	if (typeof valor === 'string') return valor;
	try {
		return JSON.stringify(valor);
	} catch {
		return String(valor);
	}
}

/** Una línea al `Ellkan.log` desde el código (ej. el resumen del sync). En el
 * navegador no hace nada. Nunca pasarle secretos ni nombres de recursos. */
export function registrar(nivel: 'info' | 'warn' | 'error', ...partes: unknown[]): void {
	if (enModoEscritorio()) void enviar(nivel, partes);
}

async function enviar(nivel: 'info' | 'warn' | 'error', partes: unknown[]): Promise<void> {
	try {
		const { invoke } = await import('@tauri-apps/api/core');
		await invoke('registrar_desde_web', { nivel, mensaje: partes.map(aTexto).join(' ') });
	} catch {
		/* sin shell o comando no disponible: el log es best-effort */
	}
}

/** Engancha `console.error`/`console.warn` y los errores sin capturar. Idempotente. */
export function instalarRegistroEnArchivo(): void {
	if (instalado || !enModoEscritorio()) return;
	instalado = true;

	for (const nivel of ['error', 'warn'] as const) {
		const original = console[nivel].bind(console);
		console[nivel] = (...args: unknown[]) => {
			original(...args);
			void enviar(nivel, args);
		};
	}
	window.addEventListener('error', (e) => void enviar('error', ['[sin capturar]', e.error ?? e.message]));
	window.addEventListener('unhandledrejection', (e) => void enviar('error', ['[promesa rechazada]', e.reason]));
}
