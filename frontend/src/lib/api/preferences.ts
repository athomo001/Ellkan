// Autor: Athan Espinoza

// F-30/F-31/F-39: wrapper de `/me/preferences` — sincroniza el store local
// (`preferencias`, ya declarado con `ubicacion: 'disk'` para no perder el
// tema elegido entre pestañas) contra el valor real del servidor.

import { api } from './client';
import { preferencias, type Preferencias } from '$lib/state/session';

// El backend usa snake_case (envelope de error/DTOs, 08-backend.md) — el
// store cliente usa camelCase como el resto del código TS de este repo.
interface PreferenciasDto {
	locale: 'en' | 'es';
	theme: 'light' | 'dark';
	clipboard_clear_minutes: number;
	auto_lock_minutes: number | null;
}

function deDto(dto: PreferenciasDto): Preferencias {
	return {
		locale: dto.locale,
		theme: dto.theme,
		clipboardClearMinutes: dto.clipboard_clear_minutes,
		autoLockMinutes: dto.auto_lock_minutes
	};
}

function aDto(p: Preferencias): PreferenciasDto {
	return {
		locale: p.locale,
		theme: p.theme,
		clipboard_clear_minutes: p.clipboardClearMinutes,
		auto_lock_minutes: p.autoLockMinutes
	};
}

export async function cargarPreferencias(): Promise<Preferencias> {
	const dto = await api.get<PreferenciasDto>('/me/preferences');
	const p = deDto(dto);
	preferencias.set(p);
	return p;
}

export async function guardarPreferencias(p: Preferencias): Promise<Preferencias> {
	const dto = await api.put<PreferenciasDto>('/me/preferences', aDto(p));
	const guardada = deDto(dto);
	preferencias.set(guardada);
	return guardada;
}

/** `data-theme` en `<html>` — único lugar que lee `tokens.css` para decidir claro/oscuro. */
export function aplicarTema(theme: Preferencias['theme']): void {
	if (typeof document === 'undefined') return;
	document.documentElement.dataset.theme = theme;
}

/**
 * Toggle rápido claro/oscuro, con animación circular (View Transitions API)
 * como mejora progresiva — nunca la única vía: `temaActual` viene del store
 * reactivo (`$preferencias.theme`), no se re-lee de `dataset.theme` del DOM
 * (evita cualquier desincronización entre store y atributo real). Si la
 * animación falla por lo que sea (navegador raro, `startViewTransition`
 * tira una excepción), el cambio de tema ya se aplicó igual — el toggle en
 * sí nunca depende de que la animación funcione.
 *
 * `onAplicado`, no ejecutar código después de llamar a esta función
 * esperando que el store ya esté actualizado: `doc.startViewTransition(cb)`
 * **no** corre `cb` sincrónicamente (a diferencia de lo que dice buena
 * parte de la documentación de la API) — corre en un microtask propio.
 * Un caller que necesite reaccionar al cambio real (ej. sincronizar con el
 * servidor) tiene que pasar `onAplicado`, que corre adentro de `aplicar()`
 * en el momento exacto en que el store cambió, sea cual sea el camino
 * (con o sin animación). Sin esto, un caller que lee `$preferencias` justo
 * después de invocar `alternarTema` puede leer el valor viejo — bug real
 * detectado con Playwright contra un Chrome de verdad, no una suposición.
 */
export function alternarTema(
	temaActual: Preferencias['theme'],
	event?: MouseEvent,
	onAplicado?: (nuevo: Preferencias['theme']) => void
): void {
	if (typeof document === 'undefined') return;
	const nuevo: Preferencias['theme'] = temaActual === 'light' ? 'dark' : 'light';
	const aplicar = () => {
		preferencias.update((p) => ({ ...p, theme: nuevo }));
		aplicarTema(nuevo);
		onAplicado?.(nuevo);
	};

	const doc = document as Document & { startViewTransition?: (cb: () => void) => { ready: Promise<void> } };
	if (!event || !doc.startViewTransition) {
		aplicar();
		return;
	}

	try {
		const x = event.clientX;
		const y = event.clientY;
		const radioFinal = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));
		const transicion = doc.startViewTransition(aplicar);
		transicion.ready
			.then(() => {
				document.documentElement.animate(
					{ clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radioFinal}px at ${x}px ${y}px)`] },
					{ duration: 450, easing: 'ease-out', pseudoElement: '::view-transition-new(root)' }
				);
			})
			.catch(() => {
				/* la transición se saltó la animación — `aplicar()` ya corrió */
			});
	} catch {
		// `startViewTransition` lanzó sincrónicamente (ej. ya hay una
		// transición en curso) — aplicar el cambio directo, sin animar.
		aplicar();
	}
}
