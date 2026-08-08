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
