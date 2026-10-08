// Autor: Athan Espinoza

// F-39: limpieza automática del portapapeles — compara que el portapapeles
// siga teniendo exactamente lo que Ellkan copió antes de borrarlo, para no
// pisar algo distinto que el usuario haya copiado después.
//
// En el escritorio (Windows) la copia la hace el proceso nativo: así el
// secreto queda fuera del historial del portapapeles (`Win+V`) y de la
// sincronización en la nube, que la auto-limpieza no alcanza a borrar. Si el
// comando no existe o falla (otra plataforma), se usa el del webview.

const enEscritorio = (): boolean => typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

async function comandoNativo(nombre: string, args?: Record<string, unknown>): Promise<boolean> {
	if (!enEscritorio()) return false;
	try {
		const { invoke } = await import('@tauri-apps/api/core');
		await invoke(nombre, args);
		return true;
	} catch {
		return false;
	}
}

export async function copiarConLimpieza(texto: string, minutos: number): Promise<void> {
	if (!(await comandoNativo('copiar_secreto', { texto }))) await navigator.clipboard.writeText(texto);
	if (minutos <= 0) return;

	setTimeout(async () => {
		try {
			const actual = await navigator.clipboard.readText();
			if (actual === texto && !(await comandoNativo('vaciar_portapapeles'))) await navigator.clipboard.writeText('');
		} catch {
			// Permiso de portapapeles denegado, o la pestaña perdió el foco
			// (algunos navegadores exigen foco para `readText`) — no hay nada
			// seguro que hacer acá, no vale la pena romper el flujo por esto.
		}
	}, minutos * 60_000);
}
