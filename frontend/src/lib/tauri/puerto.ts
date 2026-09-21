// Autor: Athan Espinoza

// F-45 (spec/13 §3): dejar que el usuario vea y elija el puerto fijo del
// backend local, en vez de que quede siempre en el autoelegido del primer
// arranque (`bindear_puerto`, `app-escritorio/backend-desktop/mod.rs`).
// Sólo tiene sentido en modo escritorio — mismo criterio de gateo que
// `$lib/tauri/conectar.ts::enModoEscritorio`.

export interface ResultadoConfigurarPuerto {
	advertencia: string | null;
}

export interface InfoApp {
	version: string;
	/** Fecha (segundos Unix) del ejecutable en ejecución; `null` si no se pudo leer. */
	binario_unix: number | null;
	ruta: string;
}

/** Qué build está corriendo: versión + fecha del binario + ruta. */
export async function infoApp(): Promise<InfoApp> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<InfoApp>('info_app');
}

/** Puerto realmente escuchando en esta sesión (`puerto_backend`, ya usado
 * por `$lib/api/client.ts`) vs. el fijo persistido en `config.json` — pueden
 * diferir si el fijo dejó de estar disponible entre arranques. */
export async function puertoActual(): Promise<number> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<number>('puerto_backend');
}

export async function puertoConfigurado(): Promise<number | null> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<number | null>('puerto_configurado');
}

/** Valida (rechazo duro <1024, bind de prueba real) y persiste un puerto
 * fijo nuevo. Aplica desde el PRÓXIMO arranque, no en esta sesión — el
 * backend actual ya está sirviendo en el puerto que resolvió al abrir la
 * app (ver el comentario de `configurar_puerto_fijo` en `lib.rs`). */
export async function configurarPuertoFijo(puerto: number): Promise<ResultadoConfigurarPuerto> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<ResultadoConfigurarPuerto>('configurar_puerto_fijo', { puerto });
}
