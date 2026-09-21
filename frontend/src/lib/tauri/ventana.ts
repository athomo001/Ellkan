// Autor: Athan Espinoza

// Qué hace la app al cerrar la ventana con la "X". Antes SIEMPRE se ocultaba
// a la bandeja sin avisar: el usuario "cerraba" la app, seguía corriendo, y
// (siendo de instancia única) al abrir el `.exe` de nuevo volvía a ver la
// ventana de la versión vieja. Ahora el backend emite `cierre-solicitado` y
// esta capa muestra un diálogo para elegir; la elección se puede recordar.
// Sólo tiene sentido en modo escritorio.

export type AlCerrar = 'preguntar' | 'bandeja' | 'salir';

export async function alCerrarConfigurado(): Promise<AlCerrar> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<AlCerrar>('al_cerrar_configurado');
}

export async function configurarAlCerrar(modo: AlCerrar): Promise<void> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<void>('configurar_al_cerrar', { modo });
}

/** Cierra la app del todo — lo mismo que "Salir" del menú de la bandeja. */
export async function cerrarAplicacion(): Promise<void> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<void>('cerrar_aplicacion');
}

/** Oculta la ventana y deja la app corriendo en la bandeja del sistema. */
export async function ocultarABandeja(): Promise<void> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<void>('ocultar_a_bandeja');
}
