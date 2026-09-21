// Autor: Athan Espinoza

// Integración con el sistema (Windows) de la app de escritorio: iniciar con la
// sesión, enlaces `ellkan://`, bloquear al bloquearse la pantalla y modo
// portable. Sólo tiene sentido dentro de Tauri; la lógica vive en el shell
// (`app-escritorio/src-tauri/src/sistema.rs`).

export interface EstadoSistema {
	/** `false` fuera de Windows: nada de esto aplica. */
	soportado: boolean;
	autostart: boolean;
	enlaces: boolean;
	bloquear_con_pantalla: boolean;
	portable: boolean;
	carpeta_de_datos: string;
}

async function invocar<T>(comando: string, args?: Record<string, unknown>): Promise<T> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<T>(comando, args);
}

export const estadoSistema = () => invocar<EstadoSistema>('sistema_estado');
export const configurarAutostart = (activo: boolean) => invocar<void>('configurar_autostart', { activo });
export const configurarEnlaces = (activo: boolean) => invocar<void>('configurar_enlaces', { activo });
export const configurarBloqueoPantalla = (activo: boolean) => invocar<void>('configurar_bloqueo_pantalla', { activo });

/**
 * Ruta interna a la que llevar al usuario por un enlace `ellkan://…` (la app
 * ya validó el enlace); `null` si no hay ninguno pendiente. Se consume: una
 * segunda llamada devuelve `null`.
 */
export async function enlacePendiente(): Promise<string | null> {
	const ruta = await invocar<string | null>('enlace_pendiente');
	// Defensa extra: sólo se navega a rutas de la bóveda.
	return ruta && ruta.startsWith('/vault') ? ruta : null;
}

// --- Copias de seguridad de la bóveda (F-53) ---

export interface Respaldo {
	nombre: string;
	bytes: number;
	creado_unix: number;
	automatico: boolean;
}

export interface Respaldos {
	carpeta: string;
	respaldos: Respaldo[];
}
