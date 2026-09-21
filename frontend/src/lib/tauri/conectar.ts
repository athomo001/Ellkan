// Autor: Athan Espinoza

// F-49 ("Conectar" desde la GUI, spec/13 §9) — lanza una terminal ya
// autenticada para un recurso ssh/ftp/telnet/vnc, sin que el secreto toque
// el portapapeles, `argv` ni el historial del shell. Sólo tiene sentido en
// el modo escritorio (Tauri): en modo servidor no hay proceso local del
// usuario que esta app pueda lanzar, así que nunca se llama fuera de un
// webview Tauri (el botón que la invoca ya está gateado por
// `'__TAURI_INTERNALS__' in window`, mismo criterio que `client.ts::baseUrl`).
//
// El secreto llega acá YA DESCIFRADO (el SPA lo abrió con `ellkan_crypto`,
// igual que para "Ver secreto") — cruza el IPC de Tauri hacia el proceso
// Rust, que lo inyecta al hijo `ssh` vía `SSH_ASKPASS` y lo descarta
// (`src-tauri/src/lib.rs::conectar_recurso`). Nunca se persiste ni se
// vuelve a mostrar acá.

export type TipoConexion = 'ssh' | 'ftp' | 'telnet' | 'vnc' | 'rdp' | 'postgresql' | 'mysql' | 'mongodb';

/**
 * Tipos cuyo secreto llega solo al cliente (askpass, variable de entorno del
 * hijo o credencial de Windows): nunca pasan por el portapapeles. Los demás
 * (ftp/telnet/vnc/mongodb) no tienen forma de recibirlo y el cliente lo pide
 * él mismo: ahí el secreto se deja en el portapapeles con auto-limpieza.
 * Lo decide `ellkan_backend::desktop::conectar::planificar`; esto es su espejo.
 */
export const TIPOS_CON_SECRETO_INYECTADO: TipoConexion[] = ['ssh', 'rdp', 'postgresql', 'mysql'];

export interface ParametrosConexion {
	tipo: TipoConexion;
	usuario: string | null;
	host: string;
	puerto: number;
	secreto: string;
	// `invoke` de Tauri exige que los args sean `Record<string, unknown>` —
	// esta firma no agrega campos reales, sólo satisface ese chequeo.
	[key: string]: unknown;
}

export async function conectar(params: ParametrosConexion): Promise<void> {
	const { invoke } = await import('@tauri-apps/api/core');
	await invoke<void>('conectar_recurso', params);
}

export function enModoEscritorio(): boolean {
	return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

/** F-46 (2026-09-17): modo escritorio es de 1 solo usuario para siempre —
 * `GET /auth/existe-usuario` (público, sin sesión) le dice al login/
 * register si ya hay alguien, para no mostrar un link "Registrate" que va
 * a fallar seguro (el backend ya rechaza un segundo registro explícito,
 * esto es sólo evitar ofrecer la opción). Sólo existe en el router de
 * escritorio — nunca se llama fuera de `enModoEscritorio()`. */
export async function existeUsuarioLocal(): Promise<boolean> {
	const { api } = await import('$lib/api/client');
	const { existe } = await api.get<{ existe: boolean }>('/auth/existe-usuario');
	return existe;
}
