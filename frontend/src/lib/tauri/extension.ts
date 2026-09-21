// Autor: Athan Espinoza

// Punto 9: instalar la extensión de navegador DESDE la app de escritorio.
// La extensión viaja embebida en el ejecutable; estos wrappers llaman a los
// comandos Tauri de `src-tauri/src/lib.rs` (`extension_*`). Sólo tiene sentido
// en modo escritorio — mismo criterio de gateo que `$lib/tauri/conectar.ts::
// enModoEscritorio`.

export interface NavegadorExtension {
	id: string;
	/** Build de la extensión que usa: los Chromium comparten `chromium`. */
	objetivo: string;
	/** El navegador está instalado en esta PC — sólo se ofrecen los que sí. */
	instalado: boolean;
	/** El usuario ya pidió instalarla para este navegador — la app la mantiene al día. */
	elegido: boolean;
	/** Carpeta estable donde queda extraída (la que se carga en el navegador). */
	ruta: string;
	version_instalada: string | null;
	al_dia: boolean;
}

export interface EstadoExtension {
	/** `false` en un build que no preparó la extensión (desarrollo). */
	incluida: boolean;
	version_incluida: string | null;
	navegadores: NavegadorExtension[];
}

/** Datos de presentación por navegador. La lista de ids soportados vive en el
 * backend (`ellkan_backend::desktop::extension::NAVEGADORES`) — acá sólo el
 * nombre y dónde se administran las extensiones. */
export const NAVEGADORES_UI: { id: string; nombre: string; paginaExtensiones: string }[] = [
	{ id: 'chrome', nombre: 'Google Chrome', paginaExtensiones: 'chrome://extensions' },
	{ id: 'edge', nombre: 'Microsoft Edge', paginaExtensiones: 'edge://extensions' },
	{ id: 'brave', nombre: 'Brave', paginaExtensiones: 'brave://extensions' },
	{ id: 'opera', nombre: 'Opera', paginaExtensiones: 'opera://extensions' },
	{ id: 'firefox', nombre: 'Mozilla Firefox', paginaExtensiones: 'about:debugging#/runtime/this-firefox' }
];

export async function estadoExtension(): Promise<EstadoExtension> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<EstadoExtension>('extension_estado');
}

/** Extrae (o actualiza) la extensión para `navegador` y hace que la app la
 * mantenga al día en cada arranque. */
export async function instalarExtension(navegador: string): Promise<NavegadorExtension> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<NavegadorExtension>('extension_instalar', { navegador });
}

/** Abre el navegador directamente en su página de extensiones, para que el
 * usuario no tenga que pegar `chrome://extensions` a mano (los navegadores no
 * dejan abrir esas direcciones desde otra app por el camino común). */
export async function abrirNavegadorEnExtensiones(navegador: string): Promise<void> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<void>('extension_abrir_navegador', { navegador });
}

export async function dejarDeActualizarExtension(navegador: string): Promise<void> {
	const { invoke } = await import('@tauri-apps/api/core');
	return invoke<void>('extension_dejar_de_actualizar', { navegador });
}

/** Ruta del `manifest.json` dentro de la carpeta de la extensión (Firefox pide
 * ese archivo, no la carpeta). */
export function rutaDelManifest(ruta: string): string {
	const separador = ruta.includes('\\') ? '\\' : '/';
	return `${ruta}${separador}manifest.json`;
}

/** Abre el explorador de archivos con el `manifest.json` de la extensión
 * seleccionado — es la carpeta que hay que elegir en "Cargar descomprimida". */
export async function mostrarCarpetaExtension(ruta: string): Promise<void> {
	const { revealItemInDir } = await import('@tauri-apps/plugin-opener');
	await revealItemInDir(rutaDelManifest(ruta));
}
