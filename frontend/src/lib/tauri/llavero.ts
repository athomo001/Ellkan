// Autor: Athan Espinoza

// F-50: Soporte de llavero / biometría del SO (Windows Credential Manager / Secret Service en Linux).
// Almacena o recupera únicamente la clave de envoltura cifrada (wrapped key).
// NUNCA la contraseña maestra ni la clave privada en claro (criterio de seguridad H-01).

import { enModoEscritorio } from './conectar';

/**
 * Guarda la clave de envoltura en el llavero seguro nativo del sistema operativo.
 */
export async function guardarEnvolturaLlavero(vaultId: string, envolturaB64: string): Promise<void> {
	if (!enModoEscritorio()) return;
	const { invoke } = await import('@tauri-apps/api/core');
	await invoke<void>('guardar_envoltura_llavero', { vaultId, envolturaB64 });
}

/**
 * Recupera la clave de envoltura desde el llavero seguro del sistema operativo.
 */
export async function recuperarEnvolturaLlavero(vaultId: string): Promise<string | null> {
	if (!enModoEscritorio()) return null;
	try {
		const { invoke } = await import('@tauri-apps/api/core');
		return await invoke<string | null>('recuperar_envoltura_llavero', { vaultId });
	} catch {
		// Degradación elegante: si el llavero no está accesible, devuelve null
		return null;
	}
}

/**
 * Elimina la clave de envoltura del llavero seguro del SO (ej. al desactivar biometría o cerrar sesión).
 */
export async function eliminarEnvolturaLlavero(vaultId: string): Promise<void> {
	if (!enModoEscritorio()) return;
	try {
		const { invoke } = await import('@tauri-apps/api/core');
		await invoke<void>('eliminar_envoltura_llavero', { vaultId });
	} catch {
		// Ignorar fallo de eliminación si la entrada ya no existe
	}
}
