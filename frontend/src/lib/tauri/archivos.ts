// Autor: Athan Espinoza

// Descargas en modo escritorio. El webview de Tauri no procesa un `<a
// download>` sobre un blob: el clic no hace nada, sin ningún error (bug real
// encontrado probando el kit de recuperación en la ventana real,
// 2026-09-20 — y lo mismo le pasaba a toda exportación y a los `.7z`). Acá
// el archivo lo escribe el backend en la carpeta Descargas y se muestra en el
// explorador para que el usuario vea dónde quedó.

import { bytesABase64 } from '$lib/crypto/b64';

/**
 * Guarda `contenido` en la carpeta Descargas del usuario (sin pisar nada:
 * si el nombre ya existe queda `nombre (1).ext`), abre el explorador con el
 * archivo seleccionado y devuelve la ruta donde quedó. Sólo en escritorio.
 */
export async function guardarEnDescargas(nombre: string, contenido: Uint8Array): Promise<string> {
	const { invoke } = await import('@tauri-apps/api/core');
	let ruta: string;
	try {
		ruta = await invoke<string>('guardar_descarga', { nombre, contenidoB64: bytesABase64(contenido) });
	} catch (err) {
		// Los comandos de Tauri rechazan con un string, no con un `Error`.
		throw new Error(typeof err === 'string' ? err : 'No se pudo guardar el archivo en Descargas.');
	}

	// Mostrar el archivo es una ayuda, no parte del guardado: si el
	// explorador no se puede abrir, el archivo ya está guardado igual.
	try {
		const { revealItemInDir } = await import('@tauri-apps/plugin-opener');
		await revealItemInDir(ruta);
	} catch {
		/* el archivo ya está en disco */
	}
	return ruta;
}
