// Autor: Athan Espinoza

// QA-08 (pendiente #100, 2026-11-22): el desbloqueo rápido con código TOTP
// (F-38) se quitó de la extensión. La clave que envolvía el secreto vivía en
// IndexedDB, dentro del perfil del navegador: quien copiara el perfil
// (backup, infostealer) se llevaba la clave, el secreto y con ellos la
// Contraseña Master. Una extensión no tiene un llavero del SO donde ponerla
// fuera del perfil, así que F-38 queda sólo en la app de escritorio.
//
// Esto borra lo que haya quedado guardado de antes. Corre en cada arranque
// del service worker; si ya no hay nada, no hace nada.

import { BrowserApi } from '../../browser-api';
import { borrarClaveDeDispositivo } from '../../../../frontend/src/lib/crypto/device-key';

export async function borrarRestosF38(): Promise<void> {
	try {
		await BrowserApi.storageLocalRemove(['ellkan.totp-local', 'ellkan.totp-local-backoff']);
		await borrarClaveDeDispositivo('totp-local');
	} catch {
		// Sin IndexedDB o storage disponible: no queda nada que borrar.
	}
}
