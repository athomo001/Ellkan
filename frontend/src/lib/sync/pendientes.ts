// Autor: Athan Espinoza

// F-47: cola de recursos cuyo push al servidor vinculado no llegó (sin red,
// servidor caído, sesión remota imposible de renovar). Sin esto, lo que se
// creaba o editaba con el servidor caído quedaba sólo en la app para
// siempre: el sync sólo baja cambios, nunca sube los que fallaron.
//
// Guarda únicamente el id y la operación, nunca el cuerpo cifrado: al
// reintentar se reconstruye desde la copia local (`notificador.ts::
// subirPendientes`), así que siempre se sube la última versión y no queda
// una segunda copia del ciphertext en `localStorage`.
//
// Se marca ANTES de intentar el push y se quita al confirmarlo: si la app se
// cierra a mitad de un pedido, el recurso sigue en la cola.

export type OperacionPendiente = 'subir' | 'borrar';

function clave(email: string): string {
	return `ellkan:sync-pendientes:${email}`;
}

export function obtenerPendientes(email: string): Record<string, OperacionPendiente> {
	try {
		return JSON.parse(localStorage.getItem(clave(email)) ?? '{}') as Record<string, OperacionPendiente>;
	} catch {
		return {};
	}
}

function guardar(email: string, pendientes: Record<string, OperacionPendiente>): void {
	try {
		if (Object.keys(pendientes).length === 0) localStorage.removeItem(clave(email));
		else localStorage.setItem(clave(email), JSON.stringify(pendientes));
	} catch {
		// Sin almacenamiento disponible: el push en vivo sigue funcionando, sólo
		// se pierde el reintento de este recurso.
	}
}

/** La última operación gana: borrar algo que nunca llegó a subirse se
 * resuelve solo (el servidor responde que no existe y se da por hecho). */
export function marcarPendiente(email: string, resourceId: string, operacion: OperacionPendiente): void {
	const pendientes = obtenerPendientes(email);
	pendientes[resourceId] = operacion;
	guardar(email, pendientes);
}

export function quitarPendiente(email: string, resourceId: string): void {
	const pendientes = obtenerPendientes(email);
	if (!(resourceId in pendientes)) return;
	delete pendientes[resourceId];
	guardar(email, pendientes);
}

/** Al desvincular: lo pendiente era para ese servidor, no para el próximo. */
export function olvidarPendientes(email: string): void {
	try {
		localStorage.removeItem(clave(email));
	} catch {
		// nada que limpiar
	}
}
