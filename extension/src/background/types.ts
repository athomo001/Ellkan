// Autor: Athan Espinoza

// Identidad de un worker conectado (spec 06 §2) — un content script puede
// abrir varios puertos con distinto `name` según qué superficie represente.
export type WorkerName = 'WebIntegration' | 'InFormMenu' | 'NotificationBar' | 'QuickAccess';

export interface WorkerInfo {
	id: string;
	// `undefined` sólo para `QuickAccess` (el popup) — no vive en el DOM de
	// ninguna pestaña, así que no hay tabId/frameId que registrar.
	tabId: number | undefined;
	frameId: number | undefined;
	name: WorkerName;
	status: 'connected' | 'disconnected';
}

/** Protocolo de eventos: `[eventName, ...args]`. */
export type EventoSaliente = [string, ...unknown[]];

/** Protocolo de request/response: `Port.request()` genera un `requestId`
 * (spec 06 §2) y resuelve cuando llega `[requestId, "SUCCESS"|"ERROR", ...]`. */
export interface MensajeRequest {
	requestId: string;
	tipo: string;
	payload?: unknown;
}
export type MensajeResponse = [string, 'SUCCESS', unknown] | [string, 'ERROR', string];
