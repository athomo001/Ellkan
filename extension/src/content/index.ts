// Autor: Athan Espinoza

// Content script — entry point. Por ahora sólo prueba el patrón de
// mensajería completo de punta a punta (spec 06 §2); la detección de campos
// de autofill (spec 06 §4) es la próxima etapa, no núcleo.

import { PortClient } from '../shared/port-client';

const cliente = new PortClient('WebIntegration');

cliente
	.request<{ pong: true; ts: number }>('PING')
	.then((respuesta) => {
		console.debug('[ellkan] mensajería background↔content OK', respuesta);
	})
	.catch((error) => {
		console.error('[ellkan] fallo el round-trip de mensajería', error);
	});
