// Autor: Athan Espinoza

// Controller: orquesta una operación puntual, delegando la lógica real al
// Service correspondiente (spec 06 §2). Demo mínima del patrón completo
// (Pagemod→Event→Controller→Service) — dominio real de sesión (F-04) se
// construye cuando se implemente el login de la extensión.
import { SesionService } from '../services/sesion-service';

export const SesionController = {
	async ping(): Promise<{ pong: true; ts: number }> {
		return SesionService.ping();
	}
};
