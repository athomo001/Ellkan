// Autor: Athan Espinoza

// Service: lógica de negocio pura (spec 06 §2) — sin tocar `chrome.*`/
// `browser.*` directo (eso vive en `BrowserApi`) ni saber nada de puertos
// (eso es responsabilidad de `Controller`/`Event`/`Pagemod`).
export const SesionService = {
	ping(): { pong: true; ts: number } {
		return { pong: true, ts: Date.now() };
	}
};
