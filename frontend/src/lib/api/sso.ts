// Autor: Athan Espinoza

// F-17 (pendiente #133): inicio de sesión con el proveedor de la
// organización (OIDC). El IdP vuelve a `/sso/callback` de esta web
// (`ELLKAN_SSO_REDIRECT_URL`); esa página le pasa `code` y `state` al
// backend con `fetch` (mismo origen: viaja la cookie `ellkan_sso` que ata el
// flujo a este navegador) y recibe la sesión en el cuerpo. Así el
// `session_id` nunca pasa por una URL, el historial ni un `Referer`.

import { api } from './client';

export type EstadoCallbackSso =
	| 'completo'
	| 'pendiente_mfa'
	| 'requiere_configurar_mfa'
	| 'requiere_cambiar_passphrase'
	| 'vinculado';

export interface ResultadoCallbackSso {
	estado: EstadoCallbackSso;
	session_id: string | null;
}

/** Ruta del backend que arranca el flujo (302 al IdP). */
export const RUTA_INICIO_SSO = '/auth/sso/oidc/redirect';

export const ssoApi = {
	/** `true` si la instancia tiene un proveedor configurado. */
	habilitado: async () => (await api.get<{ sso_enabled?: boolean }>('/auth/setup-status')).sso_enabled === true,
	/** `search` es el `?code=…&state=…` con que volvió el IdP. */
	callback: (search: string) => api.get<ResultadoCallbackSso>(`/auth/sso/oidc/callback${search}`),
	/** Vincular la cuenta ya abierta (QA-31): URL del IdP a la que ir. */
	vincular: () => api.post<{ authorization_url: string }>('/me/sso/link')
};
