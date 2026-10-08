// Autor: Athan Espinoza

// F-58: ayudas client-side para el tipo `api-token`. Todo corre en el
// navegador/webview: ni el token ni su fecha de vencimiento salen del cliente
// (la fecha vive dentro de la metadata cifrada).

/** Días antes del vencimiento a partir de los cuales se avisa (fijo, F-58). */
export const UMBRAL_VENCIMIENTO_DIAS = 14;

export interface ProveedorDetectado {
	nombre: string;
	uri: string;
}

// Prefijos públicos y documentados por cada proveedor. El orden importa: los
// más específicos primero (`sk-ant-` antes que `sk-`).
const PREFIJOS: { prefijo: RegExp; nombre: string; uri: string }[] = [
	{ prefijo: /^github_pat_/, nombre: 'GitHub', uri: 'https://github.com' },
	{ prefijo: /^gh[pousr]_/, nombre: 'GitHub', uri: 'https://github.com' },
	{ prefijo: /^glpat-/, nombre: 'GitLab', uri: 'https://gitlab.com' },
	{ prefijo: /^sk-ant-/, nombre: 'Anthropic', uri: 'https://console.anthropic.com' },
	{ prefijo: /^sk-/, nombre: 'OpenAI', uri: 'https://platform.openai.com' },
	{ prefijo: /^xox[abpr]-/, nombre: 'Slack', uri: 'https://api.slack.com' },
	{ prefijo: /^(AKIA|ASIA)[0-9A-Z]{16}$/, nombre: 'AWS', uri: 'https://console.aws.amazon.com' },
	{ prefijo: /^AIza/, nombre: 'Google Cloud', uri: 'https://console.cloud.google.com' },
	{ prefijo: /^(sk|rk|pk)_(live|test)_/, nombre: 'Stripe', uri: 'https://dashboard.stripe.com' },
	{ prefijo: /^npm_/, nombre: 'npm', uri: 'https://www.npmjs.com' },
	{ prefijo: /^pypi-/, nombre: 'PyPI', uri: 'https://pypi.org' },
	{ prefijo: /^dop_v1_/, nombre: 'DigitalOcean', uri: 'https://cloud.digitalocean.com' },
	{ prefijo: /^hf_/, nombre: 'Hugging Face', uri: 'https://huggingface.co' }
];

/** Sugiere nombre/URI a partir del prefijo del token. Sólo una sugerencia:
 * nunca se envía nada a ningún lado. */
export function detectarProveedor(token: string): ProveedorDetectado | null {
	const limpio = token.trim();
	if (!limpio) return null;
	// JSON de service account de Google Cloud pegado entero.
	if (limpio.startsWith('{') && limpio.includes('"type"') && limpio.includes('"service_account"')) {
		return { nombre: 'Google Cloud (service account)', uri: 'https://console.cloud.google.com' };
	}
	const encontrado = PREFIJOS.find((p) => p.prefijo.test(limpio));
	return encontrado ? { nombre: encontrado.nombre, uri: encontrado.uri } : null;
}

export type EstadoVencimiento = { estado: 'vencido'; dias: number } | { estado: 'por-vencer'; dias: number } | { estado: 'vigente' };

/** Estado de un `expires_at` (`YYYY-MM-DD`) respecto de `hoy`. `null` si no
 * hay fecha o no se puede leer. `dias` = días enteros que faltan (o que
 * pasaron, en `vencido`). Vence al terminar el día indicado. */
export function estadoVencimiento(expiresAt: string | undefined, hoy: Date = new Date()): EstadoVencimiento | null {
	if (!expiresAt) return null;
	const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(expiresAt);
	if (!m) return null;
	const vence = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
	const hoyUtc = Date.UTC(hoy.getFullYear(), hoy.getMonth(), hoy.getDate());
	const dias = Math.round((vence - hoyUtc) / 86_400_000);
	if (dias < 0) return { estado: 'vencido', dias: -dias };
	if (dias <= UMBRAL_VENCIMIENTO_DIAS) return { estado: 'por-vencer', dias };
	return { estado: 'vigente' };
}
