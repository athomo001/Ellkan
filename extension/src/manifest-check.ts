// Autor: Athan Espinoza

// Test dedicado de `frame-ancestors 'none'` sobre TODA página propia de la
// extensión (spec 05 §2.1, hallazgo PBL-08-001, **High**, Cure53): el más
// grave de los cuatro reportes fue credential leakage por **clickjacking**
// contra la extensión — no alcanza con asumir que el sandbox de la extensión
// ya lo resuelve. En MV3, `content_security_policy.extension_pages` aplica a
// CADA página de la extensión (popup incluido), así que verificar esa
// directiva cubre todas de una — pero sólo si además ninguna página se
// expone vía `web_accessible_resources` (una página de extensión cargable
// por cualquier sitio es el vector distinto, BWN-08-019).
//
// Lógica pura sobre el manifest ya resuelto por navegador — el self-check la
// corre contra chrome/firefox/safari.

export interface ManifestParcial {
	manifest_version?: number;
	content_security_policy?: { extension_pages?: string; sandbox?: string } | string;
	web_accessible_resources?: unknown;
	action?: { default_popup?: string };
	background?: { service_worker?: string; scripts?: string[] };
	browser_specific_settings?: { gecko?: { id?: string } };
	permissions?: string[];
	host_permissions?: string[];
}

function parseCsp(csp: string): Record<string, string[]> {
	const out: Record<string, string[]> = {};
	for (const parte of csp.split(';')) {
		const toks = parte
			.trim()
			.split(/\s+/)
			.filter(Boolean);
		if (toks.length === 0) continue;
		out[toks[0].toLowerCase()] = toks.slice(1);
	}
	return out;
}

/** Problemas de la CSP de páginas de extensión (lista vacía = OK). */
export function problemasDeCsp(m: ManifestParcial): string[] {
	const problemas: string[] = [];
	const csp = typeof m.content_security_policy === 'object' ? m.content_security_policy?.extension_pages : undefined;
	if (!csp) {
		problemas.push('falta content_security_policy.extension_pages — sin ella las páginas propias no llevan CSP restrictiva');
		return problemas;
	}
	const dir = parseCsp(csp);

	if ((dir['frame-ancestors'] ?? []).join(' ') !== "'none'") {
		problemas.push("frame-ancestors debe ser exactamente 'none' (anti-clickjacking, PBL-08-001)");
	}
	if (!dir['script-src'] || dir['script-src'].includes("'unsafe-inline'") || dir['script-src'].includes('*')) {
		problemas.push("script-src no debe permitir 'unsafe-inline' ni comodín");
	}
	const objectSrc = (dir['object-src'] ?? []).join(' ');
	if (objectSrc !== "'none'" && objectSrc !== "'self'") {
		problemas.push("object-src debe ser 'none' o 'self'");
	}
	return problemas;
}

/**
 * Diferencias reales de manifest MV3 por navegador (spec 06 §1/§7), como
 * chequeo — no basta con que la clave `__firefox__*` exista en el fuente, el
 * manifest RESUELTO tiene que quedar bien formado para el navegador destino:
 *  - Chromium: `background.service_worker` (no `scripts`).
 *  - Firefox MV3: `background.scripts` (no soporta `service_worker` igual) +
 *    `browser_specific_settings.gecko.id` (obligatorio para firmar/actualizar
 *    en AMO).
 *  - Safari: se empaqueta aparte con Xcode, pero el manifest resuelto usa el
 *    mismo shape de background por `scripts` que Firefox.
 * Devuelve la lista de problemas (vacía = OK).
 */
export function problemasPorNavegador(m: ManifestParcial, navegador: string): string[] {
	const problemas: string[] = [];
	const bg = m.background ?? {};
	if (navegador === 'chrome') {
		if (!bg.service_worker) problemas.push('chrome: background.service_worker ausente (MV3)');
		if (bg.scripts) problemas.push('chrome: background.scripts no debería estar en el manifest de Chromium');
	} else {
		if (!Array.isArray(bg.scripts) || bg.scripts.length === 0) {
			problemas.push(`${navegador}: background.scripts ausente (Firefox/Safari MV3 no usan service_worker igual)`);
		}
		if (bg.service_worker) problemas.push(`${navegador}: background.service_worker no aplica a este navegador`);
	}
	if (navegador === 'firefox' && !m.browser_specific_settings?.gecko?.id) {
		problemas.push('firefox: falta browser_specific_settings.gecko.id (obligatorio para AMO)');
	}
	if (m.manifest_version !== 3) problemas.push(`${navegador}: manifest_version debe ser 3`);
	return problemas;
}

/** `.html` expuestos vía `web_accessible_resources` — deben ser cero (una
 * página de extensión cargable por cualquier sitio es el vector de
 * BWN-08-019, y además esquiva la CSP de `extension_pages` verificada arriba). */
export function htmlExpuestoEnWAR(m: ManifestParcial): string[] {
	const war = m.web_accessible_resources;
	if (!Array.isArray(war)) return [];
	const encontrados: string[] = [];
	for (const entrada of war as unknown[]) {
		const recursos: unknown[] = Array.isArray(entrada)
			? entrada
			: ((entrada as { resources?: unknown[] } | null)?.resources ?? []);
		for (const r of recursos) {
			if (typeof r === 'string' && r.toLowerCase().endsWith('.html')) encontrados.push(r);
		}
	}
	return encontrados;
}
