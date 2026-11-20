// Autor: Athan Espinoza

// Puerto puro (sin dependencias) de `frontend/src/lib/crypto/recursos.ts::
// comandoDeConexion`/`parsearHostPuerto` — no se importa ese módulo directo
// porque arrastra `$lib/api/client`/`$lib/cache/metadataCache` (alias de
// SvelteKit, no resuelven fuera de ese build, spec 06 §5 "SvelteKit no es
// importable en un content script/popup"). Mismo comportamiento exacto,
// duplicado a propósito por ser puro texto sin cripto de por medio.

const PUERTOS_DEFAULT: Record<string, number> = {
	ssh: 22,
	ftp: 21,
	telnet: 23,
	vnc: 5900,
	rdp: 3389,
	postgresql: 5432,
	mysql: 3306,
	mongodb: 27017
};

function parsearHostPuerto(uri: string): { host: string; puerto?: number } {
	const sinEsquema = uri.replace(/^[a-z]+:\/\//i, '').trim();
	const idx = sinEsquema.lastIndexOf(':');
	if (idx === -1) return { host: sinEsquema };
	const resto = sinEsquema.slice(idx + 1);
	const puerto = Number(resto);
	if (!resto || !Number.isInteger(puerto)) return { host: sinEsquema };
	return { host: sinEsquema.slice(0, idx), puerto };
}

/** El comando se copia para pegarlo en una terminal, y el recurso puede venir
 * compartido o importado: usuario y host sólo pueden tener caracteres que no
 * cambien su significado (sin `;`, `&`, `|`, `$`, comillas, espacios…) ni
 * empezar con `-`, que se leería como una opción (`-oProxyCommand=…`). Si no
 * cumplen, no se ofrece comando. Mismo criterio que el frontend. */
const HOST_SEGURO = /^[A-Za-z0-9._%\-[\]:]+$/;
const USUARIO_SEGURO = /^[A-Za-z0-9._%+@\-]+$/;
function seguroParaComando(valor: string, patron: RegExp): boolean {
	return patron.test(valor) && !valor.startsWith('-');
}

/** `null` si el tipo de recurso no tiene un comando de conexión asociado
 * (ej. `login-password`, que en cambio se muestra como link clickable). */
export function comandoDeConexion(resourceTypeSlug: string, usuario: string, uri: string): string | null {
	if (!uri || !(resourceTypeSlug in PUERTOS_DEFAULT)) return null;
	const { host, puerto } = parsearHostPuerto(uri);
	if (!seguroParaComando(host, HOST_SEGURO) || (usuario && !seguroParaComando(usuario, USUARIO_SEGURO))) return null;
	const puertoDefault = PUERTOS_DEFAULT[resourceTypeSlug];
	const puertoNoDefault = puerto !== undefined && puerto !== puertoDefault ? puerto : undefined;
	const arroba = usuario ? `${usuario}@` : '';

	switch (resourceTypeSlug) {
		case 'ssh':
			return `ssh ${arroba}${host}${puertoNoDefault ? ` -p ${puertoNoDefault}` : ''}`;
		case 'telnet':
			return `telnet ${host}${puertoNoDefault ? ` ${puertoNoDefault}` : ''}`;
		case 'ftp':
			return `ftp://${arroba}${host}${puertoNoDefault ? `:${puertoNoDefault}` : ''}`;
		case 'vnc':
			return `vnc://${arroba}${host}${puertoNoDefault ? `:${puertoNoDefault}` : ''}`;
		case 'rdp':
			return `mstsc /v:${host}${puertoNoDefault ? `:${puertoNoDefault}` : ''}`;
		case 'postgresql':
			return `psql -h ${host} -p ${puerto ?? puertoDefault}${usuario ? ` -U ${usuario}` : ''}`;
		case 'mysql':
			return `mysql -h ${host} -P ${puerto ?? puertoDefault}${usuario ? ` -u ${usuario}` : ''} -p`;
		case 'mongodb':
			return `mongosh "mongodb://${arroba}${host}:${puerto ?? puertoDefault}/"`;
		default:
			return null;
	}
}

/** URL absoluta lista para `window.open`/`href` — sólo para tipos sin
 * comando de conexión propio (`login-password`), agrega `https://` si el
 * campo libre de la URI no trae esquema. */
export function urlAbrible(resourceTypeSlug: string, uri: string): string | null {
	if (!uri || resourceTypeSlug in PUERTOS_DEFAULT) return null;
	// Sólo http(s): una URI guardada como `javascript://…` o `data:…` no se
	// abre nunca, aunque la CSP de la extensión ya la bloquearía.
	// `host:puerto` (ej. `localhost:8080`) no es un esquema.
	if (/^[a-z][a-z0-9+.-]*:/i.test(uri) && !/^https?:\/\//i.test(uri) && !/^[^:/]+:\d+(\/|$)/.test(uri)) return null;
	return /^https?:\/\//i.test(uri) ? uri : `https://${uri}`;
}

/** Hostname limpio para pedir el favicon real del sitio (spec 06 §5bis, tras
 * comparar contra capturas reales de Proton Pass — usan el ícono real del
 * sitio, no un glifo genérico). `null` para tipos sin sentido de favicon
 * (ssh/ftp/vnc/telnet) o uri vacía. */
export function hostnameParaFavicon(resourceTypeSlug: string, uri: string): string | null {
	if (!uri || resourceTypeSlug in PUERTOS_DEFAULT) return null;
	try {
		const conEsquema = /^[a-z]+:\/\//i.test(uri) ? uri : `https://${uri}`;
		return new URL(conEsquema).hostname.toLowerCase();
	} catch {
		return null;
	}
}
