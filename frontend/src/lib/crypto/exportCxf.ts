// Autor: Athan Espinoza

// F-27: export/import personal en CXF (Credential Exchange Format,
// estándar FIDO Alliance, Review Draft marzo 2025). Sólo el formato de
// archivo, no el protocolo de transferencia en vivo (CXP, fuera de
// alcance de v1 — ver spec F-27).
//
// Estructura y nombres de campo (Header/Account/Item/EditableField,
// BasicAuthCredential, TotpCredential) verificados contra la documentación
// pública del crate Rust `credential-exchange-format`
// (docs.rs/credential-exchange-format) en el momento de escribir esto. Lo
// que **no** se pudo verificar con certeza contra el schema oficial: el
// nombre exacto del discriminador de tipo del enum `Credential` en JSON
// (acá se usa `"type": "basic-auth"|"totp"`, la convención kebab-case
// estándar de serde para este tipo de enum) y el formato exacto del campo
// `version`. El export/import de Ellkan es autoconsistente y se verifica
// de punta a punta contra sí mismo (round-trip); la interoperabilidad
// byte-exacta con un cliente externo (1Password, Apple, Google) no está
// verificada en esta sesión — documentado acá en vez de asumido.

export interface FilaExport {
	name: string;
	username: string;
	password: string;
	uri: string;
	notes: string;
	totp_secret: string;
}

interface CxfEditableField {
	value: string;
}

interface CxfBasicAuthCredential {
	type: 'basic-auth';
	username?: CxfEditableField;
	password?: CxfEditableField;
}

interface CxfTotpCredential {
	type: 'totp';
	secret: string;
	period: number;
	digits: number;
	algorithm: 'SHA1';
	issuer?: string;
}

interface CxfNoteCredential {
	type: 'note';
	content: CxfEditableField;
}

type CxfCredential = CxfBasicAuthCredential | CxfTotpCredential | CxfNoteCredential;

interface CxfItem {
	id: string;
	title: string;
	credentials: CxfCredential[];
}

interface CxfAccount {
	id: string;
	username: string;
	email: string;
	items: CxfItem[];
}

interface CxfHeader {
	version: string;
	exporter_rp_id: string;
	exporter_display_name: string;
	timestamp: number;
	accounts: CxfAccount[];
}

function idAleatorio(): string {
	return crypto.randomUUID().replace(/-/g, '');
}

export function generarCxf(filas: FilaExport[], cuentaEmail: string): string {
	const items: CxfItem[] = filas.map((fila) => {
		const credenciales: CxfCredential[] = [
			{
				type: 'basic-auth',
				username: fila.username ? { value: fila.username } : undefined,
				password: fila.password ? { value: fila.password } : undefined
			}
		];
		if (fila.totp_secret) {
			credenciales.push({
				type: 'totp',
				secret: fila.totp_secret,
				period: 30,
				digits: 6,
				algorithm: 'SHA1',
				issuer: fila.name || undefined
			});
		}
		if (fila.notes) {
			credenciales.push({ type: 'note', content: { value: fila.notes } });
		}
		return { id: idAleatorio(), title: fila.name || fila.uri || '(sin nombre)', credentials: credenciales };
	});

	const header: CxfHeader = {
		version: '1.0',
		exporter_rp_id: 'ellkan',
		exporter_display_name: 'Ellkan',
		timestamp: Math.floor(Date.now() / 1000),
		accounts: [{ id: idAleatorio(), username: cuentaEmail, email: cuentaEmail, items }]
	};

	return JSON.stringify(header, null, 2);
}

export function parsearCxf(texto: string): FilaExport[] {
	let header: CxfHeader;
	try {
		header = JSON.parse(texto);
	} catch {
		throw new Error('El archivo no es un JSON válido.');
	}
	if (!Array.isArray(header.accounts)) throw new Error('El archivo no tiene el formato CXF esperado.');

	const filas: FilaExport[] = [];
	for (const cuenta of header.accounts) {
		for (const item of cuenta.items ?? []) {
			const fila: FilaExport = { name: item.title ?? '', username: '', password: '', uri: '', notes: '', totp_secret: '' };
			for (const cred of item.credentials ?? []) {
				if (cred.type === 'basic-auth') {
					fila.username = cred.username?.value ?? '';
					fila.password = cred.password?.value ?? '';
				} else if (cred.type === 'totp') {
					fila.totp_secret = cred.secret ?? '';
				} else if (cred.type === 'note') {
					fila.notes = cred.content?.value ?? '';
				}
			}
			filas.push(fila);
		}
	}
	return filas;
}
