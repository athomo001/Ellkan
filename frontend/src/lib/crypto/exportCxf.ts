// Autor: Athan Espinoza

// F-27: export/import personal en CXF (Credential Exchange Format,
// estándar FIDO Alliance). Sólo el formato de archivo, no el protocolo de
// transferencia en vivo (CXP, fuera de alcance de v1 — ver spec F-27).
//
// Estructura verificada contra la fuente real, no contra la documentación
// renderizada: `credential-exchange-format/src/{lib,login,editable_field}.rs`
// del repo `github.com/bitwarden/credential-exchange` (el crate Rust que
// define el estándar), leído completo el 2026-09-14 tras encontrar que la
// versión anterior de este archivo tenía varias suposiciones nunca
// verificadas — todas resultaron incorrectas, no sólo una:
// - `EditableField` real es `{fieldType: "string"|"concealed-string", value,
//   id?, label?}` — la versión anterior emitía sólo `{value}`, sin
//   `fieldType` (campo obligatorio, sin el cual un importador conforme al
//   estándar no puede interpretar `value`).
// - `Header.version` real es un objeto `{major, minor}` (u8 cada uno), no
//   un string — la versión anterior emitía `"1.0"`.
// - Los campos del `Header` van en camelCase (`exporterRpId`,
//   `exporterDisplayName`) — la versión anterior usaba snake_case.
// - `Account.collections` es un campo obligatorio (`Vec<Collection>`, sin
//   `Option`) — la versión anterior no lo incluía en absoluto.
// - `OTPHashAlgorithm` usa `#[serde(rename_all = "lowercase")]` — la
//   versión anterior emitía `"SHA1"` en mayúsculas, que cualquier
//   importador conforme al estándar deserializa como variante `Unknown`,
//   no como SHA-1 real.
// El discriminador de `Credential` (`"type": "basic-auth"|"totp"|"note"`,
// `#[serde(tag = "type", rename_all = "kebab-case")]` sobre variantes Rust
// `BasicAuth`/`Totp`/`Note`) sí era correcto — no todo estaba mal, pero
// nada se dejó sin chequear contra la fuente esta vez.

import { base32Codificar } from './base32';

export interface FilaExport {
	name: string;
	username: string;
	password: string;
	uri: string;
	notes: string;
	totp_secret: string;
}

type CxfFieldType = 'string' | 'concealed-string';

interface CxfEditableField {
	fieldType: CxfFieldType;
	value: string;
}

function campoTexto(value: string): CxfEditableField {
	return { fieldType: 'string', value };
}

function campoOculto(value: string): CxfEditableField {
	return { fieldType: 'concealed-string', value };
}

interface CxfBasicAuthCredential {
	type: 'basic-auth';
	username?: CxfEditableField;
	password?: CxfEditableField;
}

/** `OTPHashAlgorithm` real: `Sha1`/`Sha256`/`Sha512` con `rename_all = "lowercase"`, más un `Unknown(String)` untagged — Ellkan sólo genera/verifica SHA1 (RFC 6238, F-08), pero un import puede traer cualquiera de las tres. */
type CxfOtpHashAlgorithm = 'sha1' | 'sha256' | 'sha512';

interface CxfTotpCredential {
	type: 'totp';
	secret: string;
	period: number;
	digits: number;
	algorithm: CxfOtpHashAlgorithm;
	issuer?: string;
}

interface CxfNoteCredential {
	type: 'note';
	content: CxfEditableField;
}

type CxfCredential = CxfBasicAuthCredential | CxfTotpCredential | CxfNoteCredential;

const TIPOS_CREDENCIAL_SOPORTADOS: ReadonlySet<string> = new Set(['basic-auth', 'totp', 'note']);

/** `CredentialScope` real (`credential_scope.rs`, `rename_all = "camelCase"`): `urls`/`androidApps` son obligatorios dentro del objeto (sin `Option`), el objeto entero es opcional en `Item.scope`. Ellkan sólo usa `urls` — sin apps Android que asociar. */
interface CxfCredentialScope {
	urls: string[];
	androidApps: never[];
}

interface CxfItem {
	id: string;
	title: string;
	credentials: CxfCredential[];
	scope?: CxfCredentialScope;
}

interface CxfAccount {
	id: string;
	username: string;
	email: string;
	/** Obligatorio en el schema real (`Vec<Collection>`, sin `Option`) — Ellkan no organiza en colecciones/carpetas dentro de un export CXF, así que siempre va vacío, nunca se omite. */
	collections: [];
	items: CxfItem[];
}

interface CxfVersion {
	major: number;
	minor: number;
}

interface CxfHeader {
	version: CxfVersion;
	exporterRpId: string;
	exporterDisplayName: string;
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
				username: fila.username ? campoTexto(fila.username) : undefined,
				password: fila.password ? campoOculto(fila.password) : undefined
			}
		];
		if (fila.totp_secret) {
			// Mismo cuidado que `exportKdbx.ts::generarKdbx`: el secreto guardado
			// no siempre viene ya en base32 (RFC 4648) — se detecta y se convierte
			// en vez de asumir, porque `secret` en el schema real es un `B32`.
			const secretoBase32 = /^[A-Z2-7]+$/.test(fila.totp_secret)
				? fila.totp_secret
				: base32Codificar(new TextEncoder().encode(fila.totp_secret));
			credenciales.push({
				type: 'totp',
				secret: secretoBase32,
				period: 30,
				digits: 6,
				algorithm: 'sha1',
				issuer: fila.name || undefined
			});
		}
		if (fila.notes) {
			credenciales.push({ type: 'note', content: campoTexto(fila.notes) });
		}
		return {
			id: idAleatorio(),
			title: fila.name || fila.uri || '(sin nombre)',
			credentials: credenciales,
			// `scope.urls` (CredentialScope real) es donde vive la URL de un
			// recurso en CXF — antes de este fix no se exportaba en absoluto,
			// se perdía en silencio (ninguno de los dos formatos JSON de
			// `BasicAuthCredential` tiene un campo de URL propio, el estándar
			// lo separa a propósito en `Item.scope` para poder listar varias
			// URLs/apps Android por credencial).
			scope: fila.uri ? { urls: [fila.uri], androidApps: [] } : undefined
		};
	});

	const header: CxfHeader = {
		version: { major: 1, minor: 0 },
		exporterRpId: 'ellkan',
		exporterDisplayName: 'Ellkan',
		timestamp: Math.floor(Date.now() / 1000),
		accounts: [{ id: idAleatorio(), username: cuentaEmail, email: cuentaEmail, collections: [], items }]
	};

	return JSON.stringify(header, null, 2);
}

/**
 * Cuenta cuántas credenciales de un CXF real tienen un `type` que Ellkan
 * todavía no importa (passkey, ssh-key, tarjeta de crédito, dirección,
 * etc. — tipos reales del estándar, sin equivalente en `FilaExport` hoy).
 * `parsearCxf` las descartaba en silencio; esto existe para poder avisarle
 * al usuario cuántas se perdieron, mismo criterio que motivó el fix del
 * importador CSV (nunca fallar/perder datos sin decirlo). Devuelve `0`
 * también ante un archivo inválido — `parsearCxf` es quien reporta ese
 * error, esto es sólo un conteo informativo adicional.
 */
export function contarCredencialesNoSoportadas(texto: string): number {
	let header: CxfHeader;
	try {
		header = JSON.parse(texto);
	} catch {
		return 0;
	}
	if (!Array.isArray(header.accounts)) return 0;

	let noSoportadas = 0;
	for (const cuenta of header.accounts) {
		for (const item of cuenta.items ?? []) {
			for (const cred of item.credentials ?? []) {
				if (!TIPOS_CREDENCIAL_SOPORTADOS.has(cred.type)) noSoportadas++;
			}
		}
	}
	return noSoportadas;
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
			const fila: FilaExport = {
				name: item.title ?? '',
				username: '',
				password: '',
				uri: item.scope?.urls?.[0] ?? '',
				notes: '',
				totp_secret: ''
			};
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
