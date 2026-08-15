// Autor: Athan Espinoza

// F-27: export/import personal en KDBX (KeePass), vía `kdbxweb` — formato
// binario real (AES-KDF/Argon2 + AES256/ChaCha20), no una reimplementación
// propia: el "100% client-side" de la spec se cumple porque nunca sale del
// navegador, no porque tenga que pasar por `ellkan_crypto.wasm` (ese wasm
// sigue siendo el único que toca los secretos de Ellkan, acá sólo empaqueta
// lo que `recursos.ts` ya descifró). TOTP se mapea al campo custom `otp`
// como URI `otpauth://` — convención ya compatible con KeePassXC/KeeWeb.

import * as kdbxweb from 'kdbxweb';
import { base32Codificar } from './base32';

export interface FilaExport {
	name: string;
	username: string;
	password: string;
	uri: string;
	notes: string;
	totp_secret: string;
}

function otpauthUri(nombre: string, secretoBase32: string): string {
	return `otpauth://totp/${encodeURIComponent(nombre)}?secret=${secretoBase32}&issuer=Ellkan&algorithm=SHA1&digits=6&period=30`;
}

export async function generarKdbx(filas: FilaExport[], masterPassword: string): Promise<ArrayBuffer> {
	const credenciales = new kdbxweb.KdbxCredentials(kdbxweb.ProtectedValue.fromString(masterPassword));
	const db = kdbxweb.Kdbx.create(credenciales, 'Ellkan');
	// El default de `Kdbx.create` es Argon2 (KDBX4) — `kdbxweb` no trae su
	// propia implementación de Argon2 (espera que la app registre
	// `CryptoEngine.setArgon2Impl`, algo que no existe acá) y tira
	// `NotImplemented` al guardar. AES-KDF sigue siendo un KDF real y
	// totalmente compatible con KeePass/KeePassXC, sin esa dependencia extra.
	db.setKdf(kdbxweb.Consts.KdfId.Aes);
	db.createDefaultGroup();
	const grupo = db.getDefaultGroup();

	for (const fila of filas) {
		const entry = db.createEntry(grupo);
		entry.fields.set('Title', fila.name);
		entry.fields.set('UserName', fila.username);
		entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(fila.password));
		entry.fields.set('URL', fila.uri);
		entry.fields.set('Notes', fila.notes);
		if (fila.totp_secret) {
			const secretoBase32 = /^[A-Z2-7]+$/.test(fila.totp_secret)
				? fila.totp_secret
				: base32Codificar(new TextEncoder().encode(fila.totp_secret));
			entry.fields.set('otp', otpauthUri(fila.name || 'Ellkan', secretoBase32));
		}
	}

	return db.save();
}

export async function parsearKdbx(bytes: ArrayBuffer, masterPassword: string): Promise<FilaExport[]> {
	const credenciales = new kdbxweb.KdbxCredentials(kdbxweb.ProtectedValue.fromString(masterPassword));
	let db: kdbxweb.Kdbx;
	try {
		db = await kdbxweb.Kdbx.load(bytes, credenciales);
	} catch {
		throw new Error('No se pudo abrir el archivo KDBX — contraseña incorrecta o archivo corrupto.');
	}

	function campo(entry: kdbxweb.KdbxEntry, nombre: string): string {
		const v = entry.fields.get(nombre);
		if (v === undefined) return '';
		return typeof v === 'string' ? v : v.getText();
	}

	function totpSecretDeOtp(entry: kdbxweb.KdbxEntry): string {
		const otp = campo(entry, 'otp');
		if (!otp) return '';
		try {
			const url = new URL(otp);
			return url.searchParams.get('secret') ?? '';
		} catch {
			return '';
		}
	}

	const filas: FilaExport[] = [];
	for (const grupo of db.groups) {
		for (const entry of grupo.allEntries()) {
			filas.push({
				name: campo(entry, 'Title'),
				username: campo(entry, 'UserName'),
				password: campo(entry, 'Password'),
				uri: campo(entry, 'URL'),
				notes: campo(entry, 'Notes'),
				totp_secret: totpSecretDeOtp(entry)
			});
		}
	}
	return filas;
}
