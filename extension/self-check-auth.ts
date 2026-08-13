// Autor: Athan Espinoza

// Chequeo de integración real del login de la extensión — corre el mismo
// código que usa el popup (`background/services/auth-service.ts`) contra el
// backend real de desarrollo (`docker compose`, `docs/seed-test-users.md`),
// no un doble/mock del backend. Mockea sólo lo que Node no tiene
// (`chrome.storage`, `chrome.runtime.getURL`) — la red y el wasm son reales.
//
// Requiere el backend real corriendo en `http://localhost:8080` (o pasar
// otra URL como primer argumento) con el usuario seed `juan.perez@ellkan.local`.
//
// Correr: node run-self-check.mjs self-check-auth.ts

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const SERVER_URL = process.argv[2] ?? 'http://localhost:8080';
const EMAIL = 'juan.perez@ellkan.local';
const PASSPHRASE = 'Ellkan!Juan-Ventas-47';

// Mismo parche de `fetch` que `self-check-storage.ts` para el `.wasm` —
// ver ese archivo para el porqué. Las llamadas HTTP reales (`fetch` al
// backend) NO se interceptan, viajan de verdad.
const ARTEFACTO_WASM_REAL = resolve(process.cwd(), '../frontend/src/lib/wasm/ellkan_crypto_bg.wasm');
const fetchOriginal = globalThis.fetch;
globalThis.fetch = (async (entrada: RequestInfo | URL, init?: RequestInit) => {
	const url = typeof entrada === 'string' ? entrada : entrada instanceof URL ? entrada.href : entrada.url;
	if (url.endsWith('.wasm')) {
		let ruta: string;
		try {
			ruta = fileURLToPath(url);
			readFileSync(ruta);
		} catch {
			ruta = ARTEFACTO_WASM_REAL;
		}
		return new Response(readFileSync(ruta), { headers: { 'Content-Type': 'application/wasm' } });
	}
	return fetchOriginal(entrada, init);
}) as typeof fetch;

function mapStorage() {
	const datos = new Map<string, unknown>();
	return {
		async get(keys: string | string[] | null): Promise<Record<string, unknown>> {
			const lista = keys === null ? [...datos.keys()] : Array.isArray(keys) ? keys : [keys];
			const resultado: Record<string, unknown> = {};
			for (const k of lista) if (datos.has(k)) resultado[k] = datos.get(k);
			return resultado;
		},
		async set(items: Record<string, unknown>): Promise<void> {
			for (const [k, v] of Object.entries(items)) datos.set(k, v);
		},
		async remove(keys: string | string[]): Promise<void> {
			for (const k of Array.isArray(keys) ? keys : [keys]) datos.delete(k);
		}
	};
}

(globalThis as Record<string, unknown>).chrome = {
	storage: { session: mapStorage(), local: mapStorage() },
	runtime: { getURL: (path: string) => `file://${resolve(process.cwd(), '../frontend/src/lib/wasm', path)}` }
};

const { AuthController } = await import('./src/background/controllers/auth-controller.ts');
const { VaultController } = await import('./src/background/controllers/vault-controller.ts');

const MAILHOG_URL = process.argv[3] ?? 'http://localhost:8025';

interface MailhogItem {
	Created: string;
	Content: { Body: string };
}

/** El envío es asíncrono del lado del backend (cola `outbound_emails` +
 * poller, mismo patrón que el resto del proyecto) — se reintenta con
 * backoff corto hasta encontrar un email **posterior** a `desde` (nunca uno
 * viejo de una corrida anterior de este mismo chequeo, que dejaría un
 * código ya vencido/consumido). */
async function leerCodigoDeMailhog(desde: Date): Promise<string> {
	for (let intento = 0; intento < 20; intento++) {
		const resp = await fetchOriginal(`${MAILHOG_URL}/api/v2/search?kind=to&query=${encodeURIComponent(EMAIL)}&limit=5`);
		const cuerpo = (await resp.json()) as { items: MailhogItem[] };
		const reciente = cuerpo.items.find((item) => new Date(item.Created) >= desde);
		if (reciente) {
			const match = reciente.Content.Body.match(/(\d{6})/);
			if (!match) throw new Error('no se encontró un código de 6 dígitos en el email');
			return match[1];
		}
		await new Promise((r) => setTimeout(r, 300));
	}
	throw new Error(`no llegó ningún email nuevo a ${EMAIL} en Mailhog (${MAILHOG_URL}) tras varios reintentos`);
}

async function main() {
	// --- Login real: passphrase correcta, dispositivo nuevo (siempre, en
	// este chequeo — `chrome.storage.local` mockeado arranca vacío cada
	// corrida) → el backend tiene que pedir verificación de dispositivo. ---
	const antesDelLogin = new Date();
	const resultado = await AuthController.login({ serverUrl: SERVER_URL, email: EMAIL, passphrase: PASSPHRASE });
	assert.equal(resultado.estado, 'pendiente_dispositivo', `se esperaba pendiente_dispositivo, vino "${resultado.estado}"`);
	assert.ok(resultado.deviceChallengeId, 'debe venir un deviceChallengeId para poder verificar el dispositivo');
	console.log('OK: login real (key-material→Argon2id→challenge→firma→verify) contra el backend real');

	// --- Las claves ya se guardaron en `storage.session` aunque falte el
	// dispositivo — confirma que el login no se pierde a mitad de camino. ---
	const sesionParcial = await AuthController.estadoSesion();
	assert.equal(sesionParcial, null, 'sin session_id todavía no debe reportarse como sesión activa');
	console.log('OK: sesión parcial (claves guardadas, sin session_id) no se confunde con sesión completa');

	// --- Bug real reportado por el usuario: el popup se cierra solo al
	// perder el foco (cambiar de pestaña para leer el código del email) —
	// `storage.session` (mockeado acá con el mismo Map, que sobrevive porque
	// es el "service worker" el que lo posee, no el popup) tiene que alcanzar
	// para retomar exactamente donde quedó, sin repetir el login. ---
	const pendiente = await AuthController.estadoPendienteDispositivo();
	assert.ok(pendiente, 'debe quedar un desafío pendiente recuperable tras cerrar y reabrir el popup');
	assert.equal(pendiente!.email, EMAIL);
	assert.equal(pendiente!.deviceChallengeId, resultado.deviceChallengeId);
	console.log('OK: AUTH_ESTADO_PENDIENTE_DISPOSITIVO sobrevive al cierre del popup (sesión parcial recuperable)');

	// --- Passphrase incorrecta: el backend/wasm deben rechazarla, nunca
	// devolver "completo" con una clave mal desenvuelta. ---
	let fallo = false;
	try {
		await AuthController.login({ serverUrl: SERVER_URL, email: EMAIL, passphrase: 'passphrase-incorrecta-a-proposito' });
	} catch {
		fallo = true;
	}
	assert.ok(fallo, 'una passphrase incorrecta debe fallar, nunca devolver una sesión');
	console.log('OK: passphrase incorrecta rechazada');

	// --- Flujo completo: código real leído de Mailhog (mismo patrón que
	// `docs/seed-test-users.md`), verificar dispositivo, sesión completa,
	// logout real. ---
	const codigo = await leerCodigoDeMailhog(antesDelLogin);
	const verificado = await AuthController.verificarDispositivo({ serverUrl: SERVER_URL, deviceChallengeId: resultado.deviceChallengeId!, codigo });
	assert.equal(verificado.estado, 'completo', `se esperaba completo tras verificar el dispositivo, vino "${verificado.estado}"`);
	console.log('OK: verificación de dispositivo con el código real completa el login');

	const sesionCompleta = await AuthController.estadoSesion();
	assert.ok(sesionCompleta, 'debe haber una sesión activa después del login completo');
	assert.equal(sesionCompleta!.email, EMAIL);
	assert.equal(sesionCompleta!.serverUrl, SERVER_URL);
	console.log('OK: AUTH_ESTADO_SESION refleja la sesión real recién creada');

	const pendienteTrasCompletar = await AuthController.estadoPendienteDispositivo();
	assert.equal(pendienteTrasCompletar, null, 'el desafío pendiente debe limpiarse solo al completar la verificación');
	console.log('OK: el estado pendiente se limpia solo al completar el login, sin dejar residuo');

	// --- Quick Access (spec 06 §2): listar y revelar contra la sesión real
	// recién creada — usa el recurso sembrado en `docs/seed-test-users.md`
	// ("CRM Ventas", dueño juan.perez@ellkan.local) para verificar el
	// round-trip completo de descifrado, no sólo que el código no explote. ---
	const items = await VaultController.listar();
	const crm = items.find((i) => i.nombre === 'CRM Ventas');
	assert.ok(crm, `se esperaba encontrar "CRM Ventas" en la lista, vino: ${items.map((i) => i.nombre).join(', ')}`);
	assert.equal(crm!.usuario, 'juan.perez');
	console.log(`OK: VAULT_LISTAR descifra metadata real (${items.length} recurso(s), incluido "CRM Ventas")`);

	const { password } = await VaultController.revelarPassword({ resourceId: crm!.id });
	assert.equal(password, 'Rsc-Juan-Crm-41k', 'la contraseña revelada debe coincidir con la sembrada en docs/seed-test-users.md');
	console.log('OK: VAULT_REVELAR_PASSWORD descifra el secreto real, coincide con el valor sembrado');

	await AuthController.logout();
	const sesionTrasLogout = await AuthController.estadoSesion();
	assert.equal(sesionTrasLogout, null, 'tras logout no debe quedar ninguna sesión');
	console.log('OK: logout real (invalida server-side + limpia el estado local)');

	console.log('\nself-check-auth: todo OK');
}

main().catch((e) => {
	console.error('self-check-auth FALLÓ:', e);
	process.exitCode = 1;
});
