import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
//#region self-check-storage.ts
var fetchOriginal = globalThis.fetch;
globalThis.fetch = (async (entrada, init) => {
	const url = typeof entrada === "string" ? entrada : entrada instanceof URL ? entrada.href : entrada.url;
	if (url.endsWith(".wasm")) {
		const buffer = readFileSync(fileURLToPath(url));
		return new Response(buffer, { headers: { "Content-Type": "application/wasm" } });
	}
	return fetchOriginal(entrada, init);
});
function mapStorage() {
	const datos = /* @__PURE__ */ new Map();
	return {
		async get(keys) {
			const lista = keys === null ? [...datos.keys()] : Array.isArray(keys) ? keys : [keys];
			const resultado = {};
			for (const k of lista) if (datos.has(k)) resultado[k] = datos.get(k);
			return resultado;
		},
		async set(items) {
			for (const [k, v] of Object.entries(items)) datos.set(k, v);
		},
		async remove(keys) {
			for (const k of Array.isArray(keys) ? keys : [keys]) datos.delete(k);
		},
		_datos: datos
	};
}
var sessionMock = mapStorage();
var localMock = mapStorage();
globalThis.chrome = { storage: {
	session: sessionMock,
	local: localMock
} };
var { SesionStorage } = await import("./sesion-storage-bcgpzp06.js");
var { MetadataCache } = await import("./metadata-cache--xAFZR8M.js");
async function main() {
	assert.equal(await SesionStorage.leer("passphrase"), null, "sin nada guardado, debe leer null");
	await SesionStorage.guardar("passphrase", "una-passphrase-de-prueba");
	assert.equal(await SesionStorage.leer("passphrase"), "una-passphrase-de-prueba");
	await SesionStorage.limpiar("passphrase");
	assert.equal(await SesionStorage.leer("passphrase"), null, "tras limpiar, debe volver a null");
	console.log("OK: SesionStorage (nivel 2) guarda/lee/limpia");
	const datosDePrueba = { recursos: [{
		id: "1",
		nombre: "CRM Ventas"
	}] };
	await MetadataCache.guardar(datosDePrueba);
	assert.ok(localMock._datos.size > 0, "debe haber escrito ciphertext en storage.local");
	const leido = await MetadataCache.leer();
	assert.deepEqual(leido, datosDePrueba, "debe descifrar exactamente lo mismo que se guardó");
	console.log("OK: MetadataCache (nivel 3) cifra/descifra con la clave efímera (AEAD real via wasm)");
	sessionMock._datos.clear();
	assert.ok(localMock._datos.size > 0, "precondición: todavía hay ciphertext residual en local");
	const trasPerderLaClave = await MetadataCache.leer();
	assert.equal(trasPerderLaClave, null, "sin la clave efímera, debe leer null (nunca intentar \"recuperar\")");
	assert.equal(localMock._datos.size, 0, "el residuo huérfano debe purgarse, no quedar sin uso");
	console.log("OK: sin clave efímera, el residuo cifrado se purga en vez de reintentarse");
	console.log("\nself-check-storage: todo OK");
}
main().catch((e) => {
	console.error("self-check-storage FALLÓ:", e);
	process.exitCode = 1;
});
//#endregion
export {};
