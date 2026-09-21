// Autor: Athan Espinoza
//
// Checks de `src/lib/sync/traspaso.ts` (punto 7: diagnóstico del traspaso de
// datos entre el servidor y la bóveda de escritorio). El módulo es puro y sin
// imports, así que Node lo carga directo (Node >= 22.18 saca los tipos solo).
//
//   node scripts/check-traspaso.mjs
//
// Sale con código != 0 si algún check falla.

import assert from 'node:assert/strict';
import { compararTraspaso } from '../src/lib/sync/traspaso.ts';

const env = (n) => ({ sealedDekB64: `dek-${n}`, secretCiphertextB64: `cipher-${n}`, secretNonceB64: `nonce-${n}` });
const remoto = (id, n = id) => ({ id, metadataCiphertextB64: `meta-${n}`, metadataNonceB64: `mn-${n}`, secreto: env(n) });
const local = (id, n = id, extra = {}) => ({
	id,
	metadataCiphertextB64: `meta-${n}`,
	metadataNonceB64: `mn-${n}`,
	secretoLocal: env(n),
	dekLocalB64: null,
	...extra
});
const tipos = (informe) => informe.hallazgos.map((h) => `${h.severidad}:${h.tipo}:${h.id}`).sort();

let hechos = 0;
function caso(nombre, fn) {
	fn();
	hechos++;
	console.log(`ok - ${nombre}`);
}

caso('full: réplica completa idéntica en los dos lados es sana y sin hallazgos', () => {
	const i = compararTraspaso({ modo: 'full', remotos: [remoto('a'), remoto('b')], locales: [local('a'), local('b')] });
	assert.equal(i.sano, true);
	assert.equal(i.sinHallazgos, 2);
	assert.deepEqual(i.hallazgos, []);
});

caso('bóveda vacía en los dos lados es sana', () => {
	const i = compararTraspaso({ modo: 'memory', remotos: [], locales: [] });
	assert.equal(i.sano, true);
	assert.equal(i.sinHallazgos, 0);
});

caso('full: detecta falta local, solo local, metadata distinta, secreto faltante y secreto distinto', () => {
	const i = compararTraspaso({
		modo: 'full',
		remotos: [remoto('falta'), remoto('meta'), remoto('sinsec'), remoto('distinto'), remoto('ok')],
		locales: [
			local('meta', 'meta', { metadataCiphertextB64: 'otra-meta' }),
			local('sinsec', 'sinsec', { secretoLocal: null }),
			local('distinto', 'distinto', { secretoLocal: { ...env('distinto'), secretCiphertextB64: 'manipulado' } }),
			local('ok'),
			local('soloLocal')
		]
	});
	assert.deepEqual(tipos(i), [
		'aviso:metadata_distinta:meta',
		'aviso:solo_local:soloLocal',
		'error:falta_local:falta',
		'error:secreto_distinto:distinto',
		'error:secreto_faltante_en_full:sinsec'
	]);
	assert.equal(i.sano, false);
	assert.equal(i.errores, 3);
	assert.equal(i.avisos, 2);
	assert.equal(i.sinHallazgos, 1, 'sólo "ok" está en los dos lados sin hallazgos');
});

caso('full: secreto remoto ilegible es aviso, no error (no se puede comparar pero el local existe)', () => {
	const r = { ...remoto('a'), secreto: null };
	const i = compararTraspaso({ modo: 'full', remotos: [r], locales: [local('a')] });
	assert.deepEqual(tipos(i), ['aviso:secreto_remoto_ilegible:a']);
	assert.equal(i.sano, true);
});

caso('memory: sin secreto local pero con DEK local es lo esperado', () => {
	const i = compararTraspaso({
		modo: 'memory',
		remotos: [remoto('a'), remoto('b')],
		locales: [local('a', 'a', { secretoLocal: null, dekLocalB64: 'dek-a' }), local('b', 'b', { secretoLocal: null, dekLocalB64: 'dek-b' })]
	});
	assert.equal(i.sano, true);
	assert.equal(i.sinHallazgos, 2);
});

caso('names_only: falta el DEK local es un error (la metadata no se descifra offline)', () => {
	const i = compararTraspaso({
		modo: 'names_only',
		remotos: [remoto('a')],
		locales: [local('a', 'a', { secretoLocal: null, dekLocalB64: null })]
	});
	assert.deepEqual(tipos(i), ['error:dek_faltante:a']);
	assert.equal(i.sano, false);
});

caso('memory: secreto replicado de antes del cambio de modo es sólo informativo', () => {
	const i = compararTraspaso({ modo: 'memory', remotos: [remoto('a')], locales: [local('a')] });
	assert.deepEqual(tipos(i), ['info:secreto_replicado_en_modo_restringido:a']);
	assert.equal(i.sano, true, 'una réplica previa no rompe el traspaso');
	assert.equal(i.infos, 1);
});

caso('memory: si el servidor no entrega el secreto es un error (no se podría ver en este modo)', () => {
	const r = { ...remoto('a'), secreto: null };
	const i = compararTraspaso({
		modo: 'memory',
		remotos: [r],
		locales: [local('a', 'a', { secretoLocal: null, dekLocalB64: 'dek-a' })]
	});
	assert.deepEqual(tipos(i), ['error:secreto_remoto_ilegible:a']);
	assert.equal(i.sano, false);
});

caso('el informe nunca filtra bytes cifrados ni DEKs', () => {
	const i = compararTraspaso({
		modo: 'full',
		remotos: [remoto('x')],
		locales: [local('x', 'x', { secretoLocal: { ...env('x'), secretCiphertextB64: 'CIPHER-SECRETO-NO-FILTRAR' } })]
	});
	const texto = JSON.stringify(i);
	assert.ok(!texto.includes('CIPHER-SECRETO-NO-FILTRAR'));
	assert.ok(!texto.includes('cipher-x'));
	assert.ok(!texto.includes('dek-x'));
	assert.ok(i.hallazgos.length > 0, 'el caso tiene que tener un hallazgo para que el chequeo tenga sentido');
});

console.log(`\n${hechos} checks OK`);
