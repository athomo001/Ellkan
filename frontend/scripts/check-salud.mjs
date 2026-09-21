// Autor: Athan Espinoza
//
// Checks ejecutables de la lógica de F-57 (salud de la bóveda), sin navegador:
//   node --experimental-strip-types frontend/scripts/check-salud.mjs

import assert from 'node:assert/strict';
import { analizar, huellaLocal } from '../src/lib/salud/informe.ts';
import { contarFiltraciones, parsearRango, sha1Hex, URL_HIBP } from '../src/lib/salud/hibp.ts';

const ahora = new Date('2026-09-20T12:00:00Z');
const hace = (dias) => new Date(ahora.getTime() - dias * 86_400_000).toISOString();
const item = (id, password, dias = 10) => ({ id, nombre: `Sitio ${id}`, usuario: 'yo', password, actualizadoEn: hace(dias) });

// Un medidor de mentira determinista: el largo decide el score.
const puntuar = (p) => (p.length >= 16 ? 4 : p.length >= 12 ? 3 : p.length >= 8 ? 2 : 0);
const base = { ahora, puntuar, huella: huellaLocal };

let n = 0;
async function check(nombre, fn) {
	await fn();
	n += 1;
	console.log(`ok  ${nombre}`);
}

await check('una contraseña débil se marca, una fuerte no', async () => {
	const inf = await analizar([item('a', '1234'), item('b', 'correcta-caballo-bateria-grapa')], { ...base, umbralDias: null });
	assert.deepEqual(inf.debiles.map((d) => d.item.id), ['a']);
	assert.equal(inf.analizados, 2);
});

await check('lo más débil va primero', async () => {
	const inf = await analizar([item('a', 'abcdefgh'), item('b', 'abc')], { ...base, umbralDias: null });
	assert.deepEqual(inf.debiles.map((d) => d.item.id), ['b', 'a']);
});

await check('una contraseña repetida en dos recursos queda marcada en AMBOS', async () => {
	const inf = await analizar([item('a', 'la-misma-clave-larga'), item('b', 'la-misma-clave-larga'), item('c', 'otra-clave-distinta-larga')], { ...base, umbralDias: null });
	assert.equal(inf.repetidas.length, 1);
	assert.deepEqual(inf.repetidas[0].map((i) => i.id).sort(), ['a', 'b']);
});

await check('tres recursos con la misma contraseña son UN grupo de tres', async () => {
	const inf = await analizar([item('a', 'x'.repeat(20)), item('b', 'x'.repeat(20)), item('c', 'x'.repeat(20))], { ...base, umbralDias: null });
	assert.equal(inf.repetidas.length, 1);
	assert.equal(inf.repetidas[0].length, 3);
});

await check('contraseñas distintas no se mezclan (ni por mayúsculas)', async () => {
	const inf = await analizar([item('a', 'Clave-Larga-1234567'), item('b', 'clave-larga-1234567')], { ...base, umbralDias: null });
	assert.equal(inf.repetidas.length, 0);
});

await check('los recursos sin contraseña no cuentan (ni como repetidos)', async () => {
	const inf = await analizar([item('a', ''), item('b', '')], { ...base, umbralDias: 0 });
	assert.equal(inf.analizados, 0);
	assert.equal(inf.repetidas.length, 0);
	assert.equal(inf.debiles.length, 0);
});

await check('sin umbral no se marca ninguna como vieja (no se fuerza la rotación)', async () => {
	const inf = await analizar([item('a', 'x'.repeat(20), 5000)], { ...base, umbralDias: null });
	assert.equal(inf.viejas.length, 0);
});

await check('con umbral se marcan las que lo superan, la más vieja primero', async () => {
	const inf = await analizar([item('a', 'a'.repeat(20), 100), item('b', 'b'.repeat(20), 400), item('c', 'c'.repeat(20), 800)], { ...base, umbralDias: 365 });
	assert.deepEqual(inf.viejas.map((v) => [v.item.id, v.dias]), [['c', 800], ['b', 400]]);
});

await check('el umbral es "más de": justo en el límite no se marca', async () => {
	const inf = await analizar([item('a', 'a'.repeat(20), 365)], { ...base, umbralDias: 365 });
	assert.equal(inf.viejas.length, 0);
});

await check('sha1Hex coincide con el valor conocido de "password" (ejemplo de la documentación de HIBP)', async () => {
	assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

await check('parsearRango descarta el relleno (0 veces) y lee los contadores', () => {
	const rango = parsearRango('AAAA:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nBBBB:3\n');
	assert.equal(rango.get('1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 9545824);
	assert.equal(rango.get('BBBB'), 3);
	assert.equal(rango.has('AAAA'), false);
});

await check('contarFiltraciones sólo manda el prefijo de 5 caracteres, nunca la contraseña', async () => {
	const pedidos = [];
	const consultar = async (url, init) => {
		pedidos.push({ url, init });
		return { ok: true, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n0000000000000000000000000000000000A:0' };
	};
	const r = await contarFiltraciones(['password', 'clave-que-nadie-uso-jamas-9f8e7d'], consultar);
	assert.equal(r.get('password'), 9545824);
	assert.equal(r.get('clave-que-nadie-uso-jamas-9f8e7d'), 0);
	for (const p of pedidos) {
		assert.match(p.url, new RegExp(`^${URL_HIBP.replaceAll('.', '\\.')}[0-9A-F]{5}$`), 'la URL termina en un prefijo de 5 caracteres');
		assert.ok(!p.url.slice(URL_HIBP.length).includes('password'), 'la contraseña no viaja');
		assert.equal(p.init.headers['Add-Padding'], 'true');
	}
	assert.equal(pedidos.length, 2, 'un pedido por prefijo distinto');
});

await check('contraseñas con el mismo prefijo comparten UNA consulta', async () => {
	let llamadas = 0;
	const consultar = async () => {
		llamadas += 1;
		return { ok: true, text: async () => '' };
	};
	await contarFiltraciones(['password', 'password', ''], consultar);
	assert.equal(llamadas, 1, 'duplicadas y vacías no generan consultas extra');
});

await check('si HIBP responde con error, se propaga (no se dice "limpia" sin haber comprobado)', async () => {
	await assert.rejects(() => contarFiltraciones(['password'], async () => ({ ok: false, text: async () => '' })), /HIBP/);
});

await check('sin contraseñas no hay ninguna consulta', async () => {
	let llamadas = 0;
	const r = await contarFiltraciones([], async () => {
		llamadas += 1;
		return { ok: true, text: async () => '' };
	});
	assert.equal(llamadas, 0);
	assert.equal(r.size, 0);
});

console.log(`\n${n} checks OK`);
