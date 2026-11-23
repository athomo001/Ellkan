// Autor: Athan Espinoza

// Pendiente #64 (paso 1): las claves privadas se ponen en cero al bloquear
// o reemplazarlas, y no se tocan las que siguen en uso.

import { describe, expect, it } from 'vitest';
import { clavesDesbloqueadas, type ClavesDesbloqueadas } from './session';
import { limpiarStoresEn } from './declarative-store';

function claves(n: number): ClavesDesbloqueadas {
	return {
		x25519Private: new Uint8Array(32).fill(n),
		ed25519Private: new Uint8Array(32).fill(n + 1),
		x25519Public: new Uint8Array(32).fill(n + 2),
		ed25519Public: new Uint8Array(32).fill(n + 3)
	};
}

const enCero = (a: Uint8Array) => a.every((b) => b === 0);

describe('clavesDesbloqueadas', () => {
	it('bloquear pone en cero las privadas', () => {
		const c = claves(7);
		clavesDesbloqueadas.set(c);
		limpiarStoresEn('lock');
		expect(enCero(c.x25519Private)).toBe(true);
		expect(enCero(c.ed25519Private)).toBe(true);
		// Las públicas no son secretas: se dejan como estaban.
		expect(c.x25519Public[0]).toBe(9);
	});

	it('reemplazarlas borra las viejas y no las que se reusan', () => {
		const a = claves(1);
		clavesDesbloqueadas.set(a);
		const b = { ...claves(2), ed25519Private: a.ed25519Private };
		clavesDesbloqueadas.set(b);
		expect(enCero(a.x25519Private)).toBe(true);
		expect(a.ed25519Private[0]).toBe(2);
		expect(b.x25519Private[0]).toBe(2);
		clavesDesbloqueadas.set(null);
		expect(enCero(b.x25519Private)).toBe(true);
		expect(enCero(b.ed25519Private)).toBe(true);
	});
});
