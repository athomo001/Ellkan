// Autor: Athan Espinoza

import { describe, expect, it } from 'vitest';
import { quitarFinales } from './texto';

describe('quitarFinales', () => {
	it('quita todas las barras del final y deja las del medio', () => {
		expect(quitarFinales('/a//b///', '/')).toBe('/a//b');
		expect(quitarFinales('https://ellkan.test/', '/')).toBe('https://ellkan.test');
	});

	it('devuelve el mismo texto si no termina en el carácter', () => {
		expect(quitarFinales('/a/b', '/')).toBe('/a/b');
		expect(quitarFinales('', '/')).toBe('');
	});

	it('vacía un texto hecho sólo del carácter', () => {
		expect(quitarFinales('////', '/')).toBe('');
	});

	it('es lineal con muchas barras que no están al final (ReDoS)', () => {
		const malicioso = '/'.repeat(200_000) + 'x';
		const inicio = performance.now();
		expect(quitarFinales(malicioso, '/')).toBe(malicioso);
		expect(performance.now() - inicio).toBeLessThan(100);
	});
});
