// Autor: Athan Espinoza

import { describe, expect, it } from 'vitest';
import { CABECERA_CURSOR, LIMITE_PAGINA, traerTodasLasPaginas, type Pagina } from './paginado';

function pagina(ids: number[], cursor?: string): Pagina<number> {
	const cabeceras = new Headers();
	if (cursor) cabeceras.set(CABECERA_CURSOR, cursor);
	return { cuerpo: ids, cabeceras };
}

describe('traerTodasLasPaginas', () => {
	it('sigue el cursor hasta que el servidor deja de mandarlo', async () => {
		const pedidas: string[] = [];
		const todos = await traerTodasLasPaginas('/resources', async (ruta) => {
			pedidas.push(ruta);
			if (ruta.endsWith('after=b')) return pagina([5]);
			if (ruta.endsWith('after=a')) return pagina([3, 4], 'b');
			return pagina([1, 2], 'a');
		});
		expect(todos).toEqual([1, 2, 3, 4, 5]);
		expect(pedidas).toEqual([
			`/resources?limit=${LIMITE_PAGINA}`,
			`/resources?limit=${LIMITE_PAGINA}&after=a`,
			`/resources?limit=${LIMITE_PAGINA}&after=b`
		]);
	});

	it('con un servidor viejo (sin cabecera) hace un solo pedido', async () => {
		let pedidos = 0;
		const todos = await traerTodasLasPaginas('/resources?tag_id=x', async (ruta) => {
			pedidos++;
			expect(ruta).toBe(`/resources?tag_id=x&limit=${LIMITE_PAGINA}`);
			return pagina([1, 2, 3]);
		});
		expect(todos).toEqual([1, 2, 3]);
		expect(pedidos).toBe(1);
	});

	it('un cursor repetido no se vuelve un bucle', async () => {
		let pedidos = 0;
		await traerTodasLasPaginas('/resources', async () => {
			pedidos++;
			return pagina([1], 'mismo');
		});
		expect(pedidos).toBe(2);
	});
});
