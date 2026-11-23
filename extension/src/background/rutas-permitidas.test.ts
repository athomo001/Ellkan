// Autor: Athan Espinoza

// QA-32 (pendiente #117): allowlist de rutas por tipo de puerto y entrega del
// secreto sólo para la página real del frame.

import { describe, expect, it, vi } from 'vitest';
import { RUTAS_CONTENT, hrefDelRemitente, revelarSiCorrespondeALaPagina, rutaPermitida } from './rutas-permitidas';

describe('rutaPermitida', () => {
	it('el popup tiene todas las rutas', () => {
		for (const tipo of ['VAULT_LISTAR', 'AUTH_LOGOUT', 'AUTOFILL_BUSCAR']) {
			expect(rutaPermitida('QuickAccess', tipo)).toBe(true);
		}
	});

	it.each(['VAULT_LISTAR', 'VAULT_EDITAR', 'AUTH_LOGIN', 'AUTH_LOGOUT', 'PING'])(
		'un content script no puede pedir %s',
		(tipo) => {
			for (const worker of ['WebIntegration', 'InFormMenu', 'NotificationBar'] as const) {
				expect(rutaPermitida(worker, tipo)).toBe(false);
			}
		}
	);

	it('un content script sólo tiene autofill, revelar y crear', () => {
		expect([...RUTAS_CONTENT].sort()).toEqual(['AUTOFILL_BUSCAR', 'VAULT_CREAR', 'VAULT_REVELAR_SECRETO']);
	});
});

describe('revelarSiCorrespondeALaPagina', () => {
	const buscar = vi.fn(async (href: string) => (href.startsWith('https://banco.example/') ? [{ id: 'r-banco' }] : []));

	it('entrega el secreto del recurso que coincide con la página del frame', async () => {
		const revelar = vi.fn(async (id: string) => `secreto de ${id}`);
		await expect(revelarSiCorrespondeALaPagina('r-banco', 'https://banco.example/login', buscar, revelar)).resolves.toBe(
			'secreto de r-banco'
		);
		expect(buscar).toHaveBeenCalledWith('https://banco.example/login');
	});

	it('un iframe de otro sitio no recibe el secreto del banco', async () => {
		const revelar = vi.fn();
		await expect(revelarSiCorrespondeALaPagina('r-banco', 'https://anuncios.example/frame', buscar, revelar)).rejects.toThrow(
			'no corresponde'
		);
		expect(revelar).not.toHaveBeenCalled();
	});

	it('sin URL del remitente no entrega nada', async () => {
		const revelar = vi.fn();
		await expect(revelarSiCorrespondeALaPagina('r-banco', undefined, buscar, revelar)).rejects.toThrow();
		expect(revelar).not.toHaveBeenCalled();
	});
});

describe('hrefDelRemitente', () => {
	it('acepta el href de la página si es del mismo origen que el frame (SPA que cambió de ruta)', () => {
		expect(hrefDelRemitente('https://app.example/login', 'https://app.example/')).toBe('https://app.example/login');
	});

	it('si la página dice ser otro sitio, manda el del navegador', () => {
		expect(hrefDelRemitente('https://banco.example/login', 'https://anuncios.example/frame')).toBe('https://anuncios.example/frame');
		expect(hrefDelRemitente('no es una url', 'https://app.example/')).toBe('https://app.example/');
		expect(hrefDelRemitente(undefined, 'https://app.example/')).toBe('https://app.example/');
	});

	it('sin URL del remitente no hay página que valga', () => {
		expect(hrefDelRemitente('https://app.example/', undefined)).toBeUndefined();
	});
});
