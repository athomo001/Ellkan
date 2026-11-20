// Autor: Athan Espinoza

// QA-14 (pendiente #103): helpers puros del popup. Mismos casos que
// `frontend/src/lib/crypto/recursos.test.ts`: las dos copias tienen que
// comportarse igual.

import { describe, expect, it } from 'vitest';
import { comandoDeConexion, hostnameParaFavicon, urlAbrible } from './conexion';

describe('comandoDeConexion', () => {
	it('arma el comando de cada protocolo y sólo muestra el puerto si no es el de siempre', () => {
		expect(comandoDeConexion('ssh', 'ana', 'srv.example.com')).toBe('ssh ana@srv.example.com');
		expect(comandoDeConexion('ssh', 'ana', 'ssh://srv:2222')).toBe('ssh ana@srv -p 2222');
		expect(comandoDeConexion('mongodb', '', 'db')).toBe('mongosh "mongodb://db:27017/"');
		expect(comandoDeConexion('login-password', 'ana', 'example.com')).toBeNull();
	});

	it.each([
		['usuario con ;', 'x; rm -rf ~', 'srv'],
		['usuario con $()', '$(curl evil)', 'srv'],
		['usuario que empieza con -', '-oProxyCommand=evil', 'srv'],
		['host que empieza con -', 'ana', '-oProxyCommand=evil'],
		['host con &', 'ana', 'srv&evil']
	])('no ofrece comando con %s', (_caso, usuario, uri) => {
		expect(comandoDeConexion('ssh', usuario, uri)).toBeNull();
	});
});

describe('urlAbrible', () => {
	it('abre http(s) y completa https:// cuando falta', () => {
		expect(urlAbrible('login-password', 'https://example.com')).toBe('https://example.com');
		expect(urlAbrible('login-password', 'example.com/login')).toBe('https://example.com/login');
		expect(urlAbrible('login-password', 'localhost:8080')).toBe('https://localhost:8080');
	});

	it.each(['javascript:alert(1)', 'javascript://%0aalert(1)', 'data:text/html,x', 'file:///etc/passwd'])('no abre %s', (uri) => {
		expect(urlAbrible('login-password', uri)).toBeNull();
	});

	it('los tipos con comando propio no tienen URL', () => {
		expect(urlAbrible('ssh', 'srv')).toBeNull();
	});
});

describe('hostnameParaFavicon', () => {
	it('devuelve sólo el hostname, en minúsculas', () => {
		expect(hostnameParaFavicon('login-password', 'https://GitHub.com/login?x=1')).toBe('github.com');
		expect(hostnameParaFavicon('ssh', 'srv')).toBeNull();
	});
});
