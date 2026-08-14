// Autor: Athan Espinoza

// Chequeo mínimo, sin framework (ponytail): prueba el round-trip real de
// mensajería (Pagemod→Event→Controller→Service) y el anti-spoofing de
// PortManager (spec 05 §2.1) con un `chrome.runtime.Port` simulado — no
// hace falta un navegador real para verificar esta lógica, que no toca
// ninguna API nativa del navegador más allá de la forma de un `Port`.
//
// No verifica: carga real en Chrome/Firefox/Safari, ni el manifest —
// para eso, cargar `extension/dist` como extensión sin empaquetar
// (`chrome://extensions` → modo desarrollador → "Cargar descomprimida").
//
// Correr: node self-check.ts

import assert from 'node:assert/strict';

// `attachPagemod` enruta (vía `event.ts`) hasta `AuthController`, que carga
// `browser-api.ts` — su módulo referencia el global `chrome` apenas se
// importa. Este chequeo no ejercita nada de auth (eso es
// `self-check-auth.ts`), así que un stub vacío alcanza con tal de que
// exista.
(globalThis as Record<string, unknown>).chrome = { storage: {}, runtime: { id: 'ellkan-extension-id-fake' } };

const { PortManager } = await import('./src/background/port-manager.ts');
const { attachPagemod } = await import('./src/background/pagemod.ts');

type Listener = (mensaje: unknown) => void;

function fakePort(workerId: string, tabId: number, frameId: number) {
	return fakePortConSender(workerId, { tab: { id: tabId }, frameId });
}

function fakePortConSender(workerId: string, sender: unknown) {
	const listenersMensaje: Listener[] = [];
	const listenersDisconnect: (() => void)[] = [];
	const enviados: unknown[] = [];
	return {
		name: workerId,
		sender,
		onMessage: {
			addListener: (fn: Listener) => listenersMensaje.push(fn),
			removeListener: (fn: Listener) => {
				const i = listenersMensaje.indexOf(fn);
				if (i >= 0) listenersMensaje.splice(i, 1);
			}
		},
		onDisconnect: { addListener: (fn: () => void) => listenersDisconnect.push(fn) },
		postMessage: (mensaje: unknown) => enviados.push(mensaje),
		disconnect: () => listenersDisconnect.forEach((fn) => fn()),
		emit: (mensaje: unknown) => listenersMensaje.forEach((fn) => fn(mensaje)),
		enviados
	};
}

async function main() {
	// --- 1. Handshake + PING/PONG round-trip completo ---
	const port1 = fakePort('worker-1', 10, 0);
	attachPagemod(port1 as never);
	port1.emit({ requestId: 'h1', tipo: 'HANDSHAKE', payload: { name: 'WebIntegration' } });
	assert.deepEqual(port1.enviados[0], ['ellkan.port.ready'], 'debe confirmar el handshake');

	port1.emit({ requestId: 'r1', tipo: 'PING' });
	await new Promise((r) => setTimeout(r, 0)); // deja resolver el handler async
	const respuestaPing = port1.enviados[1] as [string, string, { pong: boolean }];
	assert.equal(respuestaPing[0], 'r1');
	assert.equal(respuestaPing[1], 'SUCCESS');
	assert.equal(respuestaPing[2].pong, true);
	console.log('OK: handshake + PING/PONG (Pagemod→Event→Controller→Service)');

	// --- 2. Anti-spoofing: mismo workerId desde otro tab/frame se rechaza ---
	let desconectado = false;
	const portSpoof = fakePort('worker-1', 999, 0); // mismo workerId, tab distinto
	portSpoof.disconnect = () => {
		desconectado = true;
	};
	attachPagemod(portSpoof as never);
	portSpoof.emit({ requestId: 'h2', tipo: 'HANDSHAKE', payload: { name: 'WebIntegration' } });
	assert.equal(desconectado, true, 'una reconexión spoofeada debe desconectarse, nunca registrarse');
	assert.ok(PortManager.get('worker-1'), 'el worker legítimo original debe seguir registrado, sin pisarse');
	console.log('OK: anti-spoofing rechaza tabId/frameId que no coinciden');

	// --- 3. Reconexión legítima: mismo workerId, mismo tab/frame, sí se acepta ---
	const port1Reconectado = fakePort('worker-1', 10, 0);
	attachPagemod(port1Reconectado as never);
	port1Reconectado.emit({ requestId: 'h3', tipo: 'HANDSHAKE', payload: { name: 'WebIntegration' } });
	assert.deepEqual(port1Reconectado.enviados[0], ['ellkan.port.ready'], 'una reconexión legítima (mismo tab/frame) sí debe aceptarse');
	console.log('OK: reconexión legítima (mismo tabId/frameId) se acepta');

	// --- 4. QuickAccess (popup): sin tab/frame, se acepta si el sender es la
	// propia extensión — este es el bug real reportado por el usuario
	// ("timeout esperando ellkan.port.ready" al loguearse desde el popup):
	// el chequeo de tabId/frameId de arriba rechazaba SIEMPRE esta conexión,
	// porque un popup nunca tiene tab/frame que reportar. ---
	const portPopup = fakePortConSender('quick-1', { id: 'ellkan-extension-id-fake' });
	attachPagemod(portPopup as never);
	portPopup.emit({ requestId: 'h4', tipo: 'HANDSHAKE', payload: { name: 'QuickAccess' } });
	assert.deepEqual(portPopup.enviados[0], ['ellkan.port.ready'], 'el popup debe poder loguearse sin tabId/frameId');
	console.log('OK: QuickAccess (popup) se registra sin tabId/frameId');

	// --- 5. Alguien pretendiendo ser QuickAccess desde OTRA extensión (sender.id
	// distinto) se rechaza — el único chequeo de legitimidad que le queda a
	// este caso, ya que no hay tab/frame que comparar. ---
	let popupSpoofDesconectado = false;
	const portPopupSpoof = fakePortConSender('quick-2', { id: 'otra-extension-cualquiera' });
	portPopupSpoof.disconnect = () => {
		popupSpoofDesconectado = true;
	};
	attachPagemod(portPopupSpoof as never);
	portPopupSpoof.emit({ requestId: 'h5', tipo: 'HANDSHAKE', payload: { name: 'QuickAccess' } });
	assert.equal(popupSpoofDesconectado, true, 'un sender.id que no es el de la propia extensión debe rechazarse');
	console.log('OK: QuickAccess rechaza un sender.id que no es el de la extensión');

	// --- 6. `conexion.ts` (spec 06 §5bis, vista de detalle): puerto puro de
	// `frontend/src/lib/crypto/recursos.ts::comandoDeConexion` — mismos casos
	// que ya cubre esa función, más `urlAbrible` (nuevo acá). ---
	const { comandoDeConexion, urlAbrible } = await import('./src/popup/conexion.ts');
	assert.equal(comandoDeConexion('ssh', 'root', 'servidor.local'), 'ssh root@servidor.local');
	assert.equal(comandoDeConexion('ssh', 'root', 'servidor.local:2222'), 'ssh root@servidor.local -p 2222');
	assert.equal(comandoDeConexion('telnet', '', 'host.local'), 'telnet host.local');
	assert.equal(comandoDeConexion('login-password', 'u', 'ejemplo.com'), null, 'login-password no tiene comando de conexión');
	assert.equal(urlAbrible('login-password', 'ejemplo.com'), 'https://ejemplo.com', 'agrega esquema si falta');
	assert.equal(urlAbrible('login-password', 'https://ejemplo.com'), 'https://ejemplo.com', 'no duplica el esquema');
	assert.equal(urlAbrible('ssh', 'servidor.local'), null, 'ssh no es un link abrible, es un comando');
	console.log('OK: conexion.ts (comandoDeConexion/urlAbrible) — mismos casos que recursos.ts');

	// --- 7. `autofill-service.ts::hostnameDeUri` (spec 06 §4.2): base del
	// matching `host` — sólo hostname exacto, nunca subdominios (eso sería
	// `base_domain`, que necesita Public Suffix List real, sin implementar
	// a propósito, ver comentario del archivo). ---
	const { hostnameDeUri } = await import('./src/background/services/autofill-service.ts');
	assert.equal(hostnameDeUri('ejemplo.com'), 'ejemplo.com', 'sin esquema, asume https y extrae el host igual');
	assert.equal(hostnameDeUri('https://ejemplo.com/login'), 'ejemplo.com', 'ignora el path');
	assert.equal(hostnameDeUri('https://EJEMPLO.com'), 'ejemplo.com', 'normaliza a minúsculas');
	assert.notEqual(hostnameDeUri('sub.ejemplo.com'), hostnameDeUri('ejemplo.com'), 'un subdominio NO matchea el dominio raíz (estrategia host, no base_domain)');
	assert.equal(hostnameDeUri(''), null, 'uri vacía no rompe, no matchea nada');
	console.log('OK: autofill-service.ts (hostnameDeUri) — matching host exacto, sin falsos positivos de subdominio');

	// --- 8. Generador de contraseñas + medidor de fortaleza (pedido explícito
	// del usuario, modal del popup) — mismos módulos que ya usa la app web,
	// sólo se confirma que siguen respetando longitud/reglas y que el
	// medidor distingue débil de fuerte, no que el algoritmo de zxcvbn en sí
	// sea correcto (eso ya lo verifica su propio paquete). ---
	const { generarPassword } = await import('../frontend/src/lib/crypto/passwordGenerator.ts');
	const { evaluarFortaleza } = await import('../frontend/src/lib/crypto/passwordStrength.ts');
	const generada = generarPassword(21, { uppercase: true, lowercase: true, digits: true, symbols: true, exclude_ambiguous: true });
	assert.equal(generada.length, 21, 'debe respetar el largo pedido');
	assert.ok(/[A-Z]/.test(generada) && /[0-9]/.test(generada), 'con mayúsculas+dígitos habilitados, al menos un carácter de cada uno debe aparecer');
	assert.ok(evaluarFortaleza('123').score < evaluarFortaleza(generada).score, 'una contraseña generada de 21 debe puntuar más fuerte que "123"');
	console.log('OK: passwordGenerator/passwordStrength (mismos módulos de la app web) — largo y fortaleza correctos');

	console.log('\nself-check: todo OK');
}

main().catch((e) => {
	console.error('self-check FALLÓ:', e);
	process.exitCode = 1;
});
