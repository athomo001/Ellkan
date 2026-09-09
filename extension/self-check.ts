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
// 2026-08-15: `event.ts` llama `LockService.registrarActividad()` en cada
// mensaje (sesión inteligente, F-04) — necesita `chrome.alarms` aunque este
// chequeo no ejercite el timeout de inactividad en sí mismo.
(globalThis as Record<string, unknown>).chrome = {
	storage: {},
	runtime: { id: 'ellkan-extension-id-fake' },
	alarms: { create: () => {}, clear: async () => true, onAlarm: { addListener: () => {} } }
};

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

	// --- 7b. `uri-match.ts` (spec 05 §2.2): las 4 estrategias de matching por
	// recurso, con el TEST DEDICADO contra dominios multi-tenant reales que
	// exige la spec (hallazgo BWN-08-020: `*.github.io` NO es un solo
	// dominio). ---
	const { coincideUri, normalizarEstrategia } = await import('./src/background/services/uri-match.ts');

	// `host` (default): hostname+puerto exactos, cualquier path; subdominio no cuenta.
	assert.ok(coincideUri('host', 'ejemplo.com', 'https://ejemplo.com/login'), 'host: mismo hostname, distinto path → matchea');
	assert.ok(!coincideUri('host', 'ejemplo.com', 'https://app.ejemplo.com/'), 'host: subdominio NO matchea');
	assert.ok(!coincideUri('host', 'https://ejemplo.com', 'https://ejemplo.com:8443/'), 'host: puerto distinto NO matchea');

	// `exact`: origen + path exactos (ignora query/hash y barra final).
	assert.ok(coincideUri('exact', 'https://ejemplo.com/login/', 'https://ejemplo.com/login?x=1'), 'exact: mismo path (barra final y query no cuentan) → matchea');
	assert.ok(!coincideUri('exact', 'https://ejemplo.com/login', 'https://ejemplo.com/otra'), 'exact: path distinto NO matchea');

	// `base_domain`: mismo dominio registrable vía PSL real.
	assert.ok(coincideUri('base_domain', 'https://www.ejemplo.com', 'https://app.ejemplo.com/x'), 'base_domain: dos subdominios del mismo eTLD+1 → matchea');
	assert.ok(coincideUri('base_domain', 'https://ejemplo.co.uk', 'https://mail.ejemplo.co.uk'), 'base_domain: eTLD compuesto (.co.uk) resuelto bien');
	// El corazón de BWN-08-020: la sección PRIVATE de la PSL tiene que estar activa.
	assert.ok(!coincideUri('base_domain', 'https://alice.github.io', 'https://bob.github.io'), 'base_domain: alice.github.io NO matchea bob.github.io (PSL PRIVATE)');
	assert.ok(!coincideUri('base_domain', 'https://mi-app.vercel.app', 'https://otra-app.vercel.app'), 'base_domain: *.vercel.app son dominios distintos');
	assert.ok(!coincideUri('base_domain', 'https://x.pages.dev', 'https://y.pages.dev'), 'base_domain: *.pages.dev son dominios distintos');
	assert.ok(coincideUri('base_domain', 'https://alice.github.io/repo', 'https://alice.github.io/repo/sub'), 'base_domain: el MISMO subdominio de github.io sí matchea');

	// `never`: nunca, aunque el resto coincida perfecto.
	assert.ok(!coincideUri('never', 'https://ejemplo.com/login', 'https://ejemplo.com/login'), 'never: nunca ofrece autofill');

	// URIs basura no rompen y no matchean.
	assert.ok(!coincideUri('host', '', 'https://ejemplo.com'), 'uri guardada vacía → no matchea');
	assert.ok(!coincideUri('base_domain', 'no es una url', 'https://ejemplo.com'), 'uri guardada inválida → no matchea');

	// Normalización: cualquier string raro cae al default `host`.
	assert.equal(normalizarEstrategia('exact'), 'exact');
	assert.equal(normalizarEstrategia('cualquier-cosa'), 'host', 'valor desconocido → host (default)');
	assert.equal(normalizarEstrategia(undefined), 'host', 'ausente → host (default)');
	console.log('OK: uri-match.ts — 4 estrategias + PSL real (github.io/vercel.app/pages.dev no son un solo dominio, BWN-08-020)');

	// --- 7c. `origin-guard.ts` (BWN-08-011): la revalidación de origen del
	// content script como función pura testeable, tal como pide el checkbox
	// dedicado. ---
	const { mismoOrigenParaFill } = await import('./src/content/origin-guard.ts');
	assert.ok(mismoOrigenParaFill('https://ejemplo.com', 'https://ejemplo.com/login?x=1'), 'mismo origen, distinto path → OK rellenar');
	assert.ok(!mismoOrigenParaFill('https://ejemplo.com', 'http://ejemplo.com/login'), 'cambio https→http es cambio de origen → NO rellenar');
	assert.ok(!mismoOrigenParaFill('https://ejemplo.com', 'https://otro.ejemplo.com/'), 'subdominio distinto es otro origen → NO rellenar');
	assert.ok(!mismoOrigenParaFill('https://ejemplo.com', 'https://ejemplo.com:8443/'), 'puerto distinto es otro origen → NO rellenar');
	assert.ok(!mismoOrigenParaFill('https://ejemplo.com', 'no-es-una-url'), 'href actual imposible de parsear → falla cerrado');
	assert.ok(!mismoOrigenParaFill('', 'https://ejemplo.com'), 'sin origen pedido → falla cerrado');
	console.log('OK: origin-guard.ts (mismoOrigenParaFill) — revalidación de origen exacta, falla cerrado (BWN-08-011)');

	// --- 7d. `field-detection.ts` (spec 06 §4.1): clasificación y emparejado
	// de campos de login como lógica pura sobre descriptores — la parte del
	// recorrido del DOM vive en `content/index.ts` y necesita un navegador. ---
	const { clasificarCampo, emparejarLogins, esCampoVisible } = await import('./src/content/field-detection.ts');

	type Campo = Parameters<typeof clasificarCampo>[0];
	const campo = (o: Partial<Campo>): Campo => ({
		opid: o.opid ?? 'x',
		type: o.type ?? 'text',
		autocomplete: o.autocomplete ?? '',
		name: o.name ?? '',
		id: o.id ?? '',
		placeholder: o.placeholder ?? '',
		ariaLabel: o.ariaLabel ?? '',
		visible: o.visible ?? true,
		formOpid: o.formOpid ?? null,
		ordenDom: o.ordenDom ?? 0
	});

	assert.equal(clasificarCampo(campo({ type: 'password' })), 'password');
	assert.equal(clasificarCampo(campo({ type: 'text', autocomplete: 'one-time-code' })), 'totp', 'autocomplete one-time-code → totp');
	assert.equal(clasificarCampo(campo({ type: 'text', name: 'otp_code' })), 'totp', 'name con "otp" → totp');
	assert.equal(clasificarCampo(campo({ type: 'email' })), 'username', 'type email → username');
	assert.equal(clasificarCampo(campo({ type: 'text', name: 'username' })), 'username', 'name username → username');
	assert.equal(clasificarCampo(campo({ type: 'text', name: 'search' })), 'otro', 'un text cualquiera → otro');

	// Login simple: usuario + password en el mismo form.
	let pares = emparejarLogins([
		campo({ opid: 'u', type: 'text', name: 'user', formOpid: 'f1', ordenDom: 0 }),
		campo({ opid: 'p', type: 'password', formOpid: 'f1', ordenDom: 1 })
	]);
	assert.deepEqual(pares, [{ formOpid: 'f1', usuario: 'u', password: 'p', totp: null }], 'login simple emparejado');

	// Honeypot: un password invisible NO se ofrece.
	pares = emparejarLogins([
		campo({ opid: 'trap', type: 'password', visible: false, formOpid: 'f1', ordenDom: 0 }),
		campo({ opid: 'u', type: 'text', name: 'email', formOpid: 'f2', ordenDom: 1 }),
		campo({ opid: 'p', type: 'password', formOpid: 'f2', ordenDom: 2 })
	]);
	assert.deepEqual(pares.map((x) => x.password), ['p'], 'el password invisible (honeypot) se descarta');

	// Registro / cambio de contraseña: 2 passwords visibles en un form → no es login.
	pares = emparejarLogins([
		campo({ opid: 'p1', type: 'password', formOpid: 'reg', ordenDom: 0 }),
		campo({ opid: 'p2', type: 'password', formOpid: 'reg', ordenDom: 1 })
	]);
	assert.equal(pares.length, 0, 'form con 2 passwords visibles no se empareja');

	// Con TOTP.
	pares = emparejarLogins([
		campo({ opid: 'u', type: 'text', name: 'user', formOpid: 'f', ordenDom: 0 }),
		campo({ opid: 'p', type: 'password', formOpid: 'f', ordenDom: 1 }),
		campo({ opid: 't', type: 'text', autocomplete: 'one-time-code', formOpid: 'f', ordenDom: 2 })
	]);
	assert.deepEqual(pares, [{ formOpid: 'f', usuario: 'u', password: 'p', totp: 't' }], 'usuario + password + totp');

	// Sin <form>: se empareja por cercanía (ordenDom). Un usuario DESPUÉS del password se ignora.
	pares = emparejarLogins([
		campo({ opid: 'p', type: 'password', formOpid: null, ordenDom: 0 }),
		campo({ opid: 'u', type: 'text', name: 'user', formOpid: null, ordenDom: 1 })
	]);
	assert.deepEqual(pares, [{ formOpid: null, usuario: null, password: 'p', totp: null }], 'usuario después del password no cuenta');

	assert.ok(!esCampoVisible({ width: 0, height: 0 }, { display: 'block', visibility: 'visible', opacity: '1' }), 'tamaño 0 → invisible');
	assert.ok(!esCampoVisible({ width: 120, height: 20 }, { display: 'none', visibility: 'visible', opacity: '1' }), 'display none → invisible');
	assert.ok(!esCampoVisible({ width: 120, height: 20 }, { display: 'block', visibility: 'visible', opacity: '0' }), 'opacity 0 → invisible');
	assert.ok(esCampoVisible({ width: 120, height: 20 }, { display: 'block', visibility: 'visible', opacity: '1' }), 'campo normal → visible');
	console.log('OK: field-detection.ts — clasificación + emparejado de login (honeypot y registro descartados, TOTP incluido)');

	// --- 7e. `autofill-script.ts` (spec 06 §4.3): acciones tipadas por `opid`
	// e intérprete con resolver inyectado (sin DOM). ---
	const { ejecutarScript, scriptParaLogin } = await import('./src/content/autofill-script.ts');

	assert.deepEqual(
		scriptParaLogin({ usuario: 'u', password: 'p', totp: null, valores: { usuario: 'ana', password: 's3cr3t' } }),
		[
			{ tipo: 'focus_by_opid', opid: 'u' },
			{ tipo: 'fill_by_opid', opid: 'u', valor: 'ana' },
			{ tipo: 'focus_by_opid', opid: 'p' },
			{ tipo: 'fill_by_opid', opid: 'p', valor: 's3cr3t' }
		],
		'script usuario+password'
	);
	assert.equal(
		scriptParaLogin({ usuario: null, password: 'p', totp: null, valores: { usuario: '', password: 'x' } }).length,
		2,
		'sin campo de usuario → sólo foco+relleno del password'
	);
	assert.equal(
		scriptParaLogin({ usuario: 'u', password: 'p', totp: 't', valores: { usuario: 'a', password: 'b', totp: '123456' } }).length,
		6,
		'con TOTP y valor → 6 acciones'
	);
	assert.equal(
		scriptParaLogin({ usuario: 'u', password: 'p', totp: 't', valores: { usuario: 'a', password: 'b' } }).length,
		4,
		'con opid de TOTP pero SIN valor → no se rellena TOTP'
	);

	// Intérprete: registra llamadas, saltea opids que no resuelven y errores puntuales.
	const llamadas: string[] = [];
	function objetivo(nombre: string, tira = false) {
		return {
			focus: () => llamadas.push(`focus:${nombre}`),
			click: () => llamadas.push(`click:${nombre}`),
			rellenar: (v: string) => {
				if (tira) throw new Error('elemento en estado raro');
				llamadas.push(`fill:${nombre}=${v}`);
			}
		};
	}
	const mapa: Record<string, ReturnType<typeof objetivo>> = { u: objetivo('u'), p: objetivo('p'), bomba: objetivo('bomba', true) };
	const res = ejecutarScript(
		[
			{ tipo: 'focus_by_opid', opid: 'u' },
			{ tipo: 'fill_by_opid', opid: 'u', valor: 'ana' },
			{ tipo: 'fill_by_opid', opid: 'no-existe', valor: 'x' },
			{ tipo: 'fill_by_opid', opid: 'bomba', valor: 'y' },
			{ tipo: 'fill_by_opid', opid: 'p', valor: 's3cr3t' }
		],
		(opid) => mapa[opid] ?? null
	);
	assert.deepEqual(llamadas, ['focus:u', 'fill:u=ana', 'fill:p=s3cr3t'], 'ejecuta lo resoluble, en orden');
	assert.deepEqual(res, { ejecutadas: 3, salteadas: 2 }, 'cuenta bien ejecutadas vs. salteadas (opid muerto + error)');
	console.log('OK: autofill-script.ts — acciones por opid, intérprete tolerante a opid muerto y a errores puntuales');

	// --- 10. `frame-ancestors 'none'` en TODA página propia de la extensión
	// (spec 05 §2.1, PBL-08-001) — se resuelve el manifest fuente para los 3
	// navegadores y se valida la CSP + que ningún .html se exponga por
	// `web_accessible_resources` (esquivaría esa CSP, BWN-08-019). ---
	const { problemasDeCsp, htmlExpuestoEnWAR, problemasPorNavegador } = await import('./src/manifest-check.ts');
	const { resolverManifest } = await import('./manifest-resolve.mjs');
	const { readFileSync } = await import('node:fs');
	// `process.cwd()` es `extension/` cuando corre `pnpm check:self` (el bundle
	// se ejecuta desde ahí) — leer el fuente por ruta absoluta evita el
	// problema de `import.meta.url` reescrito dentro del bundle del self-check.
	const fuente = JSON.parse(readFileSync(`${process.cwd()}/manifest.source.json`, 'utf8'));
	for (const navegador of ['chrome', 'firefox', 'safari']) {
		const m = resolverManifest(fuente, navegador);
		const problemas = problemasDeCsp(m);
		assert.deepEqual(problemas, [], `CSP de páginas de extensión OK para ${navegador} (${problemas.join('; ')})`);
		assert.deepEqual(htmlExpuestoEnWAR(m), [], `ningún .html en web_accessible_resources para ${navegador}`);
		assert.ok(
			typeof m.action?.default_popup === 'string' && m.action.default_popup.endsWith('.html'),
			`${navegador}: el popup es una página .html cubierta por la CSP`
		);
		// Diferencias reales MV3 por navegador (spec 06 §1/§7): el manifest
		// RESUELTO tiene que quedar bien formado para el destino.
		const probNav = problemasPorNavegador(m, navegador);
		assert.deepEqual(probNav, [], `manifest MV3 bien formado para ${navegador} (${probNav.join('; ')})`);
	}
	// Un manifest de prueba con la directiva mal puesta debe ser detectado —
	// confirma que el chequeo no pasa por vacuidad.
	assert.ok(
		problemasDeCsp({ content_security_policy: { extension_pages: "script-src 'self'; object-src 'self'" } }).some((p) => p.includes('frame-ancestors')),
		'un manifest SIN frame-ancestors debe fallar el chequeo'
	);
	assert.deepEqual(
		htmlExpuestoEnWAR({ web_accessible_resources: [{ resources: ['menu.html', 'x.png'], matches: ['<all_urls>'] }] }),
		['menu.html'],
		'un .html en web_accessible_resources debe ser detectado'
	);
	assert.ok(
		problemasPorNavegador({ manifest_version: 3, background: { scripts: ['background.js'] } }, 'chrome').some((p) => p.includes('service_worker')),
		'chrome sin background.service_worker debe fallar'
	);
	assert.ok(
		problemasPorNavegador({ manifest_version: 3, background: { scripts: ['background.js'] } }, 'firefox').some((p) => p.includes('gecko.id')),
		'firefox sin gecko.id debe fallar'
	);
	console.log('OK: manifest-check.ts — frame-ancestors + CSP + shape MV3 por navegador (chrome service_worker / firefox scripts+gecko.id)');

	// --- 11. `save-prompt.ts` (spec 06 §5): decidir SI ofrecer guardar una
	// credencial tras un submit. La barra en sí va por shadow root cerrado sin
	// iframe (misma mitigación BWN-08-019 que el menú). ---
	const { decidirGuardado } = await import('./src/content/save-prompt.ts');
	assert.deepEqual(
		decidirGuardado({ usuario: 'ana', password: 's3cr3t' }, []),
		{ ofrecer: true, modo: 'nuevo' },
		'credencial nueva, sin coincidencias → ofrecer guardar'
	);
	assert.deepEqual(
		decidirGuardado({ usuario: 'ana', password: '' }, []),
		{ ofrecer: false, modo: null },
		'sin contraseña → no ofrecer'
	);
	assert.deepEqual(
		decidirGuardado({ usuario: 'Ana', password: 's3cr3t' }, [{ usuario: 'ana' }]),
		{ ofrecer: false, modo: null },
		'ya hay una entrada para ese usuario (case-insensitive) → no ofrecer (MVP: sin "actualizar")'
	);
	assert.deepEqual(
		decidirGuardado({ usuario: 'otra', password: 's3cr3t' }, [{ usuario: 'ana' }]),
		{ ofrecer: true, modo: 'nuevo' },
		'hay entradas del sitio pero para otro usuario → ofrecer guardar la nueva'
	);
	console.log('OK: save-prompt.ts — ofrece guardar sólo credenciales nuevas (con contraseña, usuario no repetido)');

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

	// --- 9. Generador dual, modo 2: frases de paso en español (2026-08-15,
	// sólo local — decisión confirmada con el usuario). ---
	const { generarFraseDePaso } = await import('./src/popup/passphrase-generator.ts');
	const frase5 = generarFraseDePaso({ wordCount: 5, capitalize: false, includeNumbers: false, separator: '-' });
	assert.equal(frase5.split('-').length, 5, 'debe respetar la cantidad de palabras pedida');
	assert.ok(/^[a-z-]+$/.test(frase5), 'sin mayúsculas/números pedidos, sólo minúsculas y el separador');

	const fraseCapNum = generarFraseDePaso({ wordCount: 4, capitalize: true, includeNumbers: true, separator: '_' });
	const palabras = fraseCapNum.split('_');
	assert.equal(palabras.length, 4);
	assert.ok(
		palabras.every((p) => /^[A-Z][a-z]+[0-9]$/.test(p)),
		'con capitalize+includeNumbers, cada palabra debe ir en TitleCase y terminar en un dígito'
	);

	const fueraDeRango = generarFraseDePaso({ wordCount: 99, capitalize: false, includeNumbers: false, separator: ' ' });
	assert.equal(fueraDeRango.split(' ').length, 10, 'wordCount se acota al máximo de la spec (10)');
	console.log('OK: passphrase-generator.ts (frases de paso español) — cantidad/capitalización/números/separador correctos');

	console.log('\nself-check: todo OK');
}

main().catch((e) => {
	console.error('self-check FALLÓ:', e);
	process.exitCode = 1;
});
