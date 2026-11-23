// Autor: Athan Espinoza

// Servidor simulado para las auditorías de accesibilidad con sesión
// (pendiente #66): intercepta las llamadas a la API desde Playwright y
// responde con datos plausibles, sin backend ni base de datos. La identidad
// de la cuenta es real: se genera y se sella en Node con el mismo WASM que
// usa el navegador, así que el login de la UI desbloquea de verdad.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Page, Route } from '@playwright/test';
import {
	initSync,
	cifrar_aead,
	generar_dek,
	generar_identidad,
	generar_salt_kdf,
	parametros_kdf_actuales,
	sellar_clave_privada,
	sellar_para
} from '../src/lib/wasm/ellkan_crypto.js';

let wasmListo = false;
function cargarWasm(): void {
	if (wasmListo) return;
	initSync({ module: readFileSync(fileURLToPath(new URL('../src/lib/wasm/ellkan_crypto_bg.wasm', import.meta.url))) });
	wasmListo = true;
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const AHORA = '2026-11-20T10:00:00Z';
/** Puerto del backend local de la app de escritorio simulada. */
export const PUERTO_LOCAL = 47123;
const uuid = (n: number) => `01900000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const uuidABytes = (u: string) => Uint8Array.from(Buffer.from(u.replaceAll('-', ''), 'hex'));

/** Recursos del vault: metadata cifrada de verdad con una DEK sellada para
 * la clave pública de la cuenta (como los entrega `GET /resources`). */
const RECURSOS: { slug: string; metadata: Record<string, string> }[] = [
	{ slug: 'password', metadata: { name: 'Correo corporativo', username: 'ana.perez', uri: 'https://correo.ellkan.test' } },
	{ slug: 'password', metadata: { name: 'Banco', username: 'aperez', uri: 'https://banco.example' } },
	{ slug: 'api-token', metadata: { name: 'Token de despliegue', key_id: 'AKIAEJEMPLO', scopes: 'deploy', expires_at: '2027-01-31' } },
	{ slug: 'password', metadata: { name: 'Router de la oficina', username: 'admin', uri: '192.168.1.1' } }
];

type Respuesta = { status?: number; json?: unknown };
type Manejador = (url: URL, cuerpo: unknown) => Respuesta | unknown;

export class ServidorSimulado {
	readonly email = 'ana.perez@ellkan.test';
	readonly passphrase = 'una frase de prueba bastante larga';
	readonly userId = uuid(1);
	readonly sessionId = uuid(0xaa);
	/** Errores de JavaScript de la página (un mock con la forma equivocada). */
	readonly erroresDePagina: string[] = [];

	private constructor(
		private readonly tema: 'dark' | 'light',
		private readonly material: Record<string, unknown>,
		private readonly publicas: { x25519: string; ed25519: string },
		private readonly recursos: Record<string, unknown>[]
	) {}

	static async crear(tema: 'dark' | 'light'): Promise<ServidorSimulado> {
		cargarWasm();
		const id = generar_identidad();
		const salt = generar_salt_kdf();
		const [m, t, p] = parametros_kdf_actuales();
		const email = 'ana.perez@ellkan.test';
		const blob = sellar_clave_privada(
			'una frase de prueba bastante larga',
			salt,
			m,
			t,
			p,
			id.x25519_private,
			id.ed25519_private,
			new TextEncoder().encode(email)
		);
		const material = {
			email,
			encrypted_private_key_blob_b64: b64(blob.ciphertext),
			private_key_nonce_b64: b64(blob.nonce),
			kdf_salt_b64: b64(salt),
			kdf_params: { m_cost_kib: m, t_cost: t, p_cost: p }
		};
		const userId = uuid(1);
		const recursos = RECURSOS.map((r, i) => {
			const recursoId = uuid(0x100 + i);
			const dek = generar_dek();
			const aad = new Uint8Array(32);
			aad.set(uuidABytes(recursoId), 0);
			aad.set(uuidABytes(userId), 16);
			const cifrado = cifrar_aead(dek, new TextEncoder().encode(JSON.stringify(r.metadata)), aad);
			const crudo = {
				id: recursoId,
				resource_type_id: uuid(0x50),
				resource_type_slug: r.slug,
				metadata_ciphertext_b64: b64(cifrado.ciphertext),
				metadata_nonce_b64: b64(cifrado.nonce),
				created_by: userId,
				created_at: AHORA,
				updated_at: AHORA,
				metadata_key_type: 'user_key',
				metadata_key_id: null,
				folder_id: null,
				puede_borrar: true,
				own_sealed_dek_b64: b64(sellar_para(id.x25519_public, dek))
			};
			cifrado.free();
			return crudo;
		});
		const servidor = new ServidorSimulado(tema, material, { x25519: b64(id.x25519_public), ed25519: b64(id.ed25519_public) }, recursos);
		blob.free();
		id.free();
		return servidor;
	}

	async instalar(page: Page): Promise<void> {
		page.on('pageerror', (e) => this.erroresDePagina.push(`${page.url()}: ${e.message}`));
		await page.route('**/*', (route) => this.atender(route));
	}

	/** La app de escritorio es este mismo frontend dentro de WebView2
	 * (Chromium): con un `__TAURI_INTERNALS__` falso la app entra en modo
	 * escritorio (`enModoEscritorio()`), habla con el "backend local" en
	 * `127.0.0.1:PUERTO_LOCAL` (lo atiende este mismo simulador) y muestra
	 * las pantallas que sólo existen ahí. Los comandos Tauri devuelven datos
	 * plausibles; lo que no está en la tabla, `null`. */
	async instalarEscritorio(page: Page): Promise<void> {
		await page.addInitScript(
			({ puerto }) => {
				const comandos: Record<string, unknown> = {
					puerto_backend: puerto,
					puerto_configurado: null,
					info_app: { version: '1.5.0', binario_unix: 1795000000, ruta: 'C:\\Program Files\\Ellkan\\ellkan.exe' },
					al_cerrar_configurado: 'preguntar',
					hay_windows_terminal: true,
					sistema_estado: {
						soportado: true,
						autostart: false,
						enlaces: true,
						bloquear_con_pantalla: true,
						portable: false,
						carpeta_de_datos: 'C:\\Users\\ana\\AppData\\Roaming\\Ellkan'
					},
					extension_estado: {
						incluida: true,
						version_incluida: '1.5.0',
						navegadores: [
							{ id: 'chrome', objetivo: 'chromium', instalado: true, elegido: true, ruta: 'C:\\Ellkan\\extension', version_instalada: '1.4.0', al_dia: false },
							{ id: 'firefox', objetivo: 'firefox', instalado: true, elegido: false, ruta: '', version_instalada: null, al_dia: false }
						]
					}
				};
				let siguiente = 1;
				Object.defineProperty(window, '__TAURI_INTERNALS__', {
					value: {
						invoke: async (cmd: string) => (cmd === 'plugin:event|listen' ? siguiente++ : (comandos[cmd] ?? null)),
						transformCallback: () => siguiente++,
						unregisterCallback: () => {},
						convertFileSrc: (ruta: string) => ruta
					}
				});
				Object.defineProperty(window, '__TAURI_EVENT_PLUGIN_INTERNALS__', { value: { unregisterListener: () => {} } });
			},
			{ puerto: PUERTO_LOCAL }
		);
	}

	private async atender(route: Route): Promise<void> {
		const req = route.request();
		const url = new URL(req.url());
		const tipo = req.resourceType();
		if (tipo === 'eventsource') return route.fulfill({ status: 204 });
		const esApi =
			(tipo === 'fetch' || tipo === 'xhr' || tipo === 'preflight') &&
			!/\.[a-z0-9]+$/i.test(url.pathname) &&
			!/^\/(@|src\/|node_modules\/|\.svelte-kit\/)/.test(url.pathname);
		if (!esApi) return route.fallback();

		const metodo = req.method();
		// Escritorio: la SPA (localhost:5179) llama al backend local en otro
		// origen, así que las respuestas llevan CORS.
		const origen = req.headers()['origin'];
		const headers: Record<string, string> = origen
			? {
					'access-control-allow-origin': origen,
					'access-control-allow-credentials': 'true',
					'access-control-allow-headers': 'authorization, content-type, x-ellkan-sync',
					'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE',
					'access-control-expose-headers': '*'
				}
			: {};
		if (metodo === 'OPTIONS') return route.fulfill({ status: 204, headers });
		let cuerpo: unknown;
		try {
			cuerpo = req.postDataJSON();
		} catch {
			cuerpo = undefined;
		}
		const clave = `${metodo} ${url.pathname}`;
		for (const [patron, manejador] of this.rutas()) {
			if (patron.test(clave)) {
				const r = manejador(url, cuerpo);
				const respuesta: Respuesta = r && typeof r === 'object' && ('json' in r || 'status' in r) ? (r as Respuesta) : { json: r };
				if (respuesta.status === 204) return route.fulfill({ status: 204, headers });
				return route.fulfill({ status: respuesta.status ?? 200, headers, json: respuesta.json ?? {} });
			}
		}
		// Por defecto: listas vacías en los GET, éxito vacío en el resto.
		return route.fulfill({ status: 200, headers, json: metodo === 'GET' ? [] : {} });
	}

	private rutas(): [RegExp, Manejador][] {
		const yo = {
			id: this.userId,
			email: this.email,
			display_name: 'Ana Pérez',
			role: 'admin',
			created_at: AHORA,
			updated_at: AHORA,
			keys_created_at: AHORA
		};
		const claveOrg = { id: 2, public_key_x25519_b64: this.publicas.x25519, custody: 'client', created_at: AHORA };
		const admin = { user_id: this.userId, email: this.email, display_name: 'Ana Pérez', public_key_x25519_b64: this.publicas.x25519 };
		const politicaShare = { enabled: true, max_expiration_hours: 168, require_password: false, allow_link: true, allow_file: true };
		const politicaExport = { export_enabled: true, allowed_formats: ['ellkan_json', 'csv'], import_enabled: true };
		const usuarios = [
			{ id: this.userId, email: this.email, display_name: 'Ana Pérez', active: true, has_avatar: false, groups: ['Operaciones'], owned_resources_count: 4, shared_with_count: 1 },
			{ id: uuid(2), email: 'bruno.diaz@ellkan.test', display_name: 'Bruno Díaz', active: false, has_avatar: false, groups: [], owned_resources_count: 0, shared_with_count: 0 }
		];
		const grupos = [
			{
				id: uuid(0x20),
				name: 'Operaciones',
				parent_group_id: null,
				share_exempt: false,
				members: [
					{ user_id: this.userId, is_admin: true, email: this.email, display_name: 'Ana Pérez' },
					{ user_id: uuid(2), is_admin: false, email: 'bruno.diaz@ellkan.test', display_name: 'Bruno Díaz' }
				]
			},
			{ id: uuid(0x21), name: 'Soporte', parent_group_id: uuid(0x20), share_exempt: true, members: [] }
		];
		return [
			// --- login ---
			[/^GET \/auth\/setup-status$/, () => ({ setup_token_required: false, sso_enabled: false, privacy_url: null, terms_url: null })],
			[
				/^POST \/auth\/prelogin$/,
				() => ({
					email: this.email,
					kdf_salt_b64: this.material.kdf_salt_b64,
					kdf_params: this.material.kdf_params,
					auth_key_required: true
				})
			],
			[/^POST \/auth\/key-material$/, () => this.material],
			[/^POST \/auth\/challenge$/, () => ({ nonce_b64: b64(new Uint8Array(32).fill(7)) })],
			[/^POST \/auth\/verify$/, () => ({ estado: 'completo', session_id: this.sessionId, user_id: this.userId })],
			[/^GET \/auth\/session$/, () => ({ user_id: this.userId, email: this.email })],
			// --- cuenta propia ---
			[/^GET \/me$/, () => yo],
			[/^GET \/me\/permissions$/, () => ['*']],
			[
				/^GET \/me\/preferences$/,
				() => ({ locale: 'es', theme: this.tema, clipboard_clear_minutes: 1, auto_lock_minutes: 15 })
			],
			[/^PUT \/me\/preferences$/, (_u, c) => c],
			[/^GET \/me\/avatar$/, () => ({ status: 404, json: { error: { code: 'NOT_FOUND', message: 'sin avatar' } } })],
			[/^GET \/me\/recovery-kit$/, () => ({ configured: true, created_at: AHORA, must_rotate: false })],
			[/^GET \/me\/keys$/, () => ({ public_key_x25519_b64: this.publicas.x25519, public_key_ed25519_b64: this.publicas.ed25519 })],
			[/^GET \/me\/groups$/, () => [{ group_id: uuid(0x20), name: 'Operaciones', is_admin: true }]],
			[
				/^GET \/me\/sessions$/,
				() => [
					{ id: this.sessionId, dispositivo: 'Chrome · Windows', creada: AHORA, ultimo_uso: AHORA, actual: true },
					{ id: uuid(0xab), dispositivo: 'Firefox · Linux', creada: AHORA, ultimo_uso: null, actual: false }
				]
			],
			[/^GET \/me\/passkeys$/, () => [{ id: uuid(0x30), label: 'Llave USB', created_at: AHORA, last_used_at: AHORA, tiene_prf: true }]],
			[
				/^GET \/me\/emergency-access$/,
				() => [
					{
						id: uuid(0x40),
						granter_id: this.userId,
						grantee_id: uuid(2),
						granter: { email: '', display_name: '' },
						grantee: { email: 'bruno.diaz@ellkan.test', display_name: 'Bruno Díaz' },
						access_level: 'view',
						wait_time_days: 7,
						status: 'confirmed',
						request_status: null
					}
				]
			],
			[/^GET \/account-recovery\/status$/, () => ({ enrolled: true, org_recovery_key_id: 2, current_org_recovery_key_id: 2 })],
			[/^GET \/account-recovery\/org-public-key$/, () => claveOrg],
			// --- vault ---
			[/^GET \/resources$/, () => this.recursos],
			[/^GET \/tags$/, () => [{ id: uuid(0x60), name: 'trabajo', is_shared: false, created_by: this.userId }]],
			[/^GET \/metadata-keys$/, () => []],
			[
				/^GET \/external-shares$/,
				() => [
					{
						id: uuid(0x70),
						password_protected: true,
						max_views: 3,
						view_count: 1,
						expires_at: '2026-11-27T10:00:00Z',
						revoked_at: null,
						burned_at: null,
						created_at: AHORA
					}
				]
			],
			[/^GET \/external-share-policy$/, () => politicaShare],
			[/^GET \/export-policy$/, () => politicaExport],
			[/^GET \/vault\/persistence$/, () => ({ mode: 'full' })],
			// --- backend local del escritorio ---
			[/^GET \/auth\/existe-usuario$/, () => ({ existe: true })],
			[
				/^GET \/vault\/backups$/,
				() => ({
					carpeta: 'C:\\Users\\ana\\AppData\\Roaming\\Ellkan\\respaldos',
					respaldos: [{ nombre: 'ellkan-2026-11-20.db', bytes: 524288, creado_unix: 1795000000, automatico: true }]
				})
			],
			// --- administración ---
			[/^GET \/admin\/users$/, () => ({ items: usuarios, next_cursor: null })],
			[/^GET \/admin\/users\/[^/]+$/, () => usuarios[0]],
			[/^GET \/groups$/, () => grupos],
			[/^GET \/groups\/[^/]+$/, () => grupos[0]],
			[
				/^GET \/admin\/roles$/,
				() => [
					{ id: uuid(0x80), name: 'admin', permissions: ['*'], created_at: AHORA },
					{ id: uuid(0x81), name: 'auditor', permissions: ['audit:read', 'reports:read'], created_at: AHORA }
				]
			],
			[
				/^GET \/admin\/audit-log$/,
				() => ({
					items: [
						{
							id: uuid(0x90),
							actor_user_id: this.userId,
							actor_email: this.email,
							event_type: 'auth.login',
							subject_type: 'user',
							subject_id: this.userId,
							metadata: { ip: '203.0.113.7' },
							created_at: AHORA
						}
					],
					next_cursor: null
				})
			],
			[
				/^GET \/admin\/reports\/[^/]+$/,
				(u) => ({
					report_id: u.pathname.split('/').at(-1),
					items: [{ user_id: uuid(2), email: 'bruno.diaz@ellkan.test', mfa_enabled: false, last_login_at: null, created_at: AHORA }],
					next_cursor: null
				})
			],
			[
				/^GET \/admin\/system-status$/,
				() => [
					{ categoria: 'base_de_datos', checks: [{ id: 'db_ping', nivel: 'ok' }, { id: 'db_migraciones', nivel: 'ok', aplicadas: 65, fallidas: 0 }] },
					{
						categoria: 'correo',
						checks: [
							{ id: 'smtp_configurado', nivel: 'advertencia', configurado: false },
							{ id: 'correo_backlog', nivel: 'ok', pendientes: 0, fallidos: 0 }
						]
					},
					{ categoria: 'seguridad', checks: [{ id: 'origen_seguro', nivel: 'error', origen: 'http://localhost' }, { id: 'admins_activos', nivel: 'ok', cantidad: 1 }] }
				]
			],
			[
				/^GET \/admin\/update-check$/,
				() => ({
					enabled: true,
					current_version: '1.4.0',
					latest_version: '1.5.0',
					release_url: 'https://github.com/example/ellkan/releases',
					checked_at: AHORA,
					update_available: true
				})
			],
			[/^GET \/admin\/metadata-keys\/rotation-status$/, () => ({ activa: false, saliente_id: null, entrante_id: null, total_al_iniciar: 0, pendientes: 0 })],
			[
				/^GET \/admin\/account-recovery\/custody$/,
				() => ({ current: claveOrg, my_envelope_b64: b64(new Uint8Array(80).fill(3)), pending_custodians: [], org_admins: [admin], escrows_on_server_key: 0 })
			],
			[
				/^GET \/admin\/account-recovery\/requests$/,
				() => [{ id: uuid(0xa0), target_email: 'bruno.diaz@ellkan.test', status: 'pending', approvals_count: 1, approval_threshold: 2, created_at: AHORA }]
			],
			[/^GET \/admin\/account-recovery-policy$/, () => ({ required: false, grace_period_days: 14, default_approval_threshold: 2 })],
			[/^GET \/admin\/emergency-access-policy$/, () => ({ enabled: true })],
			[/^GET \/admin\/export-policy$/, () => politicaExport],
			[/^GET \/admin\/external-share-policy$/, () => politicaShare],
			[/^GET \/admin\/legal-links$/, () => ({ privacy_url: 'https://ellkan.test/privacidad', terms_url: null })],
			[
				/^GET \/admin\/mfa-policy$/,
				() => ({ require_mfa: false, allowed_methods: ['totp', 'webauthn'], grace_period_days: 7, require_mfa_since: null })
			],
			[
				/^GET \/admin\/password-policy$/,
				() => ({
					min_passphrase_length: 16,
					min_passphrase_entropy_bits: 60,
					passphrase_rotation_days: null,
					generator_default_length: 20,
					generator_charset_rules: { lowercase: true, uppercase: true, digits: true, symbols: true },
					max_clipboard_clear_minutes: 5,
					max_auto_lock_minutes: 60
				})
			],
			[/^GET \/admin\/data-retention-policy$/, () => ({ data_retention_days: null, audit_log_retention_days: 365 })],
			[/^GET \/admin\/self-registration-policy$/, () => ({ enabled: false, allowed_domains: [] })],
			[/^GET \/admin\/sharing-policy$/, () => ({ restrict_visibility_by_group: false })],
			[
				/^GET \/admin\/smtp-config$/,
				() => ({ configurado: true, host: 'smtp.ellkan.test', port: 587, from_address: 'no-reply@ellkan.test', tls: true, username: 'ellkan' })
			],
			[/^GET \/admin\/sso-config$/, () => ({ issuer_url: '', client_id: '', jit_provisioning_enabled: false })],
			[
				/^GET \/admin\/directory-sync\/config$/,
				() => ({
					ldap_url: '',
					bind_dn: '',
					require_starttls: true,
					base_dn: '',
					user_filter: '(objectClass=person)',
					attribute_mapping: { email: 'mail', display_name: 'cn' },
					last_sync_at: null,
					user_object_class: 'person',
					sync_groups: false,
					group_membership_attribute: 'memberOf'
				})
			]
		];
	}
}
