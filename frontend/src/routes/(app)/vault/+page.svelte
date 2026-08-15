<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-05/F-06/F-07/F-08/F-11: Vault real — listado con metadata descifrada
	// client-side, creación de recursos personales, ver secreto (F-39: campo
	// enmascarado + copiar con limpieza de portapapeles), compartir (sólo
	// recursos `shared_key`) y editar (`user_key` solamente — editar
	// `shared_key` exige resolver la metadata key compartida, ver guard
	// explícito en `$lib/crypto/recursos.ts::editarRecurso`).
	//
	// Layout tabla + panel lateral de detalle (en vez de expansión inline
	// por fila) — un solo recurso seleccionado a la vez, `panelModo` decide
	// qué vista del panel mostrar. El secreto sigue sin decifrarse sólo por
	// seleccionar la fila: hace falta el botón "Ver secreto" explícito
	// dentro del panel, mismo criterio de siempre (minimizar cuánto tiempo
	// vive un secreto descifrado en memoria).
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import SecretField from '$lib/components/SecretField.svelte';
	import FolderTree from '$lib/components/FolderTree.svelte';
	import LockOverlay from '$lib/components/LockOverlay.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import TagFilterBar from '$lib/components/TagFilterBar.svelte';
	import Table from '$lib/components/Table.svelte';
	import {
		listarRecursos,
		verSecreto,
		crearRecurso,
		editarRecurso,
		compartirRecursosEnLote,
		listarPermisos,
		cambiarNivelPermiso,
		revocarPermiso,
		buscarUsuarios,
		compartirRecursoConDestinatario,
		comandoDeConexion,
		infoConexion,
		eliminarRecurso,
		salirDeRecurso,
		type Recurso,
		type TipoRecurso,
		type UsuarioBusqueda
	} from '$lib/crypto/recursos';
	import {
		listarArbolCarpetas,
		crearCarpeta,
		moverCarpeta,
		moverRecursoACarpeta,
		compartirCarpeta,
		compartirCarpetaConGrupo,
		resolverMiembrosConClave,
		descendientesDe,
		type NodoCarpeta
	} from '$lib/crypto/carpetas';
	import { tagsApi, type Tag } from '$lib/api/tags';
	import { passwordPolicyApi, groupsApi } from '$lib/api/admin';
	import { misGruposApi, type GrupoDeUsuario } from '$lib/api/profile';
	import { generarPassword, type ReglasCharset } from '$lib/crypto/passwordGenerator';
	import { externalSharesApi } from '$lib/api/externalShares';
	import { cifrarContenidoDeShare } from '$lib/crypto/externalShare';
	import { conDeduplicacion, refrescarAlEnfocar, huboCambios } from '$lib/api/sync';
	import { copiarConLimpieza } from '$lib/clipboard';
	import { exportPolicyApi, adminExportPolicyApi, type ExportPolicy } from '$lib/api/exportPolicy';
	import {
		construirFilasExport,
		exportar,
		descargarArchivo,
		parsearArchivoImport,
		importar,
		detectarFormatoPorNombre,
		type FormatoExport,
		type FilaExport
	} from '$lib/crypto/exportImport';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { sesion, clavesDesbloqueadas, preferencias, permisos, tienePermiso, esAdmin } from '$lib/state/session';
	import { obtenerAvatarUrlDeUsuario } from '$lib/api/profile';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	// Heroicons outline (24x24, stroke-width 1.5) — mismo set que ya usa la
	// nav (`(app)/+layout.svelte::ICONOS`), verificados contra el repo real
	// de tailwindlabs/heroicons en vez de dibujarlos a mano.
	const ICONO_CARPETA = 'M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z';
	const ICONO_TAG = [
		'M9.568 3H5.25A2.25 2.25 0 0 0 3 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 0 0 5.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 0 0 9.568 3Z',
		'M6 6h.008v.008H6V6Z'
	];
	const ICONO_COMPARTIR =
		'M7.217 10.907a2.25 2.25 0 1 0 0 2.186m0-2.186c.18.324.283.696.283 1.093s-.103.77-.283 1.093m0-2.186 9.566-5.314m-9.566 7.5 9.566 5.314m0 0a2.25 2.25 0 1 0 3.935 2.186 2.25 2.25 0 0 0-3.935-2.186Zm0-12.814a2.25 2.25 0 1 0 3.933-2.185 2.25 2.25 0 0 0-3.933 2.185Z';
	const ICONO_EXPORTAR = 'M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3';
	const ICONO_ELIMINAR =
		'M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0';
	const ICONO_NUEVO = 'M12 4.5v15m7.5-7.5h-15';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let recursos = $state<Recurso[]>([]);

	// --- carpetas (F-09) + tags (F-10) — organización del vault ---
	let carpetas = $state<NodoCarpeta[]>([]);
	let cargandoCarpetas = $state(true);
	let errorCarpetas = $state<string | undefined>();
	let tags = $state<Tag[]>([]);
	let cargandoTags = $state(true);
	let errorTags = $state<string | undefined>();
	let tagsSeleccionados = $state<string[]>([]);
	let idsConTagsSeleccionados = $state<Set<string> | null>(null);
	let busqueda = $state('');

	async function cargarOrganizacion() {
		if (!$clavesDesbloqueadas) return;
		cargandoCarpetas = true;
		errorCarpetas = undefined;
		try {
			carpetas = await listarArbolCarpetas($clavesDesbloqueadas);
		} catch (err) {
			errorCarpetas = err instanceof ApiError ? err.message : $t.vault.carpetas.error;
		} finally {
			cargandoCarpetas = false;
		}

		cargandoTags = true;
		errorTags = undefined;
		try {
			tags = await tagsApi.listar();
		} catch (err) {
			errorTags = err instanceof ApiError ? err.message : $t.vault.tags.error;
		} finally {
			cargandoTags = false;
		}
	}

	async function onCrearCarpeta(nombreCarpeta: string, parentId: string | null) {
		if (!$clavesDesbloqueadas) return;
		try {
			const nueva = await crearCarpeta(nombreCarpeta, parentId, $clavesDesbloqueadas);
			carpetas = [...carpetas, nueva];
		} catch (err) {
			errorCarpetas = err instanceof ApiError ? err.message : $t.vault.carpetas.errorCrear;
		}
	}

	async function onMoverCarpeta(folderId: string, newParentId: string | null) {
		try {
			await moverCarpeta(folderId, newParentId);
			carpetas = carpetas.map((c) => (c.id === folderId ? { ...c, parentId: newParentId } : c));
		} catch (err) {
			errorCarpetas = err instanceof ApiError ? err.message : $t.vault.carpetas.error;
		}
	}

	// F-11: clic en una carpeta del árbol filtra la tabla — clic de nuevo la
	// quita. `null` = sin filtro (todas).
	let carpetaFiltro = $state<string | null>(null);
	function onFiltrarCarpeta(folderId: string) {
		carpetaFiltro = carpetaFiltro === folderId ? null : folderId;
		verTodoSubcarpetas = false;
	}

	// 2026-08-11 — "Ver todo": clic en una carpeta sigue mostrando sólo lo
	// directo por default (sin sorpresas); este toggle también incluye el
	// contenido de las subcarpetas. Todo client-side — `recursos` ya trae
	// TODO lo visible descifrado, `descendientesDe` (ya usado por
	// FolderTree para excluir destinos de mover) alcanza sin pedirle nada
	// nuevo al backend.
	let verTodoSubcarpetas = $state(false);

	// 2026-08-11: grupos del usuario actual (`GET /me/groups`, ya existente)
	// — los que administra habilitan "Compartir" de carpetas (regular queda
	// 100% personal) y pueblan el selector "compartir con mi grupo".
	let misGrupos = $state<GrupoDeUsuario[]>([]);
	const misGruposDondeAdmin = $derived(misGrupos.filter((g) => g.is_admin));
	const puedeCompartirCarpetas = $derived($esAdmin || misGruposDondeAdmin.length > 0);

	// 2026-08-11: al mover un recurso a una carpeta de grupo, preguntar si
	// se cede la propiedad al grupo (cualquier miembro lo edita) o se
	// mantiene personal (sólo quien lo agregó) — "ceder" resella el DEK
	// para cada miembro actual, mismo mecanismo que compartir en lote
	// (`compartirRecursosEnLote`, ya existente); "mantener" no hace nada
	// más, el move solo ya deja el recurso visible al grupo con `read`.
	let cediendoRecurso = $state<{ resourceId: string; nombre: string; groupId: string } | null>(null);
	let cediendoEnCurso = $state(false);
	let errorCeder = $state<string | undefined>();

	async function onMoverRecurso(resourceId: string, folderId: string | null) {
		try {
			await moverRecursoACarpeta(resourceId, folderId);
			recursos = recursos.map((r) => (r.id === resourceId ? { ...r, folderId } : r));

			const destino = folderId ? carpetas.find((c) => c.id === folderId) : undefined;
			if (destino?.groupId) {
				const recurso = recursos.find((r) => r.id === resourceId);
				cediendoRecurso = { resourceId, nombre: recurso?.nombre ?? '', groupId: destino.groupId };
				errorCeder = undefined;
			}
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.vault.carpetas.error;
		}
	}

	function mantenerPersonal() {
		cediendoRecurso = null;
	}

	async function cederAlGrupo() {
		if (!cediendoRecurso || !$clavesDesbloqueadas) return;
		errorCeder = undefined;
		cediendoEnCurso = true;
		try {
			const detalle = await groupsApi.obtener(cediendoRecurso.groupId);
			const destinatarios = await resolverMiembrosConClave(detalle.members.map((m) => ({ userId: m.user_id, email: m.email })));
			await compartirRecursosEnLote([cediendoRecurso.resourceId], destinatarios, $clavesDesbloqueadas, 'update');
			cediendoRecurso = null;
		} catch (err) {
			errorCeder = err instanceof ApiError ? err.message : $t.vault.carpetas.errorCeder;
		} finally {
			cediendoEnCurso = false;
		}
	}

	// F-11: compartir una carpeta — mini-form inline, sin modal aparte (mismo
	// criterio liviano que el resto del panel de detalle).
	let compartiendoCarpeta = $state<{ folderId: string; nombre: string } | null>(null);
	let tipoDestinoCarpeta = $state<'user' | 'group'>('user');
	let emailCompartirCarpeta = $state('');
	let grupoCompartirCarpeta = $state('');
	let nivelCompartirCarpeta = $state<'read' | 'update' | 'owner'>('update');
	let compartiendoCarpetaEnCurso = $state(false);
	let errorCompartirCarpeta = $state<string | undefined>();

	function onCompartirCarpeta(folderId: string, nombre: string) {
		compartiendoCarpeta = { folderId, nombre };
		tipoDestinoCarpeta = 'user';
		emailCompartirCarpeta = '';
		grupoCompartirCarpeta = misGruposDondeAdmin[0]?.group_id ?? '';
		nivelCompartirCarpeta = 'update';
		errorCompartirCarpeta = undefined;
	}

	async function confirmarCompartirCarpeta(e: SubmitEvent) {
		e.preventDefault();
		if (!compartiendoCarpeta) return;
		errorCompartirCarpeta = undefined;
		compartiendoCarpetaEnCurso = true;
		try {
			if (tipoDestinoCarpeta === 'group') {
				const detalle = await groupsApi.obtener(grupoCompartirCarpeta);
				const miembros = detalle.members.map((m) => ({ userId: m.user_id, email: m.email }));
				await compartirCarpetaConGrupo(
					compartiendoCarpeta.folderId,
					compartiendoCarpeta.nombre,
					grupoCompartirCarpeta,
					miembros,
					nivelCompartirCarpeta
				);
			} else {
				await compartirCarpeta(compartiendoCarpeta.folderId, compartiendoCarpeta.nombre, emailCompartirCarpeta, nivelCompartirCarpeta);
			}
			compartiendoCarpeta = null;
		} catch (err) {
			errorCompartirCarpeta = err instanceof ApiError ? err.message : $t.vault.carpetas.error;
		} finally {
			compartiendoCarpetaEnCurso = false;
		}
	}

	async function onCrearTag(nombreTag: string, isShared: boolean) {
		try {
			const nuevo = await tagsApi.crear(nombreTag, isShared);
			tags = [...tags, nuevo];
		} catch (err) {
			errorTags = err instanceof ApiError ? err.message : $t.vault.tags.errorCrear;
		}
	}

	// Filtro por tag: intersección de los ids de cada tag seleccionado
	// (semántica AND) — se recalcula cuando cambia la selección, nunca
	// re-descifra nada (`recursos` ya está descifrado por `cargar()`).
	$effect(() => {
		const seleccion = tagsSeleccionados;
		if (seleccion.length === 0) {
			idsConTagsSeleccionados = null;
			return;
		}
		let cancelado = false;
		Promise.all(seleccion.map((id) => tagsApi.idsConTag(id))).then((listas) => {
			if (cancelado) return;
			const [primera, ...resto] = listas.map((l) => new Set(l));
			idsConTagsSeleccionados = resto.reduce((acc, s) => new Set([...acc].filter((id) => s.has(id))), primera);
		});
		return () => {
			cancelado = true;
		};
	});

	const carpetasValidasParaFiltro = $derived(
		carpetaFiltro !== null && verTodoSubcarpetas
			? new Set([carpetaFiltro, ...descendientesDe(carpetaFiltro, carpetas)])
			: null
	);
	const recursosFiltrados = $derived(
		recursos.filter((r) => {
			if (idsConTagsSeleccionados && !idsConTagsSeleccionados.has(r.id)) return false;
			if (carpetaFiltro !== null) {
				if (carpetasValidasParaFiltro) {
					if (!r.folderId || !carpetasValidasParaFiltro.has(r.folderId)) return false;
				} else if (r.folderId !== carpetaFiltro) {
					return false;
				}
			}
			if (!busqueda.trim()) return true;
			const q = busqueda.trim().toLowerCase();
			return r.nombre.toLowerCase().includes(q) || r.usuario.toLowerCase().includes(q) || r.uri.toLowerCase().includes(q);
		})
	);

	// Passkey sin PRF deja `clavesDesbloqueadas` vacío tras el login (spec
	// F-03: la passphrase sigue haciendo falta para operaciones sobre
	// recursos), y lo mismo pasa en cualquier pestaña/reload donde la
	// sesión HTTP sobrevive pero la clave desenvuelta (memoria pura, F-04)
	// no — acá es donde efectivamente hace falta, se pide una vez. Reusa
	// `LockOverlay` (mismo componente que el auto-bloqueo del layout, F-39)
	// en vez de un form ad-hoc — antes esto era un `<TextField>` suelto sin
	// ningún contexto, que un usuario real interpretó como "se cerró mi
	// sesión" cuando en realidad seguía viva, sólo faltaba desenvolver la
	// clave — mismo bug de claridad, no de lógica.
	async function alDesbloquearVault() {
		await cargar();
		await cargarOrganizacion();
	}

	async function cargar() {
		if (!$clavesDesbloqueadas) return;
		cargando = true;
		error = undefined;
		try {
			// `conDeduplicacion` (07-frontend-web.md §2): si el refresco por
			// foco de pestaña dispara mientras ya hay una carga en curso (ej.
			// el usuario cambia de pestaña y vuelve rápido), la segunda
			// llamada espera la primera en vez de disparar una request nueva.
			const nuevos = await conDeduplicacion('vault:listar', () => listarRecursos($clavesDesbloqueadas!));
			// F-30: si nada cambió (mismo conteo, mismo `updated_at` más
			// reciente), no reemplaza la lista — preserva estado de UI local
			// (ej. el panel abierto) en un refresco por foco sin cambios reales.
			if (huboCambios(recursos, nuevos)) recursos = nuevos;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.vault.error;
		} finally {
			cargando = false;
		}
	}

	// F-15: defaults de spec/02-modelo-de-datos.md — si `GET
	// /admin/password-policy` falla, generar sigue funcionando con esto en
	// vez de romperse.
	let generatorLongitud = $state(20);
	let generatorReglas = $state<ReglasCharset>({
		uppercase: true,
		lowercase: true,
		digits: true,
		symbols: true,
		exclude_ambiguous: true
	});

	onMount(() => {
		cargar();
		cargarOrganizacion();
		misGruposApi.listar().then((g) => (misGrupos = g)).catch(() => {
			/* sin grupos no rompe nada, sólo queda sin poder compartir carpetas */
		});
		passwordPolicyApi
			.obtener()
			.then((p) => {
				generatorLongitud = p.generator_default_length;
				generatorReglas = p.generator_charset_rules as ReglasCharset;
			})
			.catch(() => {
				/* default local declarado arriba sigue sirviendo */
			});
		// F-30 (07-frontend-web.md §2): recargar al volver a la pestaña, sin
		// polling — cubre el caso de compartir/crear un recurso desde otro
		// dispositivo mientras esta pestaña quedó abierta en segundo plano.
		return refrescarAlEnfocar(cargar);
	});

	function generar() {
		password = generarPassword(generatorLongitud, generatorReglas);
	}

	function generarParaEdicion() {
		editPassword = generarPassword(generatorLongitud, generatorReglas);
	}

	// --- crear ---
	let mostrarCrear = $state(false);
	let tipoNuevo = $state<TipoRecurso>('login-password');
	let nombre = $state('');
	let usuario = $state('');
	let uri = $state('');
	let password = $state('');
	let notas = $state('');
	let totpSecretBase32 = $state('');
	let creando = $state(false);
	let errorCrear = $state<string | undefined>();

	async function crear(e: SubmitEvent) {
		e.preventDefault();
		if (!$clavesDesbloqueadas || !$sesion.userId) return;
		errorCrear = undefined;
		creando = true;
		try {
			await crearRecurso(
				{ tipo: tipoNuevo, nombre, usuario, uri, password, notas, totpSecretBase32: totpSecretBase32 || undefined },
				$clavesDesbloqueadas,
				$sesion.userId
			);
			tipoNuevo = 'login-password';
			nombre = usuario = uri = password = notas = totpSecretBase32 = '';
			mostrarCrear = false;
			await cargar();
		} catch (err) {
			errorCrear = err instanceof ApiError ? err.message : $t.vault.errorCrear;
		} finally {
			creando = false;
		}
	}

	// --- panel de detalle: un solo recurso seleccionado a la vez ---
	let seleccionado = $state<Recurso | undefined>();
	let panelModo = $state<'detalle' | 'editar' | 'externo'>('detalle');

	function seleccionarFila(recurso: Recurso) {
		if (seleccionado?.id === recurso.id) {
			seleccionado = undefined;
			return;
		}
		seleccionado = recurso;
		panelModo = 'detalle';
		secretoAbierto = undefined;
		errorSecreto = undefined;
		externoPassphrase = '';
		externoExpiraHoras = '24';
		externoMaxVistas = '1';
		externoError = undefined;
		externoLink = undefined;
	}

	// F-05/F-11: ícono de compartir directo en la fila (antes había que abrir
	// el detalle primero) — abre el modal de compartir directo.
	function compartirDesdeIcono(recurso: Recurso, e: MouseEvent) {
		e.stopPropagation();
		abrirModalCompartir(recurso);
	}

	function cerrarPanel() {
		seleccionado = undefined;
	}

	// 2026-08-11: `DELETE /resources/{id}` nuevo — el botón sólo aparece si
	// `puedeBorrar` vino en `true` (ver `ResourceService::puede_borrar`), así
	// que si esto falla igual es un 403 real, no un botón mal mostrado.
	let confirmandoEliminar = $state<string | undefined>();
	let eliminando = $state(false);
	let errorEliminar = $state<string | undefined>();

	async function confirmarEliminarRecurso() {
		if (!seleccionado) return;
		eliminando = true;
		errorEliminar = undefined;
		try {
			await eliminarRecurso(seleccionado.id);
			recursos = recursos.filter((r) => r.id !== seleccionado!.id);
			confirmandoEliminar = undefined;
			seleccionado = undefined;
		} catch (err) {
			errorEliminar = err instanceof ApiError ? err.message : $t.vault.errorEliminar;
		} finally {
			eliminando = false;
		}
	}

	// 2026-08-13: contraparte de "Eliminar" para un recurso que no es propio
	// (`!puedeBorrar`) — sacar el acceso propio sin tocar la copia del dueño.
	// Mismo patrón que `confirmarEliminarRecurso`.
	let confirmandoSalir = $state<string | undefined>();
	let saliendo = $state(false);
	let errorSalir = $state<string | undefined>();

	async function confirmarSalirRecurso() {
		if (!seleccionado) return;
		saliendo = true;
		errorSalir = undefined;
		try {
			await salirDeRecurso(seleccionado.id);
			recursos = recursos.filter((r) => r.id !== seleccionado!.id);
			confirmandoSalir = undefined;
			seleccionado = undefined;
		} catch (err) {
			errorSalir = err instanceof ApiError ? err.message : $t.vault.errorSalir;
		} finally {
			saliendo = false;
		}
	}

	// Copiar usuario/URI del panel de detalle — no son secretos, pero
	// respetan el mismo timer de limpieza automática que el resto de la app
	// (`preferencias.clipboardClearMinutes`), mismo criterio que `SecretField`.
	let campoCopiado = $state<'usuario' | 'uri' | 'comando' | undefined>();
	async function copiarCampo(campo: 'usuario' | 'uri' | 'comando', valor: string) {
		await copiarConLimpieza(valor, $preferencias.clipboardClearMinutes);
		campoCopiado = campo;
		setTimeout(() => (campoCopiado = undefined), 2000);
	}

	// --- ver secreto ---
	let secretoAbierto = $state<{ password: string; notes: string; totpSecret?: string } | undefined>();
	let cargandoSecreto = $state(false);
	let errorSecreto = $state<string | undefined>();

	async function verSecretoDelSeleccionado() {
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorSecreto = undefined;
		cargandoSecreto = true;
		try {
			secretoAbierto = await verSecreto(seleccionado, $clavesDesbloqueadas);
		} catch (err) {
			errorSecreto = err instanceof ApiError ? err.message : $t.vault.errorVerSecreto;
		} finally {
			cargandoSecreto = false;
		}
	}

	// --- editar (F-07, ver recursos.ts::editarRecurso) ---
	let editNombre = $state('');
	let editUsuario = $state('');
	let editUri = $state('');
	let editPassword = $state('');
	let editNotas = $state('');
	let editTotp = $state('');
	let cargandoParaEditar = $state(false);
	let guardandoEdicion = $state(false);
	let errorEditar = $state<string | undefined>();

	async function empezarEditar() {
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorEditar = undefined;
		panelModo = 'editar';
		cargandoParaEditar = true;
		try {
			const secreto = await verSecreto(seleccionado, $clavesDesbloqueadas);
			editNombre = seleccionado.nombre;
			editUsuario = seleccionado.usuario;
			editUri = seleccionado.uri;
			editPassword = secreto.password;
			editNotas = secreto.notes;
			editTotp = secreto.totpSecret ?? '';
		} catch (err) {
			errorEditar = err instanceof ApiError ? err.message : $t.vault.errorVerSecreto;
		} finally {
			cargandoParaEditar = false;
		}
	}

	async function guardarEdicion(e: SubmitEvent) {
		e.preventDefault();
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorEditar = undefined;
		guardandoEdicion = true;
		try {
			const actualizado = await editarRecurso(
				seleccionado,
				{
					nombre: editNombre,
					usuario: editUsuario,
					uri: editUri,
					password: editPassword,
					notas: editNotas,
					totpSecretBase32: editTotp || undefined
				},
				$clavesDesbloqueadas
			);
			recursos = recursos.map((r) => (r.id === seleccionado!.id ? actualizado : r));
			seleccionado = actualizado;
			panelModo = 'detalle';
		} catch (err) {
			errorEditar = err instanceof ApiError ? err.message : $t.vault.errorEditar;
		} finally {
			guardandoEdicion = false;
		}
	}

	// --- compartir (modal estilo Passbolt, referencia mandada por el
	// usuario 3 veces) — antes esto era un panel inline aplicando cada
	// cambio al toque; acá los cambios quedan "pendientes" en memoria hasta
	// tocar Guardar, mismo patrón que la referencia (banner "Haga clic en
	// Guardar para aplicar los cambios pendientes"). ---
	interface FilaCompartir {
		granteeType: 'user' | 'group';
		granteeId: string;
		label: string;
		/** `null` = fila agregada en esta sesión del modal, todavía no existe en el backend. */
		nivelOriginal: 'read' | 'update' | 'owner' | null;
		nivel: 'read' | 'update' | 'owner';
		quitar: boolean;
		/** Sólo presente en filas nuevas — hace falta para sellar la DEK al guardar. */
		publicKeyX25519B64?: string;
	}

	// Hallazgo real de uso 2026-08-11: el buscador de destinatarios mostraba
	// un ícono genérico para todos — cacheado y lazy (Map), mismo patrón que
	// `admin/users/+page.svelte::avatarDe`, sólo se pide si `hasAvatar` dice
	// que existe (la mayoría de los resultados no tiene uno cargado).
	let avataresUsuarios = $state<Map<string, string>>(new Map());
	async function avatarDeUsuario(userId: string, hasAvatar: boolean): Promise<string | undefined> {
		if (!hasAvatar) return undefined;
		if (avataresUsuarios.has(userId)) return avataresUsuarios.get(userId);
		const url = await obtenerAvatarUrlDeUsuario(userId);
		if (url) avataresUsuarios = new Map(avataresUsuarios).set(userId, url);
		return url ?? undefined;
	}

	let mostrarModalCompartir = $state(false);
	let cargandoPermisos = $state(false);
	let errorPermisos = $state<string | undefined>();
	let guardandoCompartir = $state(false);
	let filasCompartir = $state<FilaCompartir[]>([]);
	let busquedaCompartir = $state('');
	let resultadosBusquedaCompartir = $state<UsuarioBusqueda[]>([]);
	let buscandoCompartir = $state(false);
	let timeoutBusquedaCompartir: ReturnType<typeof setTimeout> | undefined;

	const hayPendientesCompartir = $derived(
		filasCompartir.some((f) => f.nivelOriginal === null || f.quitar || f.nivel !== f.nivelOriginal)
	);

	async function abrirModalCompartir(recurso: Recurso) {
		if (seleccionado?.id !== recurso.id) seleccionarFila(recurso);
		mostrarModalCompartir = true;
		busquedaCompartir = '';
		resultadosBusquedaCompartir = [];
		errorPermisos = undefined;
		cargandoPermisos = true;
		try {
			const permisos = await listarPermisos(recurso.id);
			filasCompartir = permisos.map((p) => ({
				granteeType: p.granteeType,
				granteeId: p.granteeId,
				label: p.label ?? p.granteeId,
				nivelOriginal: p.level,
				nivel: p.level,
				quitar: false
			}));
		} catch (err) {
			errorPermisos = err instanceof ApiError ? err.message : $t.vault.errorCompartir;
		} finally {
			cargandoPermisos = false;
		}
	}

	function cerrarModalCompartir() {
		mostrarModalCompartir = false;
	}

	function alTipearBusquedaCompartir() {
		clearTimeout(timeoutBusquedaCompartir);
		const q = busquedaCompartir;
		timeoutBusquedaCompartir = setTimeout(async () => {
			if (q.trim().length < 2) {
				resultadosBusquedaCompartir = [];
				return;
			}
			buscandoCompartir = true;
			try {
				const todos = await buscarUsuarios(q);
				resultadosBusquedaCompartir = todos.filter(
					(u) => !filasCompartir.some((f) => f.granteeType === 'user' && f.granteeId === u.userId && !f.quitar)
				);
			} catch {
				resultadosBusquedaCompartir = [];
			} finally {
				buscandoCompartir = false;
			}
		}, 250);
	}

	function agregarDeBusquedaCompartir(u: UsuarioBusqueda) {
		filasCompartir = [
			...filasCompartir,
			{
				granteeType: 'user',
				granteeId: u.userId,
				label: u.email,
				nivelOriginal: null,
				nivel: 'read',
				quitar: false,
				publicKeyX25519B64: u.publicKeyX25519B64
			}
		];
		busquedaCompartir = '';
		resultadosBusquedaCompartir = [];
	}

	function quitarFilaCompartir(f: FilaCompartir) {
		if (f.nivelOriginal === null) {
			filasCompartir = filasCompartir.filter((x) => x !== f);
		} else {
			f.quitar = true;
		}
	}

	async function guardarCompartir() {
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorPermisos = undefined;
		guardandoCompartir = true;
		try {
			for (const f of filasCompartir) {
				if (f.quitar && f.nivelOriginal !== null) {
					await revocarPermiso(seleccionado.id, f.granteeType, f.granteeId);
				} else if (f.nivelOriginal === null && f.publicKeyX25519B64) {
					await compartirRecursoConDestinatario(seleccionado, f.granteeId, f.publicKeyX25519B64, $clavesDesbloqueadas, f.nivel);
				} else if (f.nivelOriginal !== null && f.nivel !== f.nivelOriginal) {
					await cambiarNivelPermiso(seleccionado.id, f.granteeType, f.granteeId, f.nivel);
				}
			}
			mostrarModalCompartir = false;
		} catch (err) {
			errorPermisos = err instanceof ApiError ? err.message : $t.vault.errorCompartir;
		} finally {
			guardandoCompartir = false;
		}
	}

	// --- compartir externo (F-26) — comparte la contraseña del recurso con
	// alguien sin cuenta en Ellkan, vía /s/{id}. Sólo la contraseña (no
	// notas/TOTP): es el caso de uso más común y evita ambigüedad sobre qué
	// campo va en el link.
	let externoPassphrase = $state('');
	let externoExpiraHoras = $state('24');
	let externoMaxVistas = $state('1');
	let externoCreando = $state(false);
	let externoError = $state<string | undefined>();
	let externoLink = $state<string | undefined>();

	async function crearExterno(e: SubmitEvent) {
		e.preventDefault();
		if (!seleccionado || !$clavesDesbloqueadas) return;
		externoError = undefined;
		externoCreando = true;
		try {
			const secreto = await verSecreto(seleccionado, $clavesDesbloqueadas);
			const { ciphertextB64, claveFragmentoB64Url, passwordSaltB64 } = await cifrarContenidoDeShare(
				secreto.password,
				externoPassphrase || undefined
			);
			const creado = await externalSharesApi.crear({
				ciphertext_b64: ciphertextB64,
				password_protected: !!externoPassphrase,
				password_salt_b64: passwordSaltB64,
				max_views: Number(externoMaxVistas),
				expires_in_hours: Number(externoExpiraHoras)
			});
			externoLink = `${location.origin}/s/${creado.id}#${claveFragmentoB64Url}`;
		} catch (err) {
			externoError = err instanceof ApiError ? err.message : $t.vault.errorExterno;
		} finally {
			externoCreando = false;
		}
	}

	// --- selección masiva (F-27, export selectivo) — mismo patrón que
	// `(app)/admin/users/+page.svelte` ---
	let seleccionados = $state<Set<string>>(new Set());
	function toggleSeleccion(id: string) {
		const nuevo = new Set(seleccionados);
		if (nuevo.has(id)) nuevo.delete(id);
		else nuevo.add(id);
		seleccionados = nuevo;
	}
	function toggleSeleccionTodos() {
		seleccionados =
			seleccionados.size === recursosFiltrados.length ? new Set() : new Set(recursosFiltrados.map((r) => r.id));
	}

	// F-11: edición masiva — no tiene sentido "editar el secreto de N
	// recursos a la vez" en un gestor zero-knowledge (eso sería N ediciones
	// con contenido propio cada una, no una acción masiva real). Lo que sí
	// tiene sentido: mover varios a la vez a una carpeta, o taggearlos —
	// ambas reusan los endpoints singulares ya existentes en un loop, el
	// volumen típico no justifica un endpoint batch nuevo.
	let carpetaMasiva = $state('');
	let aplicandoMasivo = $state(false);
	let errorMasivo = $state<string | undefined>();

	async function moverSeleccionADeCarpeta() {
		if (seleccionados.size === 0) return;
		aplicandoMasivo = true;
		errorMasivo = undefined;
		try {
			const destino = carpetaMasiva === '' ? null : carpetaMasiva;
			await Promise.all([...seleccionados].map((id) => moverRecursoACarpeta(id, destino)));
			recursos = recursos.map((r) => (seleccionados.has(r.id) ? { ...r, folderId: destino } : r));
			seleccionados = new Set();
		} catch (err) {
			errorMasivo = err instanceof ApiError ? err.message : $t.vault.errorMasivo;
		} finally {
			aplicandoMasivo = false;
		}
	}

	let tagMasivo = $state('');

	async function agregarTagASeleccion() {
		if (seleccionados.size === 0 || !tagMasivo) return;
		aplicandoMasivo = true;
		errorMasivo = undefined;
		try {
			await Promise.all([...seleccionados].map((id) => tagsApi.aplicar(id, tagMasivo)));
			seleccionados = new Set();
		} catch (err) {
			errorMasivo = err instanceof ApiError ? err.message : $t.vault.errorMasivo;
		} finally {
			aplicandoMasivo = false;
		}
	}

	// Borrado masivo — mismo patrón que mover/taggear, con confirmación
	// inline (mismo criterio que el borrado individual, `confirmandoEliminar`
	// más abajo). Filtra a `puedeBorrar` antes de mandar nada: son los
	// mismos recursos que ya muestran el botón de borrar en el panel de
	// detalle, evitar pedir un borrado que el backend va a rechazar seguro.
	let confirmandoEliminarSeleccion = $state(false);

	async function eliminarSeleccion() {
		const borrables = recursos.filter((r) => seleccionados.has(r.id) && r.puedeBorrar).map((r) => r.id);
		if (borrables.length === 0) return;
		aplicandoMasivo = true;
		errorMasivo = undefined;
		try {
			await Promise.all(borrables.map((id) => eliminarRecurso(id)));
			recursos = recursos.filter((r) => !borrables.includes(r.id));
			seleccionados = new Set();
			confirmandoEliminarSeleccion = false;
		} catch (err) {
			errorMasivo = err instanceof ApiError ? err.message : $t.vault.errorMasivo;
		} finally {
			aplicandoMasivo = false;
		}
	}

	// Contraparte de "eliminar" masivo para recursos compartidos (no
	// propios) — mismo patrón, filtra a `!puedeBorrar`.
	let confirmandoSalirSeleccion = $state(false);

	async function salirSeleccion() {
		const compartidos = recursos.filter((r) => seleccionados.has(r.id) && !r.puedeBorrar).map((r) => r.id);
		if (compartidos.length === 0) return;
		aplicandoMasivo = true;
		errorMasivo = undefined;
		try {
			await Promise.all(compartidos.map((id) => salirDeRecurso(id)));
			recursos = recursos.filter((r) => !compartidos.includes(r.id));
			seleccionados = new Set();
			confirmandoSalirSeleccion = false;
		} catch (err) {
			errorMasivo = err instanceof ApiError ? err.message : $t.vault.errorMasivo;
		} finally {
			aplicandoMasivo = false;
		}
	}

	// --- módulo 3: compartir en lote (modal, mismo patrón que el compartir
	// individual — buscador en vivo en vez de una lista de emails a mano). ---
	let mostrarModalCompartirLote = $state(false);
	let destinatariosLote = $state<{ userId: string; label: string; publicKeyX25519B64: string; hasAvatar: boolean }[]>([]);
	let nivelCompartirLote = $state<'read' | 'update' | 'owner'>('read');
	let busquedaCompartirLote = $state('');
	let resultadosBusquedaLote = $state<UsuarioBusqueda[]>([]);
	let buscandoCompartirLote = $state(false);
	let timeoutBusquedaLote: ReturnType<typeof setTimeout> | undefined;
	let resumenCompartirLote = $state<string | undefined>();
	/** Hallazgo real de uso 2026-08-11: antes se mostraba un hint fijo
	 * ("revisá que los recursos sean de metadata compartida...") sin importar
	 * la causa real — acá se listan los motivos reales que ya devuelve el
	 * backend por ítem (ej. "esta persona ya tiene acceso a este recurso"). */
	let erroresCompartirLote = $state<{ label: string; error: string }[]>([]);

	function abrirModalCompartirLote() {
		if (seleccionados.size === 0) return;
		destinatariosLote = [];
		busquedaCompartirLote = '';
		resultadosBusquedaLote = [];
		resumenCompartirLote = undefined;
		erroresCompartirLote = [];
		errorMasivo = undefined;
		mostrarModalCompartirLote = true;
	}

	function cerrarModalCompartirLote() {
		mostrarModalCompartirLote = false;
	}

	function alTipearBusquedaLote() {
		clearTimeout(timeoutBusquedaLote);
		const q = busquedaCompartirLote;
		timeoutBusquedaLote = setTimeout(async () => {
			if (q.trim().length < 2) {
				resultadosBusquedaLote = [];
				return;
			}
			buscandoCompartirLote = true;
			try {
				const todos = await buscarUsuarios(q);
				resultadosBusquedaLote = todos.filter((u) => !destinatariosLote.some((d) => d.userId === u.userId));
			} catch {
				resultadosBusquedaLote = [];
			} finally {
				buscandoCompartirLote = false;
			}
		}, 250);
	}

	function agregarDestinatarioLote(u: UsuarioBusqueda) {
		destinatariosLote = [
			...destinatariosLote,
			{ userId: u.userId, label: u.email, publicKeyX25519B64: u.publicKeyX25519B64, hasAvatar: u.hasAvatar }
		];
		busquedaCompartirLote = '';
		resultadosBusquedaLote = [];
	}

	function quitarDestinatarioLote(userId: string) {
		destinatariosLote = destinatariosLote.filter((d) => d.userId !== userId);
	}

	async function compartirSeleccionEnLote() {
		if (seleccionados.size === 0 || destinatariosLote.length === 0) return;
		aplicandoMasivo = true;
		errorMasivo = undefined;
		resumenCompartirLote = undefined;
		erroresCompartirLote = [];
		try {
			const resultados = await compartirRecursosEnLote(
				[...seleccionados],
				destinatariosLote.map((d) => ({ userId: d.userId, publicKeyX25519B64: d.publicKeyX25519B64 })),
				$clavesDesbloqueadas!,
				nivelCompartirLote
			);
			const ok = resultados.filter((r) => !r.error).length;
			const conError = resultados.length - ok;
			resumenCompartirLote = $t.vault.compartirLote.resumen(ok, conError);
			erroresCompartirLote = resultados
				.filter((r): r is typeof r & { error: string } => !!r.error)
				.map((r) => ({
					label: destinatariosLote.find((d) => d.userId === r.recipient_user_id)?.label ?? r.recipient_user_id,
					error: r.error
				}));
			if (conError === 0) {
				seleccionados = new Set();
				mostrarModalCompartirLote = false;
			}
		} catch (err) {
			errorMasivo = err instanceof ApiError ? err.message : $t.vault.errorMasivo;
		} finally {
			aplicandoMasivo = false;
		}
	}

	// --- exportar/importar (F-27) — antes vivía en `/settings/export-import`,
	// separado del propio Vault que exporta; movido acá para poder elegir
	// "todos" o sólo lo seleccionado arriba, sin duplicar la carga/descifrado
	// de recursos que `cargar()` ya hizo.
	let mostrarExportar = $state(false);
	let cargandoPolitica = $state(true);
	let politica = $state<ExportPolicy | undefined>();
	let excepcionAdmin = $state(false);

	async function abrirExportar() {
		mostrarExportar = !mostrarExportar;
		if (!mostrarExportar || politica) return;
		cargandoPolitica = true;
		try {
			politica = await exportPolicyApi.obtener();
		} catch {
			/* sin política, el panel queda oculto (puedeExportar/puedeImportar dan false) */
		}
		if (politica && !politica.export_enabled) {
			try {
				await adminExportPolicyApi.obtener();
				excepcionAdmin = true;
			} catch {
				excepcionAdmin = false;
			}
		}
		cargandoPolitica = false;
	}

	// Módulo 1 (RBAC granular): la política de org (`politica.*_enabled`) sigue
	// siendo el techo — el permiso de rol sólo puede restringir por debajo de
	// ese techo, nunca habilitar algo que la organización apagó.
	const puedeExportar = $derived(
		!!politica && (politica.export_enabled || excepcionAdmin) && tienePermiso($permisos, 'export.use')
	);
	const puedeImportar = $derived(!!politica && politica.import_enabled && tienePermiso($permisos, 'import.use'));
	const formatosDisponibles = $derived((politica?.allowed_formats ?? []) as FormatoExport[]);

	let alcanceExport = $state<'todos' | 'seleccionados'>('todos');
	let formatoExport = $state<FormatoExport>('kdbx');
	let passwordExport = $state('');
	let exportando = $state(false);
	let errorExport = $state<string | undefined>();
	let okExport = $state<number | undefined>();
	const fortalezaExport = $derived(evaluarFortaleza(passwordExport));
	const labelFortalezaExport = $derived(
		[
			$t.fortalezaPassword.muyDebil,
			$t.fortalezaPassword.debil,
			$t.fortalezaPassword.aceptable,
			$t.fortalezaPassword.fuerte,
			$t.fortalezaPassword.muyFuerte
		][fortalezaExport.score]
	);

	async function hacerExport(e: SubmitEvent) {
		e.preventDefault();
		if (!$clavesDesbloqueadas) return;
		errorExport = undefined;
		okExport = undefined;
		exportando = true;
		try {
			const aExportar =
				alcanceExport === 'seleccionados' ? recursos.filter((r) => seleccionados.has(r.id)) : recursos;
			const { filas } = await construirFilasExport(aExportar, $clavesDesbloqueadas);
			const archivo = await exportar(formatoExport, filas, {
				password: formatoExport === 'kdbx' ? passwordExport : undefined,
				cuentaEmail: $sesion.email ?? ''
			});
			descargarArchivo(archivo);
			okExport = filas.length;
			passwordExport = '';
		} catch (err) {
			errorExport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorExportar;
		} finally {
			exportando = false;
		}
	}

	let archivoImport = $state<File | undefined>();
	let passwordImport = $state('');
	let filasPreview = $state<FilaExport[] | undefined>();
	let previsualizando = $state(false);
	let importando = $state(false);
	let errorImport = $state<string | undefined>();
	let okImport = $state<number | undefined>();

	function alElegirArchivo(e: Event) {
		archivoImport = (e.target as HTMLInputElement).files?.[0];
		filasPreview = undefined;
		errorImport = undefined;
		okImport = undefined;
	}

	async function previsualizar() {
		if (!archivoImport) return;
		errorImport = undefined;
		okImport = undefined;
		const formato = detectarFormatoPorNombre(archivoImport.name);
		if (!formato) {
			errorImport = $t.exportImport.errorFormatoDesconocido;
			return;
		}
		previsualizando = true;
		try {
			const bytes = await archivoImport.arrayBuffer();
			filasPreview = await parsearArchivoImport(formato, bytes, {
				password: formato === 'kdbx' ? passwordImport : undefined
			});
		} catch (err) {
			errorImport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorImportar;
			filasPreview = undefined;
		} finally {
			previsualizando = false;
		}
	}

	async function confirmarImport() {
		if (!filasPreview || !archivoImport || !$clavesDesbloqueadas || !$sesion.userId) return;
		const formato = detectarFormatoPorNombre(archivoImport.name);
		if (!formato) return;
		errorImport = undefined;
		importando = true;
		try {
			const creados = await importar(formato, filasPreview, $clavesDesbloqueadas, $sesion.userId);
			okImport = creados;
			filasPreview = undefined;
			archivoImport = undefined;
			passwordImport = '';
			await cargar();
		} catch (err) {
			errorImport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorImportar;
		} finally {
			importando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.vault.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.vault.titulo}</h1>

{#if !$clavesDesbloqueadas}
	<LockOverlay email={$sesion.email ?? ''} onDesbloqueado={alDesbloquearVault} />
{:else}
	<div class="vault-layout" class:con-panel={!!seleccionado}>
		{#if tienePermiso($permisos, 'folders.use')}
		<Card padded={true}>
			<FolderTree
				nodos={carpetas}
				cargando={cargandoCarpetas}
				filtroActivo={carpetaFiltro}
				onCrear={onCrearCarpeta}
				onMover={onMoverCarpeta}
				onFiltrar={onFiltrarCarpeta}
				onCompartir={tienePermiso($permisos, 'folder.share') && puedeCompartirCarpetas ? onCompartirCarpeta : undefined}
			/>
			{#if errorCarpetas}<p class="error">{errorCarpetas}</p>{/if}
			{#if compartiendoCarpeta}
				<form class="form-compartir-carpeta" onsubmit={confirmarCompartirCarpeta}>
					<p class="hint">{$t.vault.carpetas.compartirCon(compartiendoCarpeta.nombre)}</p>
					{#if misGruposDondeAdmin.length > 0}
						<label class="campo-nivel">
							{$t.vault.carpetas.tipoDestino}
							<select bind:value={tipoDestinoCarpeta}>
								<option value="user">{$t.vault.carpetas.tipoDestinoPersona}</option>
								<option value="group">{$t.vault.carpetas.tipoDestinoGrupo}</option>
							</select>
						</label>
					{/if}
					{#if tipoDestinoCarpeta === 'group'}
						<label class="campo-nivel">
							{$t.vault.carpetas.seleccionarGrupo}
							<select bind:value={grupoCompartirCarpeta}>
								{#each misGruposDondeAdmin as g (g.group_id)}
									<option value={g.group_id}>{g.name}</option>
								{/each}
							</select>
						</label>
					{:else}
						<TextField
							label={$t.vault.carpetas.emailDestinatario}
							type="email"
							bind:value={emailCompartirCarpeta}
							required
						/>
					{/if}
					<label class="campo-nivel">
						{$t.vault.carpetas.nivel}
						<select bind:value={nivelCompartirCarpeta}>
							<option value="read">{$t.vault.carpetas.nivelRead}</option>
							<option value="update">{$t.vault.carpetas.nivelUpdate}</option>
							<option value="owner">{$t.vault.carpetas.nivelOwner}</option>
						</select>
					</label>
					{#if errorCompartirCarpeta}<p class="error">{errorCompartirCarpeta}</p>{/if}
					<div class="botones-compartir-carpeta">
						<Button type="submit" variant="primary" loading={compartiendoCarpetaEnCurso}>
							{$t.vault.carpetas.compartir}
						</Button>
						<Button type="button" variant="ghost" onclick={() => (compartiendoCarpeta = null)}>
							{$t.vault.cancelar}
						</Button>
					</div>
				</form>
			{/if}
		</Card>
		{/if}

		<Card>
			{#if cargando}
				<p>{$t.vault.cargando}</p>
			{:else if error}
				<p class="error">{error}</p>
			{:else}
				<div class="cabecera">
					<p class="conteo">{$t.vault.conteo(recursosFiltrados.length)}</p>
					{#if carpetaFiltro !== null}
						<label class="ver-todo">
							<input type="checkbox" bind:checked={verTodoSubcarpetas} />
							{$t.vault.carpetas.verTodo}
						</label>
					{/if}
					<div class="botones">
						<Button variant="secondary" onclick={abrirExportar}>
							<Icon path={ICONO_EXPORTAR} size={14} />
							{$t.exportImport.titulo}
						</Button>
						<Button variant="primary" onclick={() => (mostrarCrear = !mostrarCrear)}>
							<Icon path={ICONO_NUEVO} size={14} />
							{$t.vault.nuevoRecurso}
						</Button>
					</div>
				</div>

				<TextField label={$t.vault.buscar} bind:value={busqueda} />
				<TagFilterBar tags={tags} bind:seleccionados={tagsSeleccionados} cargando={cargandoTags} onCrear={onCrearTag} />
				{#if errorTags}<p class="error">{errorTags}</p>{/if}

				{#if recursosFiltrados.length === 0}
					<p class="hint">{$t.vault.sinRecursos}</p>
				{:else}
					<div class="barra-seleccion">
						<button type="button" class="link" onclick={toggleSeleccionTodos}>
							{seleccionados.size === recursosFiltrados.length && recursosFiltrados.length > 0
								? $t.vault.deseleccionarTodos
								: $t.vault.seleccionarTodos}
						</button>
						{#if seleccionados.size > 0}<span class="hint">{$t.vault.conteoSeleccionados(seleccionados.size)}</span>{/if}
					</div>
					{#if seleccionados.size > 0}
						<div class="acciones-masivas">
							<select bind:value={carpetaMasiva}>
								<option value="">{$t.vault.carpetas.raiz}</option>
								{#each carpetas as c (c.id)}
									<option value={c.id}>{c.nombre}</option>
								{/each}
							</select>
							<Button variant="secondary" onclick={moverSeleccionADeCarpeta} loading={aplicandoMasivo}>
								<Icon path={ICONO_CARPETA} size={14} />
								{$t.vault.moverSeleccion}
							</Button>
							<select bind:value={tagMasivo}>
								<option value="">{$t.vault.tags.todos}</option>
								{#each tags as tg (tg.id)}
									<option value={tg.id}>{tg.name}</option>
								{/each}
							</select>
							<Button variant="secondary" onclick={agregarTagASeleccion} loading={aplicandoMasivo} disabled={!tagMasivo}>
								<Icon path={ICONO_TAG} size={14} />
								{$t.vault.taggearSeleccion}
							</Button>
							<Button variant="secondary" onclick={abrirModalCompartirLote}>
								<Icon path={ICONO_COMPARTIR} size={14} />
								{$t.vault.compartirLote.boton}
							</Button>
							{#if recursos.filter((r) => seleccionados.has(r.id) && r.puedeBorrar).length > 0}
								{#if confirmandoEliminarSeleccion}
									<Button variant="danger" onclick={eliminarSeleccion} loading={aplicandoMasivo}>
										{$t.vault.confirmarEliminarSeleccion(recursos.filter((r) => seleccionados.has(r.id) && r.puedeBorrar).length)}
									</Button>
									<Button variant="ghost" onclick={() => (confirmandoEliminarSeleccion = false)}>{$t.vault.cancelar}</Button>
								{:else}
									<Button variant="danger" onclick={() => (confirmandoEliminarSeleccion = true)}>
										<Icon path={ICONO_ELIMINAR} size={14} />
										{$t.vault.eliminarSeleccion}
									</Button>
								{/if}
							{/if}
							{#if recursos.filter((r) => seleccionados.has(r.id) && !r.puedeBorrar).length > 0}
								{#if confirmandoSalirSeleccion}
									<Button variant="secondary" onclick={salirSeleccion} loading={aplicandoMasivo}>
										{$t.vault.confirmarSalirSeleccion(recursos.filter((r) => seleccionados.has(r.id) && !r.puedeBorrar).length)}
									</Button>
									<Button variant="ghost" onclick={() => (confirmandoSalirSeleccion = false)}>{$t.vault.cancelar}</Button>
								{:else}
									<Button variant="secondary" onclick={() => (confirmandoSalirSeleccion = true)}>
										{$t.vault.salirSeleccion}
									</Button>
								{/if}
							{/if}
						</div>
						{#if errorMasivo}<p class="error">{errorMasivo}</p>{/if}
					{/if}
					<Table
						columnas={[
							{ key: 'sel', header: '' },
							{ key: 'nombre', header: $t.vault.nombre },
							{ key: 'usuario', header: $t.vault.usuario },
							{ key: 'uri', header: $t.vault.uri },
							{ key: 'tipo', header: '' }
						]}
						filas={recursosFiltrados}
						claveFila={(r) => r.id}
						seleccionadaId={seleccionado?.id}
						onSeleccionar={seleccionarFila}
					>
						{#snippet fila(r)}
							<td onclick={(e) => e.stopPropagation()}>
								<input
									class="checkbox-seleccion"
									type="checkbox"
									checked={seleccionados.has(r.id)}
									onchange={() => toggleSeleccion(r.id)}
								/>
							</td>
							<td>{r.nombre}</td>
							<td class="secundario">{r.usuario}</td>
							<td class="secundario">{r.uri}</td>
							<td class="secundario">
								<button
									type="button"
									class="icono-copiar"
									onclick={(e) => compartirDesdeIcono(r, e)}
									title={$t.vault.compartir}
								>
									⇄
								</button>
							</td>
						{/snippet}
					</Table>
				{/if}
			{/if}
		</Card>

		{#if seleccionado}
			<Card padded={true}>
				<div class="panel">
					<div class="panel-cabecera">
						<h2>{seleccionado.nombre}</h2>
						<button type="button" class="cerrar" onclick={cerrarPanel} title={$t.vault.cerrarPanel}>&times;</button>
					</div>

					{#if panelModo === 'detalle'}
						{#if infoConexion(seleccionado)}
							{@const info = infoConexion(seleccionado)!}
							<div class="conexion-header">
								<span class="conexion-protocolo">{info.protocolo}</span>
								<span class="conexion-puerto">{$t.vault.puerto} {info.puerto}</span>
							</div>
						{/if}
						<dl class="campos">
							<dt>{$t.vault.usuario}</dt>
							<dd>
								{seleccionado.usuario || '—'}
								{#if seleccionado.usuario}
									<button
										type="button"
										class="icono-copiar"
										onclick={() => copiarCampo('usuario', seleccionado!.usuario)}
										aria-label={$t.secretField.copiar}
									>
										{campoCopiado === 'usuario' ? '✓' : '⧉'}
									</button>
								{/if}
							</dd>
							{#if seleccionado.uri}
								<dt>{$t.vault.uri}</dt>
								<dd>
									<a href={seleccionado.uri} target="_blank" rel="noreferrer">{seleccionado.uri}</a>
									<button
										type="button"
										class="icono-copiar"
										onclick={() => copiarCampo('uri', seleccionado!.uri)}
										aria-label={$t.secretField.copiar}
									>
										{campoCopiado === 'uri' ? '✓' : '⧉'}
									</button>
								</dd>
							{/if}
						</dl>
						{#if comandoDeConexion(seleccionado)}
							{@const comando = comandoDeConexion(seleccionado)!}
							<div class="conexion-comando">
								<span class="conexion-comando-label">{$t.vault.comandoConexion}</span>
								<div class="conexion-comando-linea">
									<code>{comando}</code>
									<Button variant="secondary" onclick={() => copiarCampo('comando', comando)}>
										{campoCopiado === 'comando' ? $t.secretField.copiado : $t.secretField.copiar}
									</Button>
								</div>
							</div>
						{/if}

						{#if tienePermiso($permisos, 'folders.use')}
						<label class="campo-carpeta">
							{$t.vault.carpetas.titulo}
							<select
								value={seleccionado.folderId ?? ''}
								onchange={(e) => onMoverRecurso(seleccionado!.id, e.currentTarget.value === '' ? null : e.currentTarget.value)}
							>
								<option value="">{$t.vault.carpetas.raiz}</option>
								{#each carpetas as c (c.id)}
									<option value={c.id}>{c.nombre}</option>
								{/each}
							</select>
						</label>
						{/if}

						{#if !secretoAbierto}
							<Button variant="secondary" onclick={verSecretoDelSeleccionado} loading={cargandoSecreto}>
								{$t.vault.verSecreto}
							</Button>
						{:else}
							<SecretField
								label={$t.vault.password}
								valor={secretoAbierto.password}
								puedeRevelar={tienePermiso($permisos, 'password.preview')}
								puedeCopiar={tienePermiso($permisos, 'password.copy')}
							/>
							{#if secretoAbierto.notes}
								<p class="notas">{secretoAbierto.notes}</p>
							{/if}
							{#if secretoAbierto.totpSecret}
								<SecretField label="TOTP" valor={secretoAbierto.totpSecret} />
							{/if}
						{/if}
						{#if errorSecreto}<p class="error">{errorSecreto}</p>{/if}

						<div class="panel-acciones">
							<Button variant="ghost" onclick={empezarEditar}>{$t.vault.editar}</Button>
							<Button variant="ghost" onclick={() => abrirModalCompartir(seleccionado!)}>{$t.vault.compartir}</Button>
							<Button variant="ghost" onclick={() => (panelModo = 'externo')}>{$t.vault.compartirExterno}</Button>
							{#if seleccionado.puedeBorrar}
								{#if confirmandoEliminar === seleccionado.id}
									<Button variant="ghost" onclick={confirmarEliminarRecurso} loading={eliminando}>
										{$t.vault.confirmarEliminar}
									</Button>
									<Button variant="ghost" onclick={() => (confirmandoEliminar = undefined)}>{$t.vault.cancelar}</Button>
								{:else}
									<Button variant="ghost" onclick={() => (confirmandoEliminar = seleccionado!.id)}>{$t.vault.eliminar}</Button>
								{/if}
							{:else}
								{#if confirmandoSalir === seleccionado.id}
									<Button variant="ghost" onclick={confirmarSalirRecurso} loading={saliendo}>
										{$t.vault.confirmarSalir}
									</Button>
									<Button variant="ghost" onclick={() => (confirmandoSalir = undefined)}>{$t.vault.cancelar}</Button>
								{:else}
									<Button variant="ghost" onclick={() => (confirmandoSalir = seleccionado!.id)}>{$t.vault.salir}</Button>
								{/if}
							{/if}
						</div>
						{#if errorEliminar}<p class="error">{errorEliminar}</p>{/if}
						{#if errorSalir}<p class="error">{errorSalir}</p>{/if}
					{:else if panelModo === 'editar'}
						{#if cargandoParaEditar}
							<p>{$t.vault.cargando}</p>
						{:else}
							<form onsubmit={guardarEdicion}>
								<TextField label={$t.vault.nombre} bind:value={editNombre} required />
								<TextField label={$t.vault.usuario} bind:value={editUsuario} />
								<TextField label={$t.vault.uri} bind:value={editUri} />
								<div class="con-generar">
									<TextField label={$t.vault.password} type="password" bind:value={editPassword} required />
									<Button type="button" variant="ghost" onclick={generarParaEdicion}>{$t.vault.generarPassword}</Button>
								</div>
								<TextField label={$t.vault.notas} bind:value={editNotas} />
								<TextField label={$t.vault.totpOpcional} bind:value={editTotp} />
								{#if errorEditar}<p class="error">{errorEditar}</p>{/if}
								<div class="botones">
									<Button type="submit" variant="primary" loading={guardandoEdicion}>{$t.vault.guardarEdicion}</Button>
									<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
								</div>
							</form>
						{/if}
					{:else if panelModo === 'externo'}
						<form onsubmit={crearExterno}>
							<TextField label={$t.vault.externoExpiraHoras} type="number" bind:value={externoExpiraHoras} required />
							<TextField label={$t.vault.externoMaxVistas} type="number" bind:value={externoMaxVistas} required />
							<TextField label={$t.vault.externoPassphrase} type="password" bind:value={externoPassphrase} />
							{#if externoError}<p class="error">{externoError}</p>{/if}
							{#if externoLink}
								<p class="hint">{$t.vault.externoLinkListo}</p>
								<SecretField label={$t.vault.compartirExterno} valor={externoLink} />
								<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
							{:else}
								<div class="botones">
									<Button type="submit" variant="primary" loading={externoCreando}>{$t.vault.externoCrear}</Button>
									<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
								</div>
							{/if}
						</form>
					{/if}
				</div>
			</Card>
		{/if}
	</div>
{/if}

{#if mostrarModalCompartir && seleccionado}
	<Modal titulo={$t.vault.compartirTitulo} subtitulo={seleccionado.nombre} onCerrar={cerrarModalCompartir}>
		{#if cargandoPermisos}
			<p class="hint">{$t.admin.comun.cargando}</p>
		{:else}
			{#if filasCompartir.length > 0}
				<ul class="lista-grantees">
					{#each filasCompartir as f (f.granteeType + f.granteeId)}
						<li
							class="fila-grantee"
							class:fila-pendiente={f.quitar || f.nivelOriginal === null || f.nivel !== f.nivelOriginal}
							class:fila-quitar={f.quitar}
						>
							<span class="icono-grantee">{f.granteeType === 'group' ? '👥' : '👤'}</span>
							<span class="label-grantee">{f.label}</span>
							{#if !f.quitar}
								<select bind:value={f.nivel} disabled={f.granteeType !== 'user' && f.nivelOriginal !== null}>
									<option value="read">{$t.vault.carpetas.nivelRead}</option>
									<option value="update">{$t.vault.carpetas.nivelUpdate}</option>
									<option value="owner">{$t.vault.carpetas.nivelOwner}</option>
								</select>
							{:else}
								<span class="hint">{$t.vault.seQuitaAlGuardar}</span>
							{/if}
							<button type="button" class="icono-copiar" onclick={() => quitarFilaCompartir(f)} aria-label={$t.vault.revocarPermiso}>
								✕
							</button>
						</li>
					{/each}
				</ul>
			{/if}

			<label class="campo-nivel campo-busqueda-compartir">
				{$t.vault.compartirCon}
				<TextField
					label=""
					bind:value={busquedaCompartir}
					oninput={alTipearBusquedaCompartir}
					placeholder={$t.vault.compartirBuscarPlaceholder}
				/>
			</label>
			{#if buscandoCompartir}
				<p class="hint">{$t.admin.comun.buscar}…</p>
			{:else if resultadosBusquedaCompartir.length > 0}
				<ul class="lista-resultados-busqueda">
					{#each resultadosBusquedaCompartir as u (u.userId)}
						<li>
							<button type="button" class="resultado-busqueda" onclick={() => agregarDeBusquedaCompartir(u)}>
								<span class="icono-grantee">
									{#await avatarDeUsuario(u.userId, u.hasAvatar) then url}
										{#if url}<img class="avatar-grantee" src={url} alt="" />{:else}👤{/if}
									{/await}
								</span>
								<span class="label-grantee">{u.displayName} <span class="hint">{u.email}</span></span>
							</button>
						</li>
					{/each}
				</ul>
			{/if}

			{#if errorPermisos}<p class="error">{errorPermisos}</p>{/if}
			{#if hayPendientesCompartir}<p class="hint banner-pendientes">{$t.vault.cambiosPendientes}</p>{/if}

			<div class="botones">
				<Button variant="primary" onclick={guardarCompartir} loading={guardandoCompartir} disabled={!hayPendientesCompartir}>
					{$t.admin.comun.guardar}
				</Button>
				<Button variant="ghost" onclick={cerrarModalCompartir}>{$t.vault.cancelar}</Button>
			</div>
		{/if}
	</Modal>
{/if}

{#if cediendoRecurso}
	<Modal titulo={$t.vault.carpetas.cederTitulo} onCerrar={mantenerPersonal}>
		<p class="hint">{$t.vault.carpetas.cederPregunta(cediendoRecurso.nombre)}</p>
		{#if errorCeder}<p class="error">{errorCeder}</p>{/if}
		<div class="botones-compartir-carpeta">
			<Button type="button" variant="primary" onclick={cederAlGrupo} loading={cediendoEnCurso}>
				{$t.vault.carpetas.cederAlGrupo}
			</Button>
			<Button type="button" variant="ghost" onclick={mantenerPersonal} disabled={cediendoEnCurso}>
				{$t.vault.carpetas.cederMantener}
			</Button>
		</div>
	</Modal>
{/if}

{#if mostrarModalCompartirLote}
	<Modal titulo={$t.vault.compartirLote.boton} subtitulo={$t.vault.conteoSeleccionados(seleccionados.size)} onCerrar={cerrarModalCompartirLote}>
		{#if destinatariosLote.length > 0}
			<ul class="lista-grantees">
				{#each destinatariosLote as d (d.userId)}
					<li class="fila-grantee fila-pendiente">
						<span class="icono-grantee">
							{#await avatarDeUsuario(d.userId, d.hasAvatar) then url}
								{#if url}<img class="avatar-grantee" src={url} alt="" />{:else}👤{/if}
							{/await}
						</span>
						<span class="label-grantee">{d.label}</span>
						<button type="button" class="icono-copiar" onclick={() => quitarDestinatarioLote(d.userId)} aria-label={$t.vault.revocarPermiso}>
							✕
						</button>
					</li>
				{/each}
			</ul>
		{/if}

		<label class="campo-nivel campo-busqueda-compartir">
			{$t.vault.compartirCon}
			<TextField
				label=""
				bind:value={busquedaCompartirLote}
				oninput={alTipearBusquedaLote}
				placeholder={$t.vault.compartirBuscarPlaceholder}
			/>
		</label>
		{#if buscandoCompartirLote}
			<p class="hint">{$t.admin.comun.buscar}…</p>
		{:else if resultadosBusquedaLote.length > 0}
			<ul class="lista-resultados-busqueda">
				{#each resultadosBusquedaLote as u (u.userId)}
					<li>
						<button type="button" class="resultado-busqueda" onclick={() => agregarDestinatarioLote(u)}>
							<span class="icono-grantee">
								{#await avatarDeUsuario(u.userId, u.hasAvatar) then url}
									{#if url}<img class="avatar-grantee" src={url} alt="" />{:else}👤{/if}
								{/await}
							</span>
							<span class="label-grantee">{u.displayName} <span class="hint">{u.email}</span></span>
						</button>
					</li>
				{/each}
			</ul>
		{/if}

		<label class="campo-nivel">
			{$t.vault.carpetas.nivel}
			<select bind:value={nivelCompartirLote}>
				<option value="read">{$t.vault.carpetas.nivelRead}</option>
				<option value="update">{$t.vault.carpetas.nivelUpdate}</option>
				<option value="owner">{$t.vault.carpetas.nivelOwner}</option>
			</select>
		</label>

		{#if errorMasivo}<p class="error">{errorMasivo}</p>{/if}
		{#if resumenCompartirLote}<p class="hint">{resumenCompartirLote}</p>{/if}
		{#if erroresCompartirLote.length > 0}
			<ul class="lista-errores-lote">
				{#each erroresCompartirLote as e (e.label)}
					<li><strong>{e.label}:</strong> {e.error}</li>
				{/each}
			</ul>
		{/if}

		<div class="botones">
			<Button variant="primary" onclick={compartirSeleccionEnLote} loading={aplicandoMasivo} disabled={destinatariosLote.length === 0}>
				{$t.vault.compartirLote.confirmar}
			</Button>
			<Button variant="ghost" onclick={cerrarModalCompartirLote}>{$t.vault.cancelar}</Button>
		</div>
	</Modal>
{/if}

{#if mostrarCrear}
	<Modal titulo={$t.vault.nuevoRecurso} onCerrar={() => (mostrarCrear = false)}>
		<form onsubmit={crear} class="crear">
			<label class="campo-tipo">
				{$t.vault.tipo}
				<select bind:value={tipoNuevo}>
					<option value="login-password">{$t.vault.tipoLoginPassword}</option>
					<option value="ftp">{$t.vault.tipoFtp}</option>
					<option value="ssh">{$t.vault.tipoSsh}</option>
					<option value="vnc">{$t.vault.tipoVnc}</option>
					<option value="telnet">{$t.vault.tipoTelnet}</option>
				</select>
			</label>
			<TextField label={$t.vault.nombre} bind:value={nombre} required />
			<TextField label={$t.vault.usuario} bind:value={usuario} />
			<TextField label={tipoNuevo === 'login-password' ? $t.vault.uri : $t.vault.uriHostPuerto} bind:value={uri} />
			<div class="con-generar">
				<TextField label={$t.vault.password} type="password" bind:value={password} required />
				<Button type="button" variant="ghost" onclick={generar}>{$t.vault.generarPassword}</Button>
			</div>
			<TextField label={$t.vault.notas} bind:value={notas} />
			{#if tipoNuevo === 'login-password'}
				<TextField label={$t.vault.totpOpcional} bind:value={totpSecretBase32} />
			{/if}
			{#if errorCrear}<p class="error">{errorCrear}</p>{/if}
			<div class="botones">
				<Button type="submit" variant="primary" loading={creando}>{$t.vault.crear}</Button>
				<Button type="button" variant="ghost" onclick={() => (mostrarCrear = false)}>{$t.vault.cancelar}</Button>
			</div>
		</form>
	</Modal>
{/if}

{#if mostrarExportar}
	<Modal titulo={$t.exportImport.titulo} onCerrar={() => (mostrarExportar = false)}>
		{#if cargandoPolitica}
			<p class="hint">{$t.exportImport.cargandoPolitica}</p>
		{:else if !puedeExportar && !puedeImportar}
			<p class="hint">{$t.exportImport.sinFormatosHabilitados}</p>
		{:else}
			{#if politica && !politica.export_enabled && excepcionAdmin}
				<p class="hint">{$t.exportImport.viaExcepcionAdmin}</p>
			{/if}

			{#if puedeExportar}
				<section class="seccion-modal">
					<h3>{$t.exportImport.exportarTitulo}</h3>
					<p class="hint">{$t.exportImport.exportarHint}</p>
					<form onsubmit={hacerExport}>
						<div class="field">
							<label for="alcance-export">{$t.exportImport.alcance}</label>
							<select id="alcance-export" bind:value={alcanceExport}>
								<option value="todos">{$t.exportImport.alcanceTodos(recursosFiltrados.length)}</option>
								<option value="seleccionados" disabled={seleccionados.size === 0}>
									{$t.exportImport.alcanceSeleccionados(seleccionados.size)}
								</option>
							</select>
						</div>
						<div class="field">
							<label for="formato-export">{$t.exportImport.formato}</label>
							<select id="formato-export" bind:value={formatoExport}>
								{#each formatosDisponibles as f (f)}
									<option value={f}>{f.toUpperCase()}</option>
								{/each}
							</select>
						</div>
						{#if formatoExport === 'kdbx'}
							<TextField
								label={$t.exportImport.passwordArchivo}
								type="password"
								bind:value={passwordExport}
								hint={$t.exportImport.passwordArchivoHint}
								required
							/>
							{#if passwordExport}
								<p class="fortaleza fortaleza-{fortalezaExport.score}">{labelFortalezaExport}</p>
							{/if}
						{/if}
						{#if errorExport}<p class="error">{errorExport}</p>{/if}
						{#if okExport !== undefined}<p class="ok">{$t.exportImport.exportadoOk(okExport)}</p>{/if}
						<Button type="submit" variant="primary" loading={exportando}>{$t.exportImport.exportar}</Button>
					</form>
				</section>
			{/if}

			{#if puedeImportar}
				<section class="seccion-modal" class:con-separador={puedeExportar}>
					<h3>{$t.exportImport.importarTitulo}</h3>
					<p class="hint">{$t.exportImport.importarHint}</p>
					<div class="field">
						<label for="archivo-import">{$t.exportImport.archivo}</label>
						<input id="archivo-import" type="file" accept=".kdbx,.csv,.json" onchange={alElegirArchivo} />
					</div>
					{#if archivoImport && detectarFormatoPorNombre(archivoImport.name) === 'kdbx'}
						<TextField label={$t.exportImport.passwordArchivoImport} type="password" bind:value={passwordImport} />
					{/if}
					{#if errorImport}<p class="error">{errorImport}</p>{/if}
					{#if !filasPreview}
						<Button variant="secondary" onclick={previsualizar} disabled={!archivoImport} loading={previsualizando}>
							{$t.exportImport.previsualizar}
						</Button>
					{:else}
						<p class="hint">{$t.exportImport.previewConteo(filasPreview.length)}</p>
						<Button variant="primary" onclick={confirmarImport} loading={importando}>
							{$t.exportImport.confirmarImportar}
						</Button>
					{/if}
					{#if okImport !== undefined}<p class="ok">{$t.exportImport.importadoOk(okImport)}</p>{/if}
				</section>
			{/if}
		{/if}
	</Modal>
{/if}

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.vault-layout {
		display: grid;
		grid-template-columns: 14rem 1fr;
		gap: var(--space-4);
		align-items: start;
	}
	.vault-layout.con-panel {
		grid-template-columns: 14rem 1fr 22rem;
	}
	.cabecera {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: var(--space-4);
	}
	.conteo {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0;
	}
	.ver-todo {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
	form.crear {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.campo-tipo {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
		margin-bottom: var(--space-4);
	}
	.campo-tipo select {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-weight: normal;
	}
	.con-generar {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.con-generar :global(.field) {
		flex: 1;
		margin-bottom: 0;
	}
	.botones {
		display: flex;
		gap: var(--space-2);
	}
	:global(.secundario) {
		color: var(--text-muted);
	}
	.panel {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.panel form {
		display: flex;
		flex-direction: column;
		gap: 0;
	}
	.panel-cabecera {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.panel-cabecera h2 {
		margin: 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
		word-break: break-word;
	}
	.cerrar {
		background: none;
		border: none;
		color: var(--text-muted);
		font-size: var(--text-xl);
		line-height: 1;
		cursor: pointer;
		flex-shrink: 0;
	}
	.cerrar:hover {
		color: var(--text-primary);
	}
	.campos {
		margin: 0;
		font-size: var(--text-sm);
	}
	.campos dt {
		color: var(--text-muted);
		margin-top: var(--space-2);
	}
	.campos dd {
		margin: 0;
		color: var(--text-primary);
		word-break: break-word;
	}
	/* Estilo inspirado en Termius (referencia del usuario, 2026-08-11): un
	 * header propio para protocolo+puerto en vez de perderse como una fila
	 * más del dl, y el comando en un bloque tipo terminal con su propio
	 * botón de copiar en vez de un ícono chico. */
	.conexion-header {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
		padding-bottom: var(--space-2);
		margin-bottom: var(--space-2);
		border-bottom: 1px solid var(--border-color);
	}
	.conexion-protocolo {
		font-size: var(--text-lg);
		font-weight: 700;
		color: var(--text-primary);
		letter-spacing: 0.02em;
	}
	.conexion-puerto {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: 999px;
		padding: 0.1rem var(--space-2);
	}
	.conexion-comando {
		margin-top: var(--space-4);
	}
	.conexion-comando-label {
		display: block;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
		margin-bottom: var(--space-1);
	}
	.conexion-comando-linea {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		background: var(--bg-base);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.conexion-comando-linea code {
		flex: 1;
		font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
		font-size: var(--text-sm);
		color: var(--accent-primary);
		word-break: break-all;
	}
	.campo-carpeta {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-muted);
		margin: var(--space-3) 0;
	}
	.campo-carpeta select {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	.form-compartir-carpeta {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin-top: var(--space-3);
		padding-top: var(--space-3);
		border-top: 1px solid var(--border-color);
	}
	.campo-nivel {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-muted);
	}
	.campo-nivel select {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-family: inherit;
	}
	.botones-compartir-carpeta {
		display: flex;
		gap: var(--space-2);
	}
	.icono-copiar {
		background: none;
		border: none;
		cursor: pointer;
		font-size: var(--text-sm);
		line-height: 1;
		padding: 0 0 0 var(--space-1);
		color: var(--text-secondary);
		vertical-align: middle;
	}
	.icono-copiar:hover {
		color: var(--text-primary);
	}
	.lista-grantees {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.fila-grantee {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: 10px;
		padding: var(--space-2) var(--space-3);
		transition: border-color 0.12s ease;
	}
	.icono-grantee {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		flex-shrink: 0;
		border-radius: 50%;
		background: color-mix(in srgb, var(--accent-primary) 18%, var(--bg-base));
		font-size: var(--text-base);
		overflow: hidden;
	}
	.checkbox-seleccion {
		width: 1.15rem;
		height: 1.15rem;
		cursor: pointer;
		accent-color: var(--accent-primary);
	}
	.lista-errores-lote {
		list-style: none;
		margin: var(--space-2) 0 0 0;
		padding: 0;
		font-size: var(--text-sm);
		color: var(--danger);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.avatar-grantee {
		width: 100%;
		height: 100%;
		border-radius: 50%;
		object-fit: cover;
	}
	.label-grantee {
		flex: 1;
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 500;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.fila-grantee select {
		background: var(--bg-base);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1) var(--space-2);
		color: var(--text-primary);
		font-size: var(--text-sm);
		cursor: pointer;
	}
	/* Fila con un cambio sin guardar todavía — mismo criterio visual que la
	   referencia de Passbolt (fondo ámbar), para que "esto todavía no se
	   aplicó" sea obvio de un vistazo. */
	.fila-pendiente {
		background: color-mix(in srgb, var(--warning) 18%, var(--bg-overlay));
		border-color: color-mix(in srgb, var(--warning) 40%, var(--border-color));
	}
	.fila-quitar .label-grantee {
		text-decoration: line-through;
		color: var(--text-muted);
	}
	.campo-busqueda-compartir {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 600;
		margin-top: var(--space-2);
	}
	.lista-resultados-busqueda {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		overflow: hidden;
	}
	.resultado-busqueda {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		background: var(--bg-overlay);
		border: none;
		border-bottom: 1px solid var(--border-color);
		padding: var(--space-2) var(--space-3);
		cursor: pointer;
		text-align: left;
		font: inherit;
	}
	li:last-child .resultado-busqueda {
		border-bottom: none;
	}
	.resultado-busqueda:hover {
		background: var(--bg-raised);
	}
	.banner-pendientes {
		background: color-mix(in srgb, var(--warning) 15%, transparent);
		border: 1px solid color-mix(in srgb, var(--warning) 40%, var(--border-color));
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.panel-acciones {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-3);
	}
	.notas {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		white-space: pre-wrap;
	}
	h3 {
		margin: 0 0 var(--space-1) 0;
		font-size: var(--text-base);
		color: var(--text-primary);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-4);
	}
	.field label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.field select,
	.field input[type='file'] {
		width: 100%;
		background: var(--bg-raised);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-size: var(--text-sm);
		cursor: pointer;
		transition:
			border-color 0.12s ease,
			box-shadow 0.12s ease;
	}
	.field select:hover,
	.field input[type='file']:hover {
		border-color: var(--accent-primary);
	}
	.field select:focus-visible,
	.field input[type='file']:focus-visible {
		outline: none;
		border-color: var(--accent-primary);
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-primary) 25%, transparent);
	}
	/* Título + descripción + control agrupados con espacio ajustado entre
	   sí — sólo el espacio ENTRE secciones (Exportar vs. Importar) usa el
	   gap más generoso de `.contenido` en Modal.svelte. Antes cada línea
	   (h3, hint, form) competía por el mismo espaciado que las secciones
	   completas, así que todo se veía igual de apretado en vez de agrupado. */
	.seccion-modal {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.seccion-modal.con-separador {
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-4);
	}
	.seccion-modal h3 {
		margin: 0;
	}
	.fortaleza {
		font-size: var(--text-xs);
		margin: calc(-1 * var(--space-3)) 0 var(--space-4) 0;
	}
	.fortaleza-0,
	.fortaleza-1 {
		color: var(--danger);
	}
	.fortaleza-2 {
		color: var(--warning);
	}
	.fortaleza-3,
	.fortaleza-4 {
		color: var(--success);
	}
	.barra-seleccion {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		margin-bottom: var(--space-2);
	}
	.barra-seleccion .link {
		background: none;
		border: none;
		padding: 0;
		font-size: var(--text-xs);
		color: var(--accent-primary);
		cursor: pointer;
	}
	.acciones-masivas {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-3);
		flex-wrap: wrap;
	}
	.acciones-masivas select {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
</style>
