<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-57 — Salud de la bóveda: contraseñas débiles / repetidas / viejas /
	// filtradas. Todo se calcula en este equipo: los secretos se descifran acá
	// y nunca se envían a ningún servidor. Lo único que usa internet es la
	// comprobación de filtraciones (HIBP, k-anonymous), que es OPT-IN y sólo
	// corre cuando el usuario aprieta el botón.
	import { onDestroy } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { t } from '$lib/i18n';
	import { clavesDesbloqueadas } from '$lib/state/session';
	import { listarRecursos, verSecreto } from '$lib/crypto/recursos';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { analizar, huellaLocal, type Informe, type ItemSalud } from '$lib/salud/informe';
	import { contarFiltraciones } from '$lib/salud/hibp';

	const CLAVE_UMBRAL = 'ellkan:salud:umbral';
	const CLAVE_HIBP = 'ellkan:salud:hibp';
	const UMBRALES = ['', '90', '180', '365', '730'];

	function leer(clave: string, defecto: string): string {
		try {
			return localStorage.getItem(clave) ?? defecto;
		} catch {
			return defecto;
		}
	}
	function guardar(clave: string, valor: string) {
		try {
			localStorage.setItem(clave, valor);
		} catch {
			/* sin almacenamiento: la preferencia sólo dura esta pantalla */
		}
	}

	// Sin umbral por defecto: no se fuerza la rotación (NIST SP 800-63B).
	let umbral = $state(leer(CLAVE_UMBRAL, ''));
	let filtracionesActivas = $state(leer(CLAVE_HIBP, '0') === '1');

	let fase = $state<'inicial' | 'analizando' | 'listo'>('inicial');
	let progreso = $state({ n: 0, total: 0 });
	let informe = $state<Informe | undefined>();
	let omitidos = $state(0);
	let error = $state<string | undefined>();

	// Las contraseñas en claro no viven en estado reactivo: sólo el tiempo que
	// hace falta (para la comprobación opcional de filtraciones) y se sueltan
	// al salir de la pantalla.
	let items: ItemSalud[] = [];
	onDestroy(() => {
		items = [];
	});

	let comprobando = $state(false);
	let errorFiltraciones = $state<string | undefined>();
	let filtradas = $state<{ item: ItemSalud; veces: number }[] | undefined>();

	async function analizarBoveda() {
		error = undefined;
		filtradas = undefined;
		const claves = $clavesDesbloqueadas;
		if (!claves) {
			error = $t.salud.bloqueada;
			return;
		}
		fase = 'analizando';
		informe = undefined;
		omitidos = 0;
		items = [];
		try {
			const recursos = await listarRecursos(claves);
			progreso = { n: 0, total: recursos.length };
			for (const recurso of recursos) {
				try {
					const secreto = await verSecreto(recurso, claves);
					items.push({ id: recurso.id, nombre: recurso.nombre, usuario: recurso.usuario, password: secreto.password ?? '', actualizadoEn: recurso.updated_at });
				} catch {
					omitidos += 1;
				}
				progreso = { n: progreso.n + 1, total: recursos.length };
			}
			await recalcular();
			fase = 'listo';
		} catch (err) {
			error = err instanceof Error ? err.message : $t.salud.errorGenerico;
			fase = 'inicial';
		}
	}

	async function recalcular() {
		informe = await analizar(items, {
			ahora: new Date(),
			umbralDias: umbral === '' ? null : Number(umbral),
			puntuar: (p) => evaluarFortaleza(p).score,
			huella: huellaLocal
		});
	}

	async function cambiarUmbral() {
		guardar(CLAVE_UMBRAL, umbral);
		if (fase === 'listo') await recalcular();
	}

	function cambiarFiltraciones() {
		guardar(CLAVE_HIBP, filtracionesActivas ? '1' : '0');
		if (!filtracionesActivas) filtradas = undefined;
	}

	async function comprobarFiltraciones() {
		errorFiltraciones = undefined;
		comprobando = true;
		try {
			const conteo = await contarFiltraciones(
				items.map((i) => i.password),
				(url, init) => fetch(url, init)
			);
			filtradas = items
				.map((item) => ({ item, veces: conteo.get(item.password) ?? 0 }))
				.filter((f) => f.veces > 0)
				.sort((a, b) => b.veces - a.veces);
		} catch (err) {
			errorFiltraciones = err instanceof Error ? `${$t.salud.filtracionesError} (${err.message})` : $t.salud.filtracionesError;
		} finally {
			comprobando = false;
		}
	}

	const etiquetaUmbral: Record<string, () => string> = {
		'': () => $t.salud.umbralNinguno,
		'90': () => $t.salud.umbral90,
		'180': () => $t.salud.umbral180,
		'365': () => $t.salud.umbral365,
		'730': () => $t.salud.umbral730
	};
</script>

<svelte:head>
	<title>{$t.salud.titulo} — Ellkan</title>
</svelte:head>

<div class="pila">
	<Card>
		<h1>{$t.salud.titulo}</h1>
		<p class="hint">{$t.salud.hint}</p>

		<label class="campo">
			{$t.salud.umbralEtiqueta}
			<select id="salud-umbral" bind:value={umbral} onchange={cambiarUmbral}>
				{#each UMBRALES as u (u)}
					<option value={u}>{etiquetaUmbral[u]()}</option>
				{/each}
			</select>
		</label>

		<label class="opcion">
			<input id="salud-hibp" type="checkbox" bind:checked={filtracionesActivas} onchange={cambiarFiltraciones} />
			{$t.salud.filtracionesActivar}
		</label>
		<p class="hint">{$t.salud.filtracionesAviso}</p>

		<Button variant="primary" onclick={analizarBoveda} loading={fase === 'analizando'}>{$t.salud.analizar}</Button>
		{#if fase === 'analizando'}
			<p class="hint">{$t.salud.analizando.replace('{{n}}', String(progreso.n)).replace('{{total}}', String(progreso.total))}</p>
		{/if}
		{#if error}<p class="error">{error}</p>{/if}
	</Card>

	{#if informe}
		<Card>
			<p class="ok">{$t.salud.resumen.replace('{{n}}', String(informe.analizados))}</p>
			{#if omitidos > 0}<p class="warning">{$t.salud.omitidos.replace('{{n}}', String(omitidos))}</p>{/if}
		</Card>

		<Card>
			<h2>{$t.salud.debilesTitulo} ({informe.debiles.length})</h2>
			<p class="hint">{$t.salud.debilesHint}</p>
			{#if informe.debiles.length === 0}
				<p class="ok">{$t.salud.sinHallazgos}</p>
			{:else}
				<ul class="hallazgos" id="salud-debiles">
					{#each informe.debiles as d (d.item.id)}
						<li>
							<span>{d.item.nombre} <small>{d.item.usuario}</small></span>
							<a href={`/vault?abrir=${d.item.id}`}>{$t.salud.editar}</a>
						</li>
					{/each}
				</ul>
			{/if}
		</Card>

		<Card>
			<h2>{$t.salud.repetidasTitulo} ({informe.repetidas.length})</h2>
			<p class="hint">{$t.salud.repetidasHint}</p>
			{#if informe.repetidas.length === 0}
				<p class="ok">{$t.salud.sinHallazgos}</p>
			{:else}
				<ul class="hallazgos" id="salud-repetidas">
					{#each informe.repetidas as grupo, i (i)}
						<li class="grupo">
							<strong>{$t.salud.mismaContrasena.replace('{{n}}', String(grupo.length))}</strong>
							<ul>
								{#each grupo as item (item.id)}
									<li>
										<span>{item.nombre} <small>{item.usuario}</small></span>
										<a href={`/vault?abrir=${item.id}`}>{$t.salud.editar}</a>
									</li>
								{/each}
							</ul>
						</li>
					{/each}
				</ul>
			{/if}
		</Card>

		<Card>
			<h2>{$t.salud.viejasTitulo} ({informe.viejas.length})</h2>
			<p class="hint">{$t.salud.viejasHint}</p>
			{#if umbral === ''}
				<p class="hint">{$t.salud.viejasSinUmbral}</p>
			{:else if informe.viejas.length === 0}
				<p class="ok">{$t.salud.sinHallazgos}</p>
			{:else}
				<ul class="hallazgos" id="salud-viejas">
					{#each informe.viejas as v (v.item.id)}
						<li>
							<span>{v.item.nombre} <small>{$t.salud.hace.replace('{{n}}', String(v.dias))}</small></span>
							<a href={`/vault?abrir=${v.item.id}`}>{$t.salud.editar}</a>
						</li>
					{/each}
				</ul>
			{/if}
		</Card>

		{#if filtracionesActivas}
			<Card>
				<h2>{$t.salud.filtradasTitulo}{filtradas ? ` (${filtradas.length})` : ''}</h2>
				<p class="hint">{$t.salud.filtradasHint}</p>
				<Button onclick={comprobarFiltraciones} loading={comprobando}>{$t.salud.filtracionesComprobar}</Button>
				{#if errorFiltraciones}<p class="error">{errorFiltraciones}</p>{/if}
				{#if filtradas}
					{#if filtradas.length === 0}
						<p class="ok">{$t.salud.filtracionesLimpio}</p>
					{:else}
						<ul class="hallazgos" id="salud-filtradas">
							{#each filtradas as f (f.item.id)}
								<li>
									<span>{f.item.nombre} <small>{$t.salud.filtracionesVeces.replace('{{n}}', String(f.veces))}</small></span>
									<a href={`/vault?abrir=${f.item.id}`}>{$t.salud.editar}</a>
								</li>
							{/each}
						</ul>
					{/if}
				{/if}
			</Card>
		{/if}
	{/if}
</div>

<style>
	.pila {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	h1,
	h2 {
		margin: 0 0 var(--space-2) 0;
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-3) 0;
	}
	.campo,
	.opcion {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: var(--space-2) 0;
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.warning {
		color: var(--warning);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.hallazgos {
		list-style: none;
		margin: 0;
		padding: 0;
		font-size: var(--text-sm);
	}
	.hallazgos li {
		display: flex;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-2) 0;
		border-bottom: 1px solid var(--border-color);
	}
	.hallazgos li:last-child {
		border-bottom: none;
	}
	.hallazgos .grupo {
		flex-direction: column;
	}
	.hallazgos .grupo ul {
		list-style: none;
		margin: var(--space-2) 0 0 0;
		padding: 0 0 0 var(--space-4);
	}
	small {
		color: var(--text-secondary);
	}
</style>
