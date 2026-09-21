// Autor: Athan Espinoza

// Punto 7 de la lista de pendientes de escritorio: "como dev, poder ver si
// funciona bien el traspaso de datos" en los modos de persistencia. Este
// módulo es la parte PURA — compara lo que hay en el servidor remoto contra
// lo que hay en la bóveda local y dice qué está de más, qué falta y qué no
// coincide para el modo activo. Deliberadamente sin imports (ni `$lib`, ni
// Svelte, ni red): así se puede correr con Node directo
// (`frontend/scripts/check-traspaso.mjs`) sin levantar nada. Las llamadas a
// los dos backends viven en `diagnostico.ts`.
//
// Nunca contiene material secreto: sólo ids y banderas. Los bytes cifrados
// se comparan pero no se copian al informe, así que éste se puede pegar en
// un issue o un chat sin filtrar nada.

export type ModoPersistencia = 'full' | 'memory' | 'names_only';

export interface EnvelopeB64 {
	sealedDekB64: string;
	secretCiphertextB64: string;
	secretNonceB64: string;
}

export interface RecursoRemoto {
	id: string;
	metadataCiphertextB64: string;
	metadataNonceB64: string;
	/** `null` si el servidor no devolvió el envelope (error de red, 403, etc.). */
	secreto: EnvelopeB64 | null;
}

export interface RecursoLocal {
	id: string;
	metadataCiphertextB64: string;
	metadataNonceB64: string;
	/** Envelope completo guardado en `secret_envelopes`, `null` si no hay. */
	secretoLocal: EnvelopeB64 | null;
	/** DEK sellado guardado aparte en `metadata_deks` (modos sin réplica del secreto). */
	dekLocalB64: string | null;
}

export interface EntradaTraspaso {
	modo: ModoPersistencia;
	remotos: RecursoRemoto[];
	locales: RecursoLocal[];
}

export type Severidad = 'error' | 'aviso' | 'info';

export type TipoHallazgo =
	| 'falta_local'
	| 'solo_local'
	| 'metadata_distinta'
	| 'secreto_faltante_en_full'
	| 'secreto_distinto'
	| 'secreto_replicado_en_modo_restringido'
	| 'dek_faltante'
	| 'secreto_remoto_ilegible';

export interface Hallazgo {
	tipo: TipoHallazgo;
	severidad: Severidad;
	id: string;
	detalle: string;
}

export interface InformeTraspaso {
	modo: ModoPersistencia;
	totalRemotos: number;
	totalLocales: number;
	/** Recursos presentes en los dos lados sin ningún hallazgo de ninguna severidad. */
	sinHallazgos: number;
	hallazgos: Hallazgo[];
	errores: number;
	avisos: number;
	infos: number;
	/** `true` si no hay ningún `error` — los avisos/infos no rompen el traspaso. */
	sano: boolean;
}

function mismoEnvelope(a: EnvelopeB64, b: EnvelopeB64): boolean {
	return (
		a.sealedDekB64 === b.sealedDekB64 &&
		a.secretCiphertextB64 === b.secretCiphertextB64 &&
		a.secretNonceB64 === b.secretNonceB64
	);
}

export function compararTraspaso(entrada: EntradaTraspaso): InformeTraspaso {
	const { modo, remotos, locales } = entrada;
	const hallazgos: Hallazgo[] = [];
	const localesPorId = new Map(locales.map((l) => [l.id, l]));
	const remotosPorId = new Map(remotos.map((r) => [r.id, r]));
	const conHallazgo = new Set<string>();

	function agregar(tipo: TipoHallazgo, severidad: Severidad, id: string, detalle: string): void {
		hallazgos.push({ tipo, severidad, id, detalle });
		conHallazgo.add(id);
	}

	for (const remoto of remotos) {
		const local = localesPorId.get(remoto.id);
		if (!local) {
			agregar('falta_local', 'error', remoto.id, 'Está en el servidor pero no en esta bóveda — sincronizá y volvé a verificar.');
			continue;
		}

		if (local.metadataCiphertextB64 !== remoto.metadataCiphertextB64 || local.metadataNonceB64 !== remoto.metadataNonceB64) {
			agregar(
				'metadata_distinta',
				'aviso',
				remoto.id,
				'La metadata difiere entre el servidor y esta bóveda — hay una edición sin sincronizar de algún lado.'
			);
		}

		if (modo === 'full') {
			if (!local.secretoLocal) {
				agregar('secreto_faltante_en_full', 'error', remoto.id, 'En réplica completa el secreto tiene que estar guardado localmente y no lo está.');
			} else if (remoto.secreto && !mismoEnvelope(local.secretoLocal, remoto.secreto)) {
				agregar('secreto_distinto', 'error', remoto.id, 'El secreto guardado localmente no coincide con el del servidor.');
			}
			if (!remoto.secreto) {
				agregar('secreto_remoto_ilegible', 'aviso', remoto.id, 'No se pudo leer el secreto del servidor para compararlo.');
			}
			continue;
		}

		// `memory` / `names_only`: el secreto NO debería estar en disco, pero sí
		// el DEK sellado (para descifrar la metadata offline) y el secreto tiene
		// que poder pedirse al servidor.
		if (local.secretoLocal) {
			agregar(
				'secreto_replicado_en_modo_restringido',
				'info',
				remoto.id,
				'Tiene el secreto guardado localmente: se sincronizó antes de cambiar de modo o se creó en esta PC (el cambio de modo no purga lo ya replicado).'
			);
		} else if (!local.dekLocalB64) {
			agregar('dek_faltante', 'error', remoto.id, 'Sin secreto ni DEK locales: la metadata no se puede descifrar sin conexión.');
		}
		if (!remoto.secreto) {
			agregar('secreto_remoto_ilegible', 'error', remoto.id, 'El secreto no se puede pedir al servidor, así que no se podría ver en este modo.');
		}
	}

	for (const local of locales) {
		if (!remotosPorId.has(local.id)) {
			agregar('solo_local', 'aviso', local.id, 'Está en esta bóveda pero no en el servidor — el envío al servidor está pendiente o falló.');
		}
	}

	const errores = hallazgos.filter((h) => h.severidad === 'error').length;
	const avisos = hallazgos.filter((h) => h.severidad === 'aviso').length;
	const infos = hallazgos.filter((h) => h.severidad === 'info').length;
	const enAmbos = remotos.filter((r) => localesPorId.has(r.id));

	return {
		modo,
		totalRemotos: remotos.length,
		totalLocales: locales.length,
		sinHallazgos: enAmbos.filter((r) => !conHallazgo.has(r.id)).length,
		hallazgos,
		errores,
		avisos,
		infos,
		sano: errores === 0
	};
}
