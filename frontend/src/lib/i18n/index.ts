// Autor: Athan Espinoza

// F-31: `t` es un store derivado del idioma elegido (`preferencias.locale`)
// — cambiar el idioma desde `/settings/preferences` actualiza toda la UI de
// inmediato (los componentes que leen `$t` son reactivos a ese store), sin
// logout ni pérdida de sesión, tal como pide el criterio de aceptación.

import { derived } from 'svelte/store';
import { preferencias } from '$lib/state/session';
import es from './es';
import en from './en';
import type { Diccionario } from './es';

const diccionarios: Record<'es' | 'en', Diccionario> = { es, en };

export const t = derived(preferencias, ($preferencias) => diccionarios[$preferencias.locale]);
