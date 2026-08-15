// Autor: Athan Espinoza

// Fuente única de las secciones del panel admin, agrupadas por categoría —
// antes `+layout.svelte` (nav) y `+page.svelte` (landing) duplicaban el
// mismo array plano de 18 entradas por separado (comentario viejo en
// `+page.svelte` lo admitía), con el riesgo real de que una sección nueva se
// agregara en un solo lugar y no en el otro. Ahora los dos importan esto.

import type { Diccionario } from '$lib/i18n/es';

export interface Seccion {
	href: string;
	label: (t: Diccionario) => string;
}

export interface Categoria {
	titulo: (t: Diccionario) => string;
	items: Seccion[];
}

export const categorias: Categoria[] = [
	{
		titulo: (t) => t.admin.categorias.usuariosYGrupos,
		items: [
			{ href: '/admin/users', label: (t) => t.admin.nav.usuarios },
			{ href: '/admin/roles', label: (t) => t.admin.nav.roles },
			{ href: '/admin/groups', label: (t) => t.admin.nav.grupos }
		]
	},
	{
		titulo: (t) => t.admin.categorias.seguridad,
		items: [
			{ href: '/admin/policies/mfa', label: (t) => t.admin.nav.politicaMfa },
			{ href: '/admin/policies/password', label: (t) => t.admin.nav.politicaPassword },
			{ href: '/admin/policies/account-recovery', label: (t) => t.admin.nav.politicaRecovery },
			{ href: '/admin/policies/self-registration', label: (t) => t.admin.nav.politicaSelfRegistration },
			{ href: '/admin/policies/emergency-access', label: (t) => t.admin.nav.politicaEmergencia },
			{ href: '/admin/policies/device-approval', label: (t) => t.admin.nav.politicaDispositivo },
			{ href: '/admin/policies/retention', label: (t) => t.admin.nav.politicaRetencion }
		]
	},
	{
		titulo: (t) => t.admin.categorias.datosYComparticion,
		items: [
			{ href: '/admin/policies/export', label: (t) => t.admin.nav.politicaExport },
			{ href: '/admin/policies/external-share', label: (t) => t.admin.nav.politicaExternalShare },
			{ href: '/admin/metadata-keys', label: (t) => t.admin.nav.metadataKeys }
		]
	},
	{
		titulo: (t) => t.admin.categorias.integraciones,
		items: [
			{ href: '/admin/smtp', label: (t) => t.admin.nav.smtp },
			{ href: '/admin/sso', label: (t) => t.admin.nav.sso },
			{ href: '/admin/scim', label: (t) => t.admin.nav.scim },
			{ href: '/admin/directory-sync', label: (t) => t.admin.nav.directorySync }
		]
	},
	{
		titulo: (t) => t.admin.categorias.supervision,
		items: [
			{ href: '/admin/audit-log', label: (t) => t.admin.nav.auditoria },
			{ href: '/admin/reports', label: (t) => t.admin.nav.reportes },
			{ href: '/admin/system-status', label: (t) => t.admin.nav.estadoSistema }
		]
	}
];
