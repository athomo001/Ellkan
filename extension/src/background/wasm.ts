// Autor: Athan Espinoza

// Reusa el mismo `ellkan_crypto.wasm` ya compilado y commiteado para el
// frontend web (spec 06 §1/§9, spec 05 §2.1) — se importa el artefacto
// existente en vez de correr un segundo `wasm-pack build` propio de la
// extensión, para que no puedan divergir dos binarios wasm construidos por
// separado desde el mismo crate. Mismo patrón de carga perezosa que
// `frontend/src/lib/crypto/wasm.ts::cargarCrypto`.
//
// `init()` se llama con una URL explícita (`chrome.runtime.getURL`) en vez
// de dejar que el glue de wasm-bindgen resuelva `import.meta.url` solo:
// bajo el bundle IIFE del service worker (necesario para que sea un script
// autocontenido, spec 06 §1) Rollup no puede preservar `import.meta` y lo
// reemplaza por `{}` — la rama que lo usa (`new URL(..., import.meta.url)`)
// sólo corre si no se pasa un argumento a `init()`, así que pasándolo
// siempre esa rama queda inalcanzable y el warning de build es inofensivo.
// `build.mjs` copia el `.wasm` a `dist/ellkan_crypto_bg.wasm` a propósito
// para que esta URL exista de verdad en el paquete final.
import init, * as ellkanCrypto from '../../../frontend/src/lib/wasm/ellkan_crypto.js';
import { BrowserApi } from '../browser-api';

let listo: Promise<typeof ellkanCrypto> | null = null;

export function cargarCrypto(): Promise<typeof ellkanCrypto> {
	if (!listo) {
		listo = init(BrowserApi.getRuntimeURL('ellkan_crypto_bg.wasm')).then(() => ellkanCrypto);
	}
	return listo;
}
