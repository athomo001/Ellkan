// Autor: Athan Espinoza

// Entry point del service worker — sólo cablea `BrowserApi.onConnect` a
// `Pagemod` (spec 06 §2). Nada de lógica de negocio acá.

import { BrowserApi } from '../browser-api';
import { attachPagemod } from './pagemod';

BrowserApi.onConnect((port) => attachPagemod(port));
