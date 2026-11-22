// Autor: Athan Espinoza

// Entry point del service worker — sólo cablea `BrowserApi.onConnect` a
// `Pagemod` (spec 06 §2). Nada de lógica de negocio acá.

import { BrowserApi } from '../browser-api';
import { attachPagemod } from './pagemod';
import { LockService } from './services/lock-service';
import { borrarRestosF38 } from './services/restos-f38';

BrowserApi.onConnect((port) => attachPagemod(port));
LockService.instalarListener();
void borrarRestosF38();
