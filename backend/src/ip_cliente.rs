// Autor: Athan Espinoza

//! QA-26: IP real del cliente detrás de un reverse proxy.
//!
//! Todos los límites sin sesión (el general de `rate_limit` y los
//! `GovernorLayer` de recuperación y enlaces externos) se indexan por la IP
//! del peer TCP. Detrás de un proxy esa IP es siempre la del proxy, así que
//! todo el mundo compartía un mismo bucket: un solo abusador bloqueaba a
//! todos. Con `ELLKAN_TRUSTED_PROXIES` (IPs o rangos CIDR separados por coma)
//! este middleware, cuando el peer es uno de esos proxies, toma la IP del
//! cliente de `X-Forwarded-For` y la deja en `ConnectInfo` — todos los
//! límites la usan sin tocarlos uno por uno.
//!
//! `X-Forwarded-For` lo puede escribir cualquiera: sólo se lee si el peer es
//! un proxy confiable, y se recorre de derecha a izquierda saltando los
//! proxies confiables. La primera IP que no lo es, es la del cliente — lo
//! que el cliente haya puesto más a la izquierda no se usa nunca.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

pub const VARIABLE: &str = "ELLKAN_TRUSTED_PROXIES";

#[derive(Clone, Default)]
pub struct ProxiesConfiables(Arc<Vec<IpNet>>);

impl ProxiesConfiables {
    /// Lista separada por comas o espacios; una IP suelta vale como /32 o /128.
    pub fn desde_texto(texto: &str) -> Result<Self, String> {
        let mut redes = Vec::new();
        for parte in texto.split([',', ' ']).map(str::trim).filter(|p| !p.is_empty()) {
            let red = match parte.parse::<IpNet>() {
                Ok(red) => red,
                Err(_) => parte
                    .parse::<IpAddr>()
                    .map(IpNet::from)
                    .map_err(|_| format!("{VARIABLE}: «{parte}» no es una IP ni un rango CIDR"))?,
            };
            redes.push(red);
        }
        Ok(Self(Arc::new(redes)))
    }

    /// Sin la variable (o vacía) no se confía en ningún proxy: se usa la IP
    /// del peer TCP, como antes.
    pub fn desde_entorno() -> Result<Self, String> {
        Self::desde_texto(&std::env::var(VARIABLE).unwrap_or_default())
    }

    pub fn esta_vacia(&self) -> bool {
        self.0.is_empty()
    }

    fn confia(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|red| red.contains(&ip))
    }

    /// `xff`: los valores de `X-Forwarded-For` en orden, unidos por coma.
    pub fn ip_del_cliente(&self, peer: IpAddr, xff: Option<&str>) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.confia(peer) {
            return peer;
        }
        let Some(xff) = xff else {
            return peer;
        };
        let mut cliente = peer;
        for parte in xff.rsplit(',') {
            let parte = parte.trim();
            // Algunos proxies agregan el puerto (`1.2.3.4:5678`, `[::1]:80`).
            let Some(ip) = parte.parse::<IpAddr>().ok().or_else(|| parte.parse::<SocketAddr>().ok().map(|s| s.ip())) else {
                // Una entrada ilegible corta la cadena: no se puede saber
                // quién la puso, se queda con la última IP confiable.
                break;
            };
            cliente = ip.to_canonical();
            if !self.confia(cliente) {
                break;
            }
        }
        cliente
    }
}

/// Middleware externo a todos los límites: reemplaza el `ConnectInfo` del
/// peer por el del cliente real cuando corresponde.
pub async fn reemplazar_peer_por_cliente(State(proxies): State<ProxiesConfiables>, mut req: Request, next: Next) -> Response {
    if !proxies.esta_vacia()
        && let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>().copied()
    {
        let valores: Vec<&str> = req.headers().get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
        let xff = (!valores.is_empty()).then(|| valores.join(","));
        let ip = proxies.ip_del_cliente(addr.ip(), xff.as_deref());
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, addr.port())));
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn sin_proxies_confiables_usa_el_peer_aunque_traiga_cabecera() {
        let p = ProxiesConfiables::default();
        assert_eq!(p.ip_del_cliente(ip("10.0.0.2"), Some("1.2.3.4")), ip("10.0.0.2"));
    }

    #[test]
    fn peer_que_no_es_proxy_no_puede_falsear_su_ip() {
        let p = ProxiesConfiables::desde_texto("10.0.0.0/8").unwrap();
        assert_eq!(p.ip_del_cliente(ip("203.0.113.9"), Some("1.2.3.4")), ip("203.0.113.9"));
    }

    #[test]
    fn detras_de_un_proxy_toma_la_ip_del_cliente() {
        let p = ProxiesConfiables::desde_texto("10.0.0.2").unwrap();
        assert_eq!(p.ip_del_cliente(ip("10.0.0.2"), Some("198.51.100.7")), ip("198.51.100.7"));
    }

    #[test]
    fn lo_que_el_cliente_pone_a_la_izquierda_no_cuenta() {
        // El cliente manda `X-Forwarded-For: 1.1.1.1` y el proxy agrega la real.
        let p = ProxiesConfiables::desde_texto("10.0.0.0/8, 172.16.0.0/12").unwrap();
        assert_eq!(p.ip_del_cliente(ip("10.0.0.2"), Some("1.1.1.1, 198.51.100.7, 172.16.0.5")), ip("198.51.100.7"));
    }

    #[test]
    fn sin_cabecera_o_ilegible_queda_la_ultima_confiable() {
        let p = ProxiesConfiables::desde_texto("10.0.0.2").unwrap();
        assert_eq!(p.ip_del_cliente(ip("10.0.0.2"), None), ip("10.0.0.2"));
        assert_eq!(p.ip_del_cliente(ip("10.0.0.2"), Some("basura")), ip("10.0.0.2"));
    }

    #[test]
    fn acepta_puertos_e_ipv4_mapeada_en_ipv6() {
        let p = ProxiesConfiables::desde_texto("127.0.0.1,::1").unwrap();
        assert_eq!(p.ip_del_cliente(ip("::ffff:127.0.0.1"), Some("198.51.100.7:4321")), ip("198.51.100.7"));
        assert_eq!(p.ip_del_cliente(ip("::1"), Some("[2001:db8::1]:443")), ip("2001:db8::1"));
    }

    #[test]
    fn valores_invalidos_fallan_con_mensaje() {
        assert!(ProxiesConfiables::desde_texto("").unwrap().esta_vacia());
        assert!(ProxiesConfiables::desde_texto("10.0.0.0/33").is_err());
        assert!(ProxiesConfiables::desde_texto("proxy.local").is_err());
    }
}
