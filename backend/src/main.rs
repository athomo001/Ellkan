// Autor: Athan Espinoza

use std::net::SocketAddr;
use std::time::Duration;

use ellkan_backend::config::Config;

/// Cuánto se espera a las solicitudes en curso al apagar (QA-44).
const PLAZO_APAGADO: Duration = Duration::from_secs(20);

/// SIGTERM (lo que manda `docker stop` y systemd) o Ctrl+C.
async fn senal_de_apagado() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let sigterm = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut senal) => {
                senal.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "no se pudo escuchar SIGTERM; sólo Ctrl+C apaga en orden");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm => {}
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::desde_entorno()?;
    let proveedor_otel = ellkan_backend::observabilidad::inicializar_tracing(cfg.otel_endpoint.as_deref());

    let mut estado = ellkan_backend::construir_estado(&cfg.database_url, cfg.secrets_key).await?;
    ellkan_backend::asegurar_token_de_instalacion(&mut estado).await?;
    let app = ellkan_backend::construir_router(estado);

    let addr: SocketAddr = cfg.bind_addr.parse()?;

    // Operativa 1 (spec/11): si hay cert/key configurados, Axum termina TLS
    // él mismo vía `axum-server`+`rustls` — alternativa a levantar un
    // reverse proxy sólo para eso. Sin ellos (default), HTTP plano, mismo
    // comportamiento de siempre.
    //
    // QA-44: apagado ordenado. Con SIGTERM (`docker stop`) o Ctrl+C se deja
    // de aceptar conexiones y se terminan las solicitudes en curso; las que
    // no terminan solas (los avisos SSE duran minutos) se cortan a los
    // `PLAZO_APAGADO`, antes de que Docker mate el proceso (compose da 30 s,
    // `stop_grace_period`).
    let (avisar, aviso) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        senal_de_apagado().await;
        tracing::info!("señal de apagado: termino las solicitudes en curso (hasta {} s)", PLAZO_APAGADO.as_secs());
        let _ = avisar.send(true);
    });

    match (&cfg.tls_cert_path, &cfg.tls_key_path) {
        (Some(cert), Some(key)) => {
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            tracing::info!("ellkan-backend escuchando en {} (TLS terminado in-process)", addr);
            let handle = axum_server::Handle::new();
            let para_apagar = handle.clone();
            let mut aviso_tls = aviso.clone();
            tokio::spawn(async move {
                let _ = aviso_tls.wait_for(|apagar| *apagar).await;
                para_apagar.graceful_shutdown(Some(PLAZO_APAGADO));
            });
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
            tracing::info!("ellkan-backend escuchando en {} (HTTP plano)", cfg.bind_addr);
            let mut aviso_servidor = aviso.clone();
            let servidor =
                axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(async move {
                    let _ = aviso_servidor.wait_for(|apagar| *apagar).await;
                });
            let mut aviso_plazo = aviso.clone();
            tokio::select! {
                resultado = servidor => resultado?,
                _ = async move {
                    let _ = aviso_plazo.wait_for(|apagar| *apagar).await;
                    tokio::time::sleep(PLAZO_APAGADO).await;
                } => tracing::warn!("venció el plazo de apagado: se cortan las conexiones que quedaban abiertas"),
            }
        }
    }

    // Vacía el buffer de spans pendientes antes de salir — si el `SdkTracerProvider`
    // se dropea sin esto, se pierden los últimos spans exportados en batch.
    if let Some(proveedor) = proveedor_otel {
        let _ = proveedor.shutdown();
    }

    Ok(())
}
