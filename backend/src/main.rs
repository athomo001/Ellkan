// Autor: Athan Espinoza

use std::net::SocketAddr;

use ellkan_backend::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::desde_entorno()?;
    let proveedor_otel = ellkan_backend::observabilidad::inicializar_tracing(cfg.otel_endpoint.as_deref());

    let estado = ellkan_backend::construir_estado(&cfg.database_url, cfg.secrets_key).await?;
    let app = ellkan_backend::construir_router(estado);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!("ellkan-backend escuchando en {}", cfg.bind_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    // Vacía el buffer de spans pendientes antes de salir — si el `SdkTracerProvider`
    // se dropea sin esto, se pierden los últimos spans exportados en batch.
    if let Some(proveedor) = proveedor_otel {
        let _ = proveedor.shutdown();
    }

    Ok(())
}
