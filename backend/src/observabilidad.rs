// Autor: Athan Espinoza

//! Instrumentación OpenTelemetry: **apagada por defecto**, el operador activa
//! su propio colector vía `ELLKAN_OTEL_ENDPOINT`; Ellkan nunca "llama a
//! casa". El `fmt` layer a stdout sigue activo siempre (comportamiento
//! previo, no se pierde al no configurar OTel).
//!
//! Política de redacción: los spans HTTP capturan método, ruta (sin query
//! string), status, latencia y `actor_id` — nunca headers, body ni el texto
//! de las consultas SQL. Se aplica desde el primer middleware instrumentado
//! (`TraceLayer` en `lib.rs`), no se agrega después.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Inicializa `tracing`: siempre con salida a stdout; adicionalmente exporta
/// a un colector OTLP vía HTTP/protobuf si `otel_endpoint` está configurado.
/// Devuelve el `SdkTracerProvider` para que el llamador lo mantenga vivo (y
/// pueda hacer `shutdown()` al terminar) — si se dropea antes, deja de
/// exportar spans en pie.
pub fn inicializar_tracing(otel_endpoint: Option<&str>) -> Option<SdkTracerProvider> {
    let filtro = tracing_subscriber::EnvFilter::from_default_env();
    let capa_stdout = tracing_subscriber::fmt::layer();

    let Some(endpoint) = otel_endpoint else {
        tracing_subscriber::registry().with(filtro).with(capa_stdout).init();
        return None;
    };

    let exportador = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
        .expect("configuración de exportador OTLP válida");

    let proveedor = SdkTracerProvider::builder().with_batch_exporter(exportador).build();
    let tracer = proveedor.tracer("ellkan-backend");
    let capa_otel = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(filtro)
        .with(capa_stdout)
        .with(capa_otel)
        .init();

    Some(proveedor)
}
