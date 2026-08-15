// Autor: Athan Espinoza

//! Benchmark de regresión de performance (F-32): compara la primera lectura
//! de un recurso (apertura asimétrica de la DEK sellada) contra las lecturas
//! siguientes una vez que la DEK ya está en `CacheDeSessionKeys` (descifrado
//! simétrico AEAD directo).

use criterion::{criterion_group, criterion_main, Criterion};
use secrecy::SecretBox;

use ellkan_crypto::aead::{cifrar, descifrar};
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::sellado::{abrir_dek, sellar_dek};
use ellkan_crypto::sesion::CacheDeSessionKeys;

const AAD: &[u8] = b"resource_id:bench|user_id:bench";
const CONTENIDO: &[u8] = b"contenido de secreto de prueba para el benchmark";

fn primera_lectura_asimetrica(c: &mut Criterion) {
    let destinatario = KeypairAcuerdo::generar();
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let envoltura = cifrar(&dek, CONTENIDO, AAD).unwrap();
    let sellado = sellar_dek(destinatario.publica(), &dek);

    c.bench_function("primera_lectura_asimetrica_abrir_dek_mas_descifrar", |b| {
        b.iter(|| {
            let dek_abierta = abrir_dek(destinatario.privada(), &sellado).unwrap();
            descifrar(&dek_abierta, &envoltura, AAD).unwrap()
        })
    });
}

fn lectura_cacheada_simetrica(c: &mut Criterion) {
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let envoltura = cifrar(&dek, CONTENIDO, AAD).unwrap();

    let mut cache = CacheDeSessionKeys::nueva();
    cache.insertar("recurso-bench", dek);

    c.bench_function("lectura_cacheada_solo_aead_descifrar", |b| {
        b.iter(|| {
            let dek_cacheada = cache.obtener("recurso-bench").unwrap();
            descifrar(dek_cacheada, &envoltura, AAD).unwrap()
        })
    });
}

criterion_group!(benches, primera_lectura_asimetrica, lectura_cacheada_simetrica);
criterion_main!(benches);
