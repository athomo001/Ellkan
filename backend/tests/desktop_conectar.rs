// Autor: Athan Espinoza

//! "Conectar" (F-49): el plan de cada tipo de recurso. `host` y `usuario`
//! pueden venir de un import externo, así que se validan antes de armar nada.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::conectar::{planificar, puerto_por_defecto, validar_host, validar_usuario, Inyeccion, Ventana};

#[test]
fn ssh_entrega_la_clave_por_askpass_y_nunca_en_los_argumentos() {
    let plan = planificar("ssh", Some("root"), "srv.local", 2222).unwrap();
    assert_eq!(plan.programas, vec!["ssh.exe"]);
    assert_eq!(plan.args, vec!["root@srv.local", "-p", "2222"]);
    assert_eq!(plan.inyeccion, Inyeccion::Askpass);
    assert_eq!(plan.ventana, Ventana::Terminal);
}

#[test]
fn ssh_sin_usuario_usa_solo_el_host() {
    let plan = planificar("ssh", None, "srv.local", 22).unwrap();
    assert_eq!(plan.args, vec!["srv.local", "-p", "22"]);
    let plan = planificar("ssh", Some(""), "srv.local", 22).unwrap();
    assert_eq!(plan.args[0], "srv.local", "un usuario vacío es 'sin usuario'");
}

#[test]
fn un_host_que_parece_una_opcion_se_rechaza_no_se_ejecuta() {
    // `ssh -oProxyCommand=calc` ejecutaría un comando: un host nunca puede empezar con `-`.
    for malo in ["-oProxyCommand=calc", "-p", "--help", "-", ""] {
        assert!(validar_host(malo).is_err(), "{malo:?} no debería ser un host válido");
        assert!(planificar("ssh", None, malo, 22).is_err());
        assert!(planificar("postgresql", Some("u"), malo, 5432).is_err());
    }
}

#[test]
fn un_host_con_caracteres_de_shell_o_espacios_se_rechaza() {
    for malo in ["a b", "host;calc", "host&calc", "host|x", "host`x`", "host$(x)", "host\"x", "host\nx", "ho st", "host/x", "host\\x", "host'x"] {
        assert!(validar_host(malo).is_err(), "{malo:?}");
    }
}

#[test]
fn los_hosts_normales_se_aceptan() {
    for bueno in ["srv.local", "192.168.1.10", "mi-servidor_1", "db.example.com", "[::1]", "::1", "fe80::1%eth0", "localhost"] {
        assert!(validar_host(bueno).is_ok(), "{bueno:?}");
    }
    assert!(validar_host(&"a".repeat(253)).is_ok());
    assert!(validar_host(&"a".repeat(254)).is_err());
}

#[test]
fn un_usuario_raro_se_rechaza() {
    for malo in ["-oProxyCommand=x", "us\nuario", "us\"uario", "us'uario", "a\tb"] {
        assert!(validar_usuario(malo).is_err(), "{malo:?}");
        assert!(planificar("ssh", Some(malo), "srv", 22).is_err());
    }
    assert!(validar_usuario("ana.perez@empresa").is_ok());
    assert!(validar_usuario("DOMINIO\\ana").is_ok());
}

#[test]
fn rdp_usa_la_credencial_de_windows_y_no_la_linea_de_comandos() {
    let plan = planificar("rdp", Some("Administrador"), "10.0.0.5", 3390).unwrap();
    assert_eq!(plan.programas, vec!["mstsc.exe"]);
    assert_eq!(plan.args, vec!["/v:10.0.0.5:3390"]);
    assert_eq!(plan.inyeccion, Inyeccion::CredencialRdp);
    assert_eq!(plan.ventana, Ventana::Propia);
    assert!(plan.args.iter().all(|a| !a.to_lowercase().contains("pass")), "ningún argumento lleva la contraseña");
}

#[test]
fn postgresql_pasa_la_clave_por_variable_de_entorno_del_hijo() {
    let plan = planificar("postgresql", Some("postgres"), "db.local", 5433).unwrap();
    assert_eq!(plan.programas, vec!["psql.exe"]);
    assert_eq!(plan.args, vec!["-h", "db.local", "-p", "5433", "-U", "postgres"]);
    assert_eq!(plan.inyeccion, Inyeccion::Entorno("PGPASSWORD"));
    assert_eq!(planificar("postgresql", None, "db.local", 5432).unwrap().args, vec!["-h", "db.local", "-p", "5432"]);
}

#[test]
fn mysql_pasa_la_clave_por_variable_de_entorno_y_acepta_mariadb() {
    let plan = planificar("mysql", Some("root"), "db.local", 3307).unwrap();
    assert_eq!(plan.programas, vec!["mysql.exe", "mariadb.exe"]);
    assert_eq!(plan.args, vec!["-h", "db.local", "-P", "3307", "-u", "root"]);
    assert_eq!(plan.inyeccion, Inyeccion::Entorno("MYSQL_PWD"));
}

#[test]
fn mongodb_no_pone_la_clave_en_la_uri_ni_en_los_argumentos() {
    let plan = planificar("mongodb", Some("ana@corp"), "mongo.local", 27018).unwrap();
    assert_eq!(plan.programas, vec!["mongosh.exe"]);
    assert_eq!(plan.args, vec!["mongodb://ana%40corp@mongo.local:27018/"], "el usuario va codificado y sin contraseña");
    assert_eq!(plan.inyeccion, Inyeccion::Portapapeles, "mongosh la pide, el frontend la deja en el portapapeles");
    assert_eq!(planificar("mongodb", None, "mongo.local", 27017).unwrap().args, vec!["mongodb://mongo.local:27017/"]);
}

#[test]
fn ftp_telnet_y_vnc_se_mantienen_como_antes() {
    assert_eq!(planificar("ftp", None, "ftp.local", 21).unwrap().args, vec!["ftp.local"]);
    assert!(planificar("ftp", None, "ftp.local", 2121).unwrap().args.is_empty(), "ftp.exe no acepta puerto por argumento");
    assert_eq!(planificar("telnet", None, "t.local", 23).unwrap().args, vec!["t.local", "23"]);
    let vnc = planificar("vnc", None, "v.local", 5901).unwrap();
    assert_eq!(vnc.args, vec!["v.local::5901"]);
    assert_eq!(vnc.programas, vec!["vncviewer.exe", "tvnviewer.exe"]);
    for tipo in ["ftp", "telnet", "vnc"] {
        assert_eq!(planificar(tipo, None, "h.local", 1).unwrap().inyeccion, Inyeccion::Portapapeles, "{tipo}: sin forma de recibirla");
    }
}

#[test]
fn un_tipo_desconocido_se_rechaza_con_un_mensaje_claro() {
    let err = planificar("secure_note", None, "h.local", 1).unwrap_err();
    assert!(err.contains("secure_note"), "{err}");
}

#[test]
fn los_puertos_por_defecto() {
    for (tipo, puerto) in [("ssh", 22), ("ftp", 21), ("telnet", 23), ("vnc", 5900), ("rdp", 3389), ("postgresql", 5432), ("mysql", 3306), ("mongodb", 27017)] {
        assert_eq!(puerto_por_defecto(tipo), Some(puerto), "{tipo}");
    }
    assert_eq!(puerto_por_defecto("login-password"), None);
}
