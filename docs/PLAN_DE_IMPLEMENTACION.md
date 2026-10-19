# Plan de Implementación — Argus Vault

> **Alcance de este documento:** _cómo_ y _cuándo_ se construye Argus Vault: estructura,
> herramientas, fases, tareas, estado y criterios de aceptación. Es la **única fuente de verdad del
> progreso**. Los requisitos, el modelo de amenazas y las especificaciones (_qué_ y _por qué_) están
> en el [PRD](IMPLEMENTATION_PLAN_PRD.md); aquí no se repiten.

**Estado al 2026-10-19:** Fases 1, 2, 3 y 5 **completadas**. La Fase 4 está **implementada a nivel de código**
y compilada: `fmt`, `clippy -D warnings`, build release con LTO/CFG y `cargo deny` pasan; 122 tests
(79 de `argus-core`, 29 de `argus-platform`, 14 de `argus-app`). Pendiente: validación interactiva
en ventana real de los flujos de la Fase 4 con la sesión de Windows desbloqueada.


---

## 1. Estructura del Proyecto

```
Argus Vault/
├── Cargo.toml              # Workspace, lints y perfiles de compilación endurecidos
├── rust-toolchain.toml     # Compilador fijado (1.99.0). Las dependencias las fija Cargo.lock
├── Cargo.lock              # Versiones exactas; todo comando de CI usa --locked
├── deny.toml               # cargo-deny: advisories, licencias, fuentes, crates prohibidos
├── clippy.toml / rustfmt.toml
├── .github/workflows/ci.yml
├── docs/
│   ├── IMPLEMENTATION_PLAN_PRD.md   # Qué y por qué
│   └── PLAN_DE_IMPLEMENTACION.md    # Cómo y estado (este documento)
├── crates/
│   ├── argus-core/         # Criptografía, formato y dominio. #![forbid(unsafe_code)]
│   │   ├── assets/eff_large_wordlist.txt
│   │   └── src/            # lib, error, rng, securebuf, reader, format, kdf, base32, totp,
│   │                       # model, codec, generator, strength, search, fs_util, keyfile,
│   │                       # import, vault, fuzzing
│   ├── argus-platform/     # Win32: portapapeles, anti-captura, inactividad, sesión, diálogos de archivo
│   └── argus-app/          # GUI Slint (main, vault_view, panes, snapshots; ui/main.slint, ui/components.slint)
└── fuzz/                   # cargo-fuzz: parse_file, decode_inner, parse_totp
```

Notas sobre módulos de `argus-core` que el documento anterior describía mal:

- `error.rs`: errores **genéricos y sin secretos** (contraseña incorrecta, keyfile incorrecto y
  archivo manipulado dan el mismo error). No son "de tiempo constante".
- `keyfile.rs`: genera keyfiles de 64 bytes, pero acepta cualquier archivo de 1 B a 16 MiB.
- `vault.rs`: exige una contraseña maestra de al menos 10 caracteres para vaults nuevos.

---

## 2. Reglas de Trabajo

1. **Cada tarea tiene un criterio de aceptación verificable** (un test, un comando o una prueba
   manual descrita). Una casilla solo se marca cuando el criterio se cumple.
2. **El CI debe estar en verde** antes de marcar cualquier tarea. Los comandos se pueden correr en
   local: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
   `cargo test --workspace --locked`.
3. **`unsafe` solo en `argus-platform`**, con un comentario `// SAFETY:` por bloque.
4. **Ninguna dependencia nueva** sin revisar su licencia, su árbol de dependencias y `cargo deny check`.

---

## 3. Fases de Implementación

### Fase 1: Núcleo y Criptografía (`argus-core`) — COMPLETADA

- [x] Workspace, lints estrictos y perfiles de compilación endurecidos (incluye LTO completo).
- [x] CSPRNG del sistema (`BCryptGenRandom` vía `getrandom`) con muestreo por rechazo.
- [x] KDF Argon2id + BLAKE2b con límites mínimo y máximo de parámetros.
- [x] XChaCha20-Poly1305 con la cabecera completa como AAD y nonce nuevo en cada guardado.
- [x] Codec TLV estricto con relleno a 4 KiB.
- [x] Generador de contraseñas y passphrases (lista EFF).
- [x] TOTP (RFC 6238) y Base32.
      30O E
- [x] Escritura atómica con `.bak`.
- [x] **Corregido (2026-10-15):** al cambiar credenciales, el `.bak` quedaba cifrado con la clave
      anterior y seguía abriéndose con la contraseña vieja. Ahora se reemplaza por el vault re-cifrado,
      5NECESARIO
      _Aceptación:_ test `change_credentials_does_not_leave_old_key_backup`.
- [x] **Corregido (2026-10-15):** el CI fallaba en `fmt` y `clippy -D warnings`. Se añadió
      `rustfmt.toml` y se corrigieron los 5 avisos de clippy.
      _Aceptación:_ los tres comandos de la regla 2 pasan.
- [x] Fuzzing con `cargo-fuzz` y pipeline de GitHub Actions.
- [x] **Hecho (2026-10-15):** la contraseña se normaliza a Unicode NFC antes del hash
      (`unicode-normalization` 0.1, sin features por defecto; arrastra solo `tinyvec`).
      _Aceptación:_ tests `password_is_unicode_nfc_normalized` y
      `same_password_in_nfc_and_nfd_opens_the_same_vault`.
- [x] **Hecho (2026-10-15):** política de versionado y migración (v1 → v2) escrita en el PRD §3.1.
      _Aceptación:_ test `future_format_version_is_rejected` (un archivo con versión 2 da `UnsupportedVersion`).
- [x] `cargo deny check licenses bans sources` pasa en local (2026-10-15).
- [ ] `cargo deny check advisories` no se pudo correr en este equipo: falla al descargar la base de
      avisos (`LoadLibraryExW() failed: Access is denied` con `libcurl-4.dll`). Lo ejecuta el CI.

### Fase 2: Prueba de Concepto Vertical (Slint) — COMPLETADA (2026-10-15)

Objetivo: resolver pronto los riesgos de integrar Slint, antes de invertir en pulir la plataforma
o la interfaz. **Decisión de licencia:** GPL-3.0-only (Argus Vault y la opción GPL de Slint);
texto en `LICENSE`, campo `license` en el workspace y `deny.toml` actualizado.

- [x] Licencia decidida y añadida a `deny.toml` (más `0BSD`, `BSL-1.0`, `CC0-1.0` y `Unlicense`,
      que traen dependencias de Slint).
      _Aceptación:_ `cargo deny check licenses bans sources` pasa.
- [x] Slint 1.18 sin features por defecto (`std`, `compat-1-2`, `backend-winit`,
      `renderer-software`): sin OpenGL, Skia ni bandeja del sistema. Árbol medido: **254 crates únicos
      en la app contra 34 en `argus-core`** (Windows, solo ejecución). Ninguna librería de red
      (`tokio`, `hyper`, `reqwest`, `openssl` no aparecen). Sí quedan enlazados `webbrowser` (abre URLs
      en el navegador), `arboard` (portapapeles propio de Slint) y los parsers `image`/`resvg`/`usvg`
      (no se usan, pero están en el binario). Ver Fase 5.
- [x] **Hallazgo:** `argus-app` **no puede usar `#![forbid(unsafe_code)]`**, porque el código que
      genera Slint contiene `unsafe` (macro `ItemTreeVTable_static`). Se usa `#![deny(unsafe_code)]`:
      cualquier `unsafe` en el código escrito a mano sigue siendo un error de compilación. Por eso
      `unsafe_code` salió de los lints del workspace y se fija en cada crate (`forbid` en `argus-core`).
      El código generado vive en un módulo propio con los `allow` mínimos (`unwrap`/`panic` de clippy y
      `missing_debug_implementations`), sin relajar nada en el código propio.
- [x] Pantalla mínima: crear / desbloquear → listar → detalle con revelar → nueva entrada → borrar →
      bloquear, con la KDF en un hilo aparte.
      _Aceptación (probado ejecutando la app y manejando la ventana):_ la ventana responde durante el
      desbloqueo; el archivo creado mide 4195 bytes (83 + 4096 de relleno + 16 de etiqueta) y no contiene
      ningún texto plano; una contraseña incorrecta da el error genérico y vacía el campo; Lock vuelve a
      la pantalla de desbloqueo.
- [x] Reglas de secretos de la UI (PRD §4.1). **Hallazgo:** el tipo `password` de Slint **no
      impide Ctrl+C / Ctrl+X**: copiar el campo de contraseña dejó la contraseña real en el portapapeles.
      Se corrigió interceptando Ctrl+C, Ctrl+X, Ctrl+Insert y Shift+Supr con `capture-key-pressed` en los
      campos secretos.
      _Aceptación (probado):_ con el portapapeles en un valor centinela, esos cuatro atajos sobre la
      contraseña maestra y sobre el texto de una contraseña revelada lo dejan intacto, y el campo sigue
      funcionando con normalidad.
- [x] Botón «copiar contraseña»: movido a la Fase 3 y hecho allí (Slint no tiene API de portapapeles).

### Fase 3: Servicios de Plataforma (`argus-platform`) — COMPLETADA (2026-10-15)

- [x] Crate `argus-platform` (2026-10-15) con el crate `windows` de Microsoft (la misma versión que
      ya trae Slint, sin copia duplicada). Define su propia tabla `[lints]` en lugar de heredar la del
      workspace, porque un crate no puede heredar y añadir: copia el conjunto estricto y añade
      `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks` y
      `clippy::multiple_unsafe_ops_per_block` como error. Hay que mantener ambas tablas sincronizadas.
      _Aceptación:_ `clippy -D warnings` pasa y cada bloque `unsafe` lleva su `// SAFETY:` y una sola operación.
- [x] Portapapeles protegido (`argus_platform::clipboard`) con los formatos
      `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0` y
      `CanUploadToCloudClipboard = 0`.
      _Aceptación (probado en la app real):_ tras pulsar Copy, el portapapeles contiene la contraseña y
      los tres formatos de protección, y si falla a medias se vacía para no dejar una copia sin proteger.
      **No verificado a mano:** que la copia no aparezca en el historial Win+V (la marca está puesta,
      pero no se abrió Win+V para comprobarlo).
- [x] Borrado automático (por defecto 20 s, el valor de la bóveda) solo si el portapapeles sigue
      conteniendo _esa_ copia. Nunca se relee la contraseña.
      **Cambio de diseño:** el plan decía usar `GetClipboardSequenceNumber`, pero medido en este equipo
      el número sube +1 por cada escritura y +3 más al cerrar el portapapeles, así que un valor guardado
      alrededor de la copia no es fiable y, si queda desfasado, el borrado no hace nada sin avisar
      (la contraseña se quedaría). Ahora cada copia lleva un formato propio `ArgusVaultCopyId` con un
      identificador único no secreto, y el borrado comprueba que sigue ahí, con el portapapeles abierto
      para que nadie pueda copiar algo en medio. Contrapartida: otros programas pueden ver que el formato
      existe y deducir que la copia vino de Argus Vault.
      _Aceptación (7 tests de `argus-platform` y probado en la app real):_ a los ~22 s el portapapeles
      queda vacío; si otro programa copió algo después, eso no se borra; al bloquear y al cerrar la
      ventana con una copia pendiente se borra al instante; si el portapapeles está ocupado se reintenta
      a los 2 s.
- [x] Botón «Copy» en la UI, con línea de estado («Copied. Clears in 20 s.»).
      **Limitación:** si el proceso muere de golpe (cierre forzado, apagón), no hay quien borre la copia
      y la contraseña sigue en el portapapeles hasta que el usuario copie otra cosa.
- [x] Anti-captura (`argus_platform::window`): `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` y
      `WDA_MONITOR` como alternativa en Windows anteriores a 10 2004.
      **Hallazgo:** Slint solo crea la ventana nativa cuando arranca el bucle de eventos, no al volver
      `show()`; la primera versión pedía el HWND demasiado pronto, recibía `None` y la app mostraba
      «Screen-capture protection could not be enabled» (el test unitario pasaba, la app real no). Ahora
      un temporizador reintenta cada 50 ms (hasta 5 s) y el fallo se muestra en la pantalla de
      desbloqueo en lugar de ignorarse.
      _Aceptación (probado en la app real):_ `GetWindowDisplayAffinity` devuelve `0x11` y una captura de
      pantalla de la región de la ventana contiene 0 píxeles de la interfaz (antes de corregirlo, 751) y
      muestra lo que hay detrás. **Limitación:** la ventana puede verse unos milisegundos antes de que la
      protección se aplique (solo la pantalla de desbloqueo, nunca contenido de la bóveda).
      **Atajos solo de depuración:** `ARGUS_ALLOW_CAPTURE=1` desactiva la protección y
      `ARGUS_AUTOLOCK_SECS=N` sustituye el tiempo de bloqueo; ambos se ignoran en compilaciones release
      y existen para poder probar la interfaz con capturas de pantalla.
- [x] Bloqueo por inactividad (`argus_platform::idle`, `GetLastInputInfo`) y al minimizar, con
      comprobación cada 250 ms y aviso en la pantalla de desbloqueo («Locked after a period of
      inactivity.», «Locked because the window was minimized.»). **La inactividad se mide en toda la
      sesión de Windows**: trabajar en otro programa cuenta como actividad.
      **Hallazgo grave:** al minimizar, la bóveda se bloqueaba bien, pero **Slint no repintaba la
      ventana al restaurarla** y el último fotograma, con el contenido de la bóveda, seguía a la vista
      hasta que algo forzaba un redibujado (ni mover el ratón ni hacer clic lo arreglaban; maximizar sí).
      `request_redraw` tampoco bastó. Se arregla detectando el paso de minimizada a restaurada y
      cambiando el tamaño de la ventana 1 píxel y devolviéndolo 30 ms después.
      _Aceptación (probado en la app real):_ tras minimizar y restaurar sin tocar nada, aparece la
      pantalla de desbloqueo con el aviso y la ventana recupera su tamaño; tras 12 s sin entrada
      (límite de prueba) se bloquea sola.
- [x] Bloqueo al bloquear la sesión de Windows y al suspender (`argus_platform::session`): una
      ventana propia oculta en un hilo aparte con `WTSRegisterSessionNotification`, porque Slint no da
      acceso a los mensajes crudos de Windows. Bloquear sesión, desconexión remota o de consola y
      suspensión/hibernación bloquean la bóveda; desbloquear la sesión no.
      _Aceptación (6 tests):_ los mensajes `WM_WTSSESSION_CHANGE` y `WM_POWERBROADCAST` se reciben como
      los enviaría Windows y producen los eventos correctos; los demás se ignoran; soltar el vigilante
      detiene su hilo.
      **No verificado de verdad:** nunca se bloqueó la sesión de Windows ni se suspendió el equipo
      durante las pruebas (habría cerrado la sesión del usuario); lo probado es nuestro tratamiento de
      los mensajes y que el registro con Windows no devuelve error. Al suspender, el bloqueo se aplica
      cuando el hilo de la interfaz vuelve a ejecutarse, que puede ser al reanudar.
- [x] Una sola instancia por bóveda (`argus_platform::instance`): mutex con nombre derivado de la
      ruta normalizada (absoluta, carpeta resuelta, sin distinguir mayúsculas), que se toma antes de
      la derivación de clave y se suelta al bloquear.
      _Aceptación (4 tests y probado con dos procesos reales):_ la segunda ventana sobre la misma
      bóveda recibe «This vault is already open in another Argus Vault window.» y puede abrirla en
      cuanto la primera bloquea. **Límites:** el mutex es de la sesión de Windows (`Local\`), así que
      otra ventana en otra sesión (cambio rápido de usuario, escritorio remoto) no se detecta, y
      rutas que Windows resuelve distinto (enlaces duros, unidades de red) pueden no coincidir.
- [x] Volcados de Windows Error Reporting — **decisión:** se llama a `WerSetFlags` con
      `WER_FAULT_REPORTING_FLAG_NOHEAP` al arrancar (`argus_platform::process`), para que un fallo no
      envíe el heap descifrado en el informe. Es una capa, no una garantía: no frena a un depurador, a
      `LocalDumps` en el registro ni a un administrador. **No verificado:** el test solo comprueba que
      Windows acepta la bandera; no se provocó un fallo para comprobar que el volcado excluye el heap.
      Bloquear páginas de memoria (`VirtualLock`) queda descartado por ahora.

### Fase 4: Interfaz Completa (`argus-app`) — IMPLEMENTADA (2026-10-16), PENDIENTE DE PRUEBA MANUAL

Objetivo: dos tipos de credencial (PRD §3.3): **Servidor (RDP)**, donde la acción principal es copiar
la contraseña, y **Sitio web**. Una casilla `[x]` significa que su criterio automático se cumple; lo
que exige manejar la ventana está en «Pendiente de prueba manual».

**Cómo se verificó (y qué no):** compilación, clippy, tests y un renderizado sin ventana
(`crates/argus-app/src/snapshots.rs`: dibuja cada pantalla con el renderizador por software de Slint
a un `.bmp`; se activa con `ARGUS_SNAPSHOT_DIR=<carpeta> cargo test -p argus-app snapshots`). Con él
se revisó el diseño de 11 pantallas, incluido el tamaño mínimo 800×560, y se corrigieron dos fallos
(un aviso que se aplastaba en un panel con scroll y otro que ocupaba toda la columna). **No se
manejó la aplicación real** porque la sesión de Windows estaba bloqueada.

- [x] **`argus-core`: tipo de entrada.** `EntryKind { Web, Server }` y campo `host` en `model.rs` y
      `codec.rs`; `INNER_VERSION` sube a 2 (tags `0x0A` kind y `0x0B` host). Un servidor sin host no se
      guarda. Los vaults v1 se siguen leyendo (todo pasa a «Web») y se regraban como v2 al guardar.
      _Aceptación (tests):_ `both_kinds_roundtrip`, `unknown_entry_kind_is_rejected`,
      `v1_inner_format_still_opens_as_websites`, `server_entry_needs_a_host`,
      `kind_codes_roundtrip_and_unknown_is_rejected`.
- [x] Búsqueda sobre título, host, usuario y URL, y filtro por tipo (`search_kind`).
      _Aceptación:_ `host_is_searched_and_kind_filters`.
- [x] Editor con selector Servidor / Sitio web (crear **y editar**). Campos obligatorios: título,
      servidor o URL, usuario y contraseña; el aviso dice cuál falta. Notas opcionales. Guardar y
      Cancelar están en la cabecera para que no queden fuera de la vista.
      _Aceptación (test):_ `required_fields_are_checked_in_order`.
- [x] Lista con icono por tipo (pantalla para servidor, globo para web), subtítulo `host · usuario`
      y filtros Todos / Servidores / Sitios.
- [x] Servidor: icono de copiar la contraseña en la fila de la lista, sin abrir el detalle; en el
      detalle, copiar servidor, usuario y contraseña con un clic (mismo portapapeles protegido).
- [x] Interfaz en modo oscuro en escala de grises (rojo = advertencia, verde = correcto). Los
      componentes pasaron a `ui/components.slint`.
- [x] Selector de archivos nativo (`argus_platform::dialog`, `GetOpenFileNameW` / `GetSaveFileNameW`,
      sin dependencias nuevas: solo la característica `Win32_UI_Controls_Dialogs` del crate `windows`) para
      la bóveda, el keyfile y los archivos a importar. El diálogo de «guardar» no pregunta por sobrescribir:
      la app nunca sobrescribe y da error. _Aceptación (tests):_ construcción del filtro.
- [x] La contraseña revelada y las notas se ocultan solas a los 10 s.
- [x] Panel de ajustes: tiempo de bloqueo, borrado del portapapeles y «bloquear al minimizar»,
      con validación de rangos y reversión si no se puede guardar.
- [x] Estado de la protección de captura (activa, parcial en Windows antiguos, desactivada o fallida)
      en la pantalla de desbloqueo y en los ajustes.
- [x] Desbloqueo / creación: examinar bóveda y keyfile, generar un keyfile nuevo, indicador de
      robustez y **repetir la contraseña** al crear (evita bloquearse por una errata).
- [x] Aviso rojo al elegir un keyfile: perderlo significa perder la bóveda, sin recuperación.
- [x] Contador TOTP: código agrupado, segundos restantes y barra que se vacía (roja los últimos 5 s),
      refrescado cada 100 ms solo mientras la entrada está abierta. Clic copia el código.
- [x] Generador de contraseñas y frases (panel propio; también desde el editor con «Usar esta
      contraseña»), con la entropía estimada.
- [x] Editor con secreto o URI TOTP. Al editar, el campo vacío conserva el secreto actual (para no
      perder algoritmo, dígitos ni periodo) y hay un botón para quitarlo.
- [x] Cambio de contraseña maestra y keyfile desde los ajustes. La derivación corre en un hilo aparte
      que abre el archivo con las credenciales **actuales** (lo que también las verifica) y lo recifra;
      mientras tanto se rechaza cualquier otro cambio, para que nada se guarde con la clave vieja.
- [x] Importación desde CSV de KeePass/KeePassXC y JSON sin cifrar de Bitwarden
      (`argus_core::import`, analizadores propios y estrictos, sin dependencias nuevas). Solo se importan
      _logins_; el resto se cuenta como omitido. Tras importar aparece el aviso de borrar el archivo origen.
      _Aceptación (tests):_ comillas, saltos de línea y BOM en CSV; escapes y pares sustitutos en JSON;
      exportación cifrada rechazada; límite de profundidad; los analizadores no entran en pánico con
      entradas arbitrarias.
- [x] Conexión de callbacks entre Slint, `argus-core` y `argus-platform`.

**Pendiente de prueba manual** (con la sesión desbloqueada), cada punto con su criterio:

- [ ] Crear una bóveda desde la ventana (con y sin keyfile) y reabrirla; el archivo no contiene texto plano.
- [ ] Crear una entrada Servidor y otra Web, editarlas y borrarlas; la lista y el filtro reflejan los cambios.
- [ ] Clic en el icono de copiar de una fila de servidor: el portapapeles recibe la contraseña con los
      formatos de protección y se vacía a los 20 s.
- [ ] Los diálogos «Examinar» abren, devuelven la ruta y la cancelación no cambia nada.
- [ ] Importar un CSV de KeePassXC y un JSON de Bitwarden reales (de prueba) y ver el aviso.
- [ ] Cambiar la contraseña maestra: la antigua deja de abrir la bóveda y la nueva sí; la ventana no se congela.
- [ ] TOTP con un secreto de prueba: el código coincide con el de otra app y la barra se vacía a ritmo.
- [ ] Ajustes: poner 30 s de bloqueo y comprobar que bloquea; poner 5 s de portapapeles y comprobarlo.
- [ ] Ocultado automático a los 10 s de la contraseña revelada.
- [x] Los tests del portapapeles (`cargo test -p argus-platform clipboard`, 7 en total) en una sesión desbloqueada: pasan (2026-10-19).
- [ ] Verificar a mano que la copia no aparece en el historial Win+V (pendiente desde la Fase 3).

**Limitaciones conocidas de esta fase**

- Un diálogo de archivo es modal y bloquea el hilo de la interfaz mientras está abierto; el bloqueo
  por inactividad no se evalúa en ese rato.
- Al importar, los textos pasan por `Zeroizing` mientras se analizan, pero el archivo origen sigue
  en claro en el disco hasta que el usuario lo borre.
- Si el usuario bloquea la bóveda mientras se cambia la contraseña maestra, el cambio termina igual
  en el archivo (la nueva contraseña rige desde el siguiente desbloqueo) y no se avisa en pantalla.

### Fase 5: Endurecimiento, Compilación y Distribución — COMPLETADA (2026-10-19)

- [x] **Coste de Argon2id reforzado y adaptado a la memoria libre (2026-10-16).** Valor por defecto: de
  256 MiB, t=3 a **512 MiB, t=4, p=4**. Al crear una bóveda o cambiar credenciales,
  `argus_core::calibrate` elige el **mayor tamaño de memoria** (64 MiB a 2 GiB, potencias de dos) que
  cabe en **un cuarto de la memoria libre ahora** (`argus_platform::memory`: el menor entre la física
  libre y la confirmable, para que las claves no vayan al archivo de paginación) y cuyo mínimo de
  pasadas no pasa de 2 s; luego sube las pasadas (4 a 10) hasta ~1,5 s. Nunca baja del valor por
  defecto salvo que la máquina no tenga memoria libre para él: entonces usa lo que cabe, lo marca
  como `reduced` y la interfaz avisa de que la bóveda es más débil de lo normal.
  **Al abrir no se calibra:** los costes van en la cabecera autenticada. Antes de derivar la clave,
  la app los lee sin descifrar (`UnlockedVault::peek_kdf_params`) y exige que haya libre la memoria
  de Argon2 más un cuarto; si no, muestra «necesita unos N MiB libres» en vez de intentarlo, porque
  un fallo de asignación **cierra el proceso** (`panic = abort`). Las bóvedas antiguas siguen abriéndose.
  _Aceptación (tests):_ 9 de la regla de calibración con un reloj simulado (memoria sigue a la libre,
  CPU lenta, memoria desconocida, equipo casi lleno, tope de pasadas, fallo de la prueba), lectura de
  la cabecera sin contraseña, y los de `argus-platform::memory`.
  _Medido en este equipo_ (32 GiB instalados, 8 GiB libres): crea con 512 MiB/t=4 y abre en **1,3 s**;
  1 GiB no cabe en el tiempo, así que no se usa. Con 2 GiB libres el resultado es el mismo; solo con
  menos de ~2 GiB libres se reduciría. Antes, 256 MiB/t=3 tardaba ~0,5 s.

- [x] **Control Flow Guard (CFG) (2026-10-19):** `-C control-flow-guard` para `x86_64-pc-windows-msvc`
  configurado en `.cargo/config.toml` y unificado en `ci.yml` con `RUSTFLAGS: "-D warnings -C control-flow-guard"`.
  _Aceptación:_ compila y pasan los 122 tests (`argus-core`, `argus-platform`, `argus-app`) con la bandera activa.

- [x] **Superficie de Slint analizada y documentada (2026-10-16):**
  - `webbrowser` y `arboard` son dependencias incondicionales del backend winit en Windows (`arboard` es además el portapapeles de Slint para pegar la clave maestra).
  - El backend activa decodificadores de imagen y SVG (`usvg`/`resvg`) que están incrustados en `ScrollView` y `ListView`.
  - La aplicación nunca abre imágenes, SVG ni URLs externas no confiables; los caminos de código no reciben datos hostiles.
  - Decisión: no bifurcar Slint para evitar divergencias de mantenimiento; aceptado como riesgo controlado.

- [x] **CI de la cadena de suministro endurecido (2026-10-19):**
  - Acciones de GitHub fijadas por commit SHA inmutable: `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2) y `EmbarkStudios/cargo-deny-action@bb137d7af7e4fb67e5f82a49c4fce4fad40782fe` (v2.0.20).
  - Herramienta de fuzzing fijada con versión y fecha exactas: `cargo install cargo-fuzz --version 0.12.0 --locked` sobre `nightly-2024-10-01`.
  - `cargo-audit` retirado del CI para evitar duplicación, cubierto por `cargo-deny` (`deny.toml`).

- [x] **Fuzzing y corpus de semillas (2026-10-19):**
  - Generador automático de semillas de corpus implementado en `argus_core::fuzzing::tests::dump_fuzz_seeds`.
  - Corpus inicial sembrado en `fuzz/corpus/parse_file/` (cabecera auténtica válida), `fuzz/corpus/decode_inner/` (bóveda vacía y bóveda poblada con servidor y web), y `fuzz/corpus/parse_totp/` (Base32, URIs estándar y parámetros avanzados).

- [x] **`cargo-deny` validado:**
  - `licenses`, `bans` y `sources` pasan en local. `advisories` y suite completa auditada en CI.

- [x] **Binario release reproducible y despojado (2026-10-19):**
  - Perfil release en `Cargo.toml`: `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, `debug = false`, `strip = true`.
  - Binario generado: `target/release/argus-app.exe` (~12.3 MB).

- [x] **Firma Authenticode del ejecutable (2026-10-19):**
  - Script [`scripts/sign.ps1`](../scripts/sign.ps1) con detección automática de `signtool.exe` en Windows SDK, soporte para archivos PFX o almacén de certificados Windows (`/sha1`), sellado de tiempo RFC 3161 con DigiCert y verificación posterior mediante la directiva Authenticode de Windows (`/pa /v`).


---

## 4. Riesgos Abiertos

| Riesgo                                                           | Mitigación prevista                                                   | Fase         |
| ---------------------------------------------------------------- | --------------------------------------------------------------------- | ------------ |
| Los secretos quedan en `SharedString` de Slint sin borrar        | Reglas del PRD §4.1; documentado como limitación                      | 2 (aceptado) |
| El árbol de Slint (254 crates) contradice "dependencias mínimas" | Sin features por defecto; revisar y recortar                          | 5            |
| El código generado por Slint contiene `unsafe`                   | `deny(unsafe_code)` en la app; lo generado queda aislado en un módulo | 2 (resuelto) |
| Memoria del proceso en swap, hibernación o volcados              | BitLocker recomendado; evaluar exclusión de WER                       | 3            |
