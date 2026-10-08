# WiFi Lab Auditor

Aplicación de escritorio para Kali/Linux: inventario Wi-Fi, capturas reales con `dumpcap`, importación PCAP/PCAPNG, análisis con TShark/HCX y recuperación offline con Hashcat. La recuperación permite seleccionar varios diccionarios locales y probarlos secuencialmente, dejando cada intento en el historial.

La interfaz usa controles Qt nativos y está organizada por proyecto: **Redes → Capturas → Recuperación**. Los archivos y resultados se guardan en el equipo.

## Arranque

```bash
./scripts/install-kali.sh
./scripts/run.sh
```

Requiere Python 3.12+, Qt6 y SQLAlchemy. El instalador comprueba dependencias, prepara el entorno y crea el comando local; no cambia permisos ni configuración de red. Si faltan herramientas en Kali:

```bash
sudo apt install python3-venv python3-pyqt6 python3-sqlalchemy network-manager iw aircrack-ng tshark wireshark-common hcxtools hcxdumptool hashcat policykit-1
```

Ejecuta la app como usuario normal desde tu sesión gráfica. También puedes activar `.venv` y usar `wifi-lab-auditor`. No hace falta ejecutar toda la interfaz con `sudo`.

## Capturar desde el adaptador

1. En **Proyectos**, guarda nombre, responsable y referencia de autorización. El proyecto queda seleccionado en la barra superior.
2. En **Redes Wi-Fi**, selecciona la red de tu laboratorio y pulsa **Añadir red seleccionada al proyecto**. Confirma el BSSID incluido en el permiso. También puedes registrarlo manualmente desde Capturas.
3. En **Capturas**, elige la red autorizada; el adaptador y la frecuencia se rellenan desde el inventario. Ajusta la duración solo si necesitas otra ventana.
4. Si la interfaz aparece como `managed`, marca la confirmación y pulsa **Preparar monitor…**. La aplicación pedirá autorización del sistema mediante polkit para ejecutar `airmon-ng`; esto puede desconectar la conexión Wi-Fi de ese adaptador. Actualiza los adaptadores y selecciona la interfaz `monitor` creada. Un adaptador dedicado evita afectar tu conexión habitual.
5. Pulsa **Iniciar captura**. Se ejecuta `dumpcap` con filtro para la red autorizada, límite de 64 MB y duración máxima de una hora. La ventana recomendada es de 120 segundos; si la reconexión automática está activa, la app aplica como mínimo esa duración para dejar tiempo al intento dirigido y a los cuatro mensajes EAPOL. **Detener y conservar archivo** finaliza el proceso y guarda lo capturado; después puedes pulsar **Analizar selección**.

Para obtener el cliente ya no tienes que escribir una MAC: al seleccionar una interfaz monitor la aplicación observa automáticamente el BSSID durante 20 segundos y llena **Cliente detectado automáticamente**. Cuando encuentra uno, deja preparada la autorización y una reconexión dirigida sobre ese único cliente. Si el propio equipo tiene otra interfaz gestionada conectada al BSSID autorizado, la aplicación la desconecta y reconecta primero mediante NetworkManager; si no, usa el cliente autorizado observado. La captura continúa durante la ventana recomendada para observar los cuatro mensajes EAPOL. Si no aparece, pulsa **Volver a detectar**. Nunca se acepta un cliente fuera del alcance del proyecto ni una solicitud de difusión contra todos los clientes; el adaptador debe estar en modo monitor y `aireplay-ng` debe estar instalado.

La frecuencia se obtiene automáticamente de la frecuencia que informa NetworkManager (con el canal como respaldo) y no se acepta un valor MHz arbitrario que pueda desincronizar la radio. La captura usa una interfaz que ya está en modo monitor e intenta fijar el canal autorizado. Algunos controladores rechazan el cambio de canal desde `dumpcap`; en ese caso se reintenta usando el canal que ya configuró `airmon-ng`, y ambos intentos quedan en los logs del artefacto. No se intenta cambiar canales en una interfaz gestionada. El adaptador, su controlador, los permisos de captura y el dominio regulatorio determinan lo que puede capturarse. La reconexión automática es una acción dirigida, explícita y única sobre el cliente seleccionado; el material de autenticación debe estar presente en el tráfico observado.

La aplicación conserva el resultado de la captura mientras actualiza los adaptadores; no reinicia la detección de clientes al terminar. Si `aireplay-ng` transmite pero registra `0 ACKs`, la reconexión se marca como no confirmada y se muestra el motivo. Tras la captura EAPOL y el único intento dirigido, el modo automático ejecuta un segundo método PMKID limitado al BSSID autorizado con `hcxdumptool`, sin desautenticación masiva ni sondeos de difusión. Si cualquiera de los dos métodos produce material convertible, aparece una captura lista para recuperación; si ambos fallan, se conservan los dos diagnósticos.

Si **Redes Wi-Fi** muestra cero resultados mientras el adaptador aparece como `monitor`, NetworkManager no puede explorar desde ese modo. Pulsa **Gestionar adaptador**, restaura el adaptador en **Capturas**, vuelve a **Redes Wi-Fi** y pulsa **Buscar redes**. Antes de registrar una red seleccionada, elige el proyecto activo en la barra superior. Al volver a capturar, selecciona el BSSID y canal del módem correcto; cada módem puede anunciar un BSSID diferente.

**Permisos:** Diagnóstico consulta `dumpcap -D`. Si falla, configura los permisos de captura de Wireshark de tu distribución. En Kali/Debian se pueden gestionar con `sudo dpkg-reconfigure wireshark-common`; cuando se use el grupo `wireshark`, añade tu usuario a ese grupo y vuelve a iniciar sesión. La app no modifica esos permisos automáticamente.

## Importar y analizar una captura propia

1. Selecciona un proyecto y registra el BSSID autorizado, aunque no aparezca en el inventario actual.
2. En **Capturas**, pulsa **Importar archivo** y selecciona un PCAP/PCAPNG de hasta 512 MiB.
3. Se conserva una copia del original y se registra su SHA-256. El original no se modifica.
4. TShark cuenta tramas del BSSID, EAPOL y mensajes M1–M4 sobre las primeras 200 000 tramas del archivo. HCX convierte el archivo completo y se conserva únicamente material del BSSID autorizado.
5. La ficha distingue mensajes observados de material WPA convertible. Contar M1–M4 no se presenta como prueba de un handshake válido.

Las capturas sin material recuperable siguen disponibles. Un error del parser aparece como error; no se convierte en un éxito simulado.

Una captura puede contener balizas y tráfico de datos sin contener una autenticación EAPOL. En ese caso el registro muestra las tramas observadas, los clientes y frecuencias vistos, y clasifica el siguiente paso: BSSID no visto, cliente sin nueva autenticación, asociación sin EAPOL o tráfico sin material convertible. El registro no significa que la captura haya fallado ni que el BSSID sea automáticamente recuperable.

## Recuperación offline

1. Abre **Recuperación** y selecciona una captura cuyo análisis haya producido material WPA compatible.
2. Pulsa **Añadir diccionarios…** y selecciona varios archivos a la vez con Ctrl o Shift. Se admiten archivos de texto sin comprimir de hasta 2 GiB; puedes quitar elementos seleccionados o limpiar la lista sin volver a abrir el selector.
3. Define un tiempo máximo entre 10 y 3600 segundos. Ese límite se aplica a cada diccionario, no al lote completo.
4. Pulsa **Iniciar recuperación**. Hashcat prueba los diccionarios en el orden mostrado, sin intervención entre ellos, y se detiene cuando encuentra un resultado recuperable. Mientras trabaja, la interfaz muestra el nombre y posición del diccionario actual, las pruebas realizadas, el total, el porcentaje, la velocidad y las coincidencias verificadas. Cada diccionario ejecutado queda como una fila independiente en el historial.
5. Consulta el historial. Los estados distinguen recuperación, resultado parcial, diccionario agotado, interrupción y error. Un límite de tiempo no equivale a agotar el diccionario.
6. **Mostrar resultado local** revela las claves recuperadas en un diálogo. No se suben ni se copian automáticamente al portapapeles.

No hay garantía de recuperar una clave. WPA3-SAE y redes empresariales no se convierten automáticamente en material WPA-PSK 22000. Esta versión ofrece recuperación por diccionario; no implementa campañas distribuidas, máscaras ni reanudación de Hashcat. Un trabajo interrumpido puede iniciarse de nuevo, conservando su historial anterior.

## Inventario y diagnóstico

El inventario inicial consulta las redes conocidas por NetworkManager sin forzar escaneo. **Buscar redes** solicita un escaneo normal; no es una captura pasiva en modo monitor. Cada fila representa un BSSID (una radio concreta), por eso un mismo SSID puede aparecer en 2.4 GHz y 5/6 GHz. La tabla muestra la banda, el canal y el BSSID para que puedas escoger la radio autorizada; la identidad del objetivo siempre es el BSSID, no solo el nombre de la red. Hay filtros y exportación CSV. La señal real se muestra en porcentaje, sin inventar valores dBm.

**Adaptadores** consulta `iw`. **Diagnóstico** comprueba herramientas, NetworkManager, radio Wi-Fi y permisos/interfaces de `dumpcap`. El indicador superior muestra `SYSTEM ONLINE` en verde cuando todas las comprobaciones del backend pasan y `SYSTEM OFFLINE` en rojo cuando falta una herramienta o falla el acceso a red/captura. Las consultas se ejecutan fuera del hilo de la interfaz. Un trabajo de laboratorio bloquea cambios de proyecto y nuevas exploraciones de red hasta terminar.

## Persistencia

- Base real: `~/.local/share/wifi-lab-auditor/auditor.sqlite3`.
- Capturas y resultados: subdirectorio `artifacts`, con un directorio privado por operación.
- La base de demostración es `demo.sqlite3`. No ejecuta captura ni recuperación reales.
- Al cerrar, se solicita la detención del proceso propio y se espera a guardar su estado. En el siguiente arranque, trabajos inconclusos quedan marcados como interrumpidos. Solo se permite una instancia por base de datos.

No se eliminan automáticamente capturas ni resultados. Haz copias de seguridad y gestiona el espacio local. Los archivos importados pueden contener tráfico adicional al BSSID seleccionado; el análisis y la recuperación se restringen al alcance registrado.

## Pruebas y demo

```bash
./scripts/test.sh
# Prueba opcional con Hashcat real y una clave sintética conocida:
WIFI_LAB_TEST_HASHCAT=1 ./scripts/test.sh
# Interfaz con inventario sintético:
WIFI_LAB_MOCK=1 WIFI_LAB_MOCK_SCENARIO=capture-valid ./scripts/run.sh
```

Las pruebas generan capturas sintéticas localmente. Si TShark y HCX están instalados, verifican su conversión real; la prueba opcional comprueba la clave devuelta por Hashcat. También cubren autorización, cancelación, estados de error, persistencia y controles de la interfaz.

**Validación pendiente para despliegue:** captura por radio con el BSSID y adaptador autorizados del operador, distintas combinaciones de controlador/permisos y la instalación/actualización en un sistema limpio. Las pruebas offline no sustituyen esa aceptación de hardware.

```bash
./scripts/build-deb.sh
./scripts/check-release.sh
```

El paquete se escribe en `dist/`. No incluye bases, capturas, resultados ni cachés.
Para regenerar también el paquete de compatibilidad `0.1.0` con el código actual, ejecuta `PACKAGE_VERSION=0.1.0 ./scripts/build-deb.sh` antes del comando normal.

Diseño basado en [ui-skills](https://github.com/ibelick/ui-skills), adaptando `baseline-ui` y accesibilidad a Qt. Consulta [DESIGN.md](DESIGN.md) y [la arquitectura](docs/architecture.md).
