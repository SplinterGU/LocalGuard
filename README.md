# LocalGuard

Bloqueador de publicidad y rastreadores por DNS para Android. Utiliza una VPN local para filtrar las consultas dirigidas al servidor DNS que anuncia al sistema, sin root y sin enviar el tráfico del teléfono a un servidor VPN remoto.

El bloqueo se realiza por dominio. LocalGuard no inspecciona páginas ni contenido HTTPS y no controla la reproducción de anuncios dentro de otras aplicaciones.

## Características

- Activación y parada desde la aplicación o la notificación del servicio.
- Autorización VPN mediante el diálogo de Android.
- Lista inicial de dominios incluida en la aplicación.
- Reglas adicionales editables en formato dominios o hosts.
- Coincidencia con el dominio indicado y sus subdominios.
- Excepciones con prioridad sobre las reglas de bloqueo.
- Respuestas NXDOMAIN para consultas a dominios bloqueados.
- Procesamiento de consultas DNS A, AAAA y otros tipos, con bloqueo por nombre de dominio.
- Resolución externa por UDP y TCP, con servidor secundario del mismo proveedor.
- Cloudflare, Quad9 y Google como proveedores seleccionables.
- Aplicación de cambios a las siguientes consultas sin reiniciar el servicio.
- Contadores persistentes de consultas, bloqueos y errores.
- Registro en memoria de las últimas 100 consultas procesadas.
- Implementación Java con APIs nativas de Android, sin bibliotecas externas de ejecución.

## Cómo funciona

LocalGuard anuncia el servidor DNS virtual `10.77.0.2` y configura una única ruta VPN: `10.77.0.2/32`.

Cuando llega una consulta a ese servidor:

1. Interpreta el paquete IPv4 y su transporte UDP o TCP.
2. Lee la pregunta DNS y comprueba las reglas y excepciones.
3. Si el dominio está bloqueado, genera una respuesta NXDOMAIN.
4. Si está permitido, consulta al proveedor DNS seleccionado mediante un socket protegido y vinculado a una red física.
5. Encapsula la respuesta en un paquete IP/UDP o IP/TCP y la devuelve al sistema.

```text
Consultas al DNS anunciado
           |
      10.77.0.2/32
           |
       TUN local
           |
  Reglas y excepciones
       /         \
  Bloqueado    Permitido
      |            |
  NXDOMAIN    DNS externo
       \          /
     Respuesta IP/UDP o IP/TCP
               |
              TUN

HTTP, HTTPS y tráfico a otros destinos -> red normal
```

La aplicación no captura todo el tráfico del dispositivo. Las conexiones a otros destinos permanecen fuera del túnel.

## Características técnicas

| Componente | Implementación |
|---|---|
| Lenguaje | Java |
| Android mínimo | Android 8.0 / API 26 |
| SDK de compilación y destino | API 35 |
| Interfaz | Activity y widgets nativos de Android |
| Servicio | VpnService en primer plano, tipo specialUse |
| Dirección local del túnel | 10.77.0.1/32 |
| DNS virtual y ruta | 10.77.0.2/32 |
| MTU | 1500 bytes |
| Entrada/salida del TUN | No bloqueante, con Os.poll() |
| Escritura al TUN | Centralizada en el hilo del túnel mediante cola de salida |
| Señalización | Par de sockets locales no bloqueantes |
| Transporte hacia el proveedor | DNS IPv4 sobre UDP/TCP, puerto 53, sin cifrado |
| Respuesta de bloqueo | NXDOMAIN, código DNS 3 |
| Persistencia | SharedPreferences para configuración y contadores |
| Historial | Hasta 100 entradas en memoria; sin archivo persistente |
| Reinicio automático del servicio | Deshabilitado: START_NOT_STICKY |

El hilo del túnel centraliza la lectura, escritura y cierre del descriptor. Los workers procesan las consultas y encolan los paquetes de respuesta. La parada señala la salida del hilo sin esperar cierres de sockets o locks desde el hilo principal; primero se cierra el TUN y después se liberan los demás recursos.

### Transporte DNS

- Validación y generación de checksums IPv4, UDP y TCP.
- Transporte DNS/TCP local con framing por longitud, reensamblado del flujo, retransmisión de segmentos y pipelining limitado.
- Limitación del tamaño anunciado por EDNS a 1232 bytes.
- Consulta TCP al proveedor cuando una respuesta UDP llega truncada.
- Uso de TCP hacia el proveedor para consultas mayores de 1232 bytes.
- Respuesta truncada al cliente UDP si la respuesta completa supera 1232 bytes, para permitir un nuevo intento por TCP.
- Sin reensamblado de paquetes IP fragmentados.

Se anuncia un DNS IPv4, pero también se procesan consultas AAAA. El tráfico IPv6 hacia otros destinos se permite fuera del túnel mediante `allowFamily(AF_INET6)`.

### Límites de recursos

- Hasta 8 workers y una cola de 128 tareas.
- Cola de salida de hasta 256 paquetes.
- Hasta 64 sesiones DNS/TCP locales.
- Hasta 8 consultas TCP pendientes en cola por sesión, además de la consulta en ejecución.
- Registro de hasta 100 consultas.

Si se satura la cola de tareas UDP, se intenta responder SERVFAIL. Si se satura la cola de salida, se descarta el paquete y se registra el evento. Los límites del transporte TCP pueden provocar el cierre de la sesión.

## Proveedores DNS

| Proveedor | Principal | Secundario |
|---|---|---|
| Cloudflare | 1.1.1.1 | 1.0.0.1 |
| Quad9 | 9.9.9.9 | 149.112.112.112 |
| Google | 8.8.8.8 | 8.8.4.4 |

Las consultas permitidas salen del dispositivo hacia el proveedor elegido. Esta implementación no utiliza DNS-over-HTTPS ni DNS-over-TLS.

## Reglas y excepciones

Se acepta un dominio por línea o entradas compatibles con el formato hosts. Se admiten comentarios precedidos por `#`.

```text
# Dominios de ejemplo
ads.example.com
tracker.example.com
*.metrics.example.com

# Formato hosts
0.0.0.0 ads.other.example.com
127.0.0.1 tracker.other.example.com
```

Una regla para `tracker.example.com` también coincide con `sub.tracker.example.com`, pero no con `nottracker.example.com`.

El prefijo `*.` es opcional: las reglas ya incluyen subdominios. Se aceptan prefijos hosts `0.0.0.0`, `127.0.0.1`, `::` y `::1`.

Las excepciones se introducen en su propio campo y tienen prioridad:

```text
needed.example.com
```

La lista inicial es pequeña y se encuentra en `app/src/main/assets/domains.txt`. Las listas adicionales se incorporan pegando su contenido en el campo de reglas. No hay descarga ni actualización automática de listas.

No se admiten EasyList, expresiones regulares, reglas de URL ni filtros cosméticos. Bloquear dominios puede afectar funciones de otras aplicaciones; las excepciones permiten autorizar los dominios necesarios.

## Uso

1. Desactivar DNS privado en los ajustes de Android para obtener un filtrado predecible. Si se detecta un proveedor privado personalizado, LocalGuard no inicia el servicio y muestra el motivo.
2. Abrir LocalGuard y seleccionar el proveedor DNS.
3. Configurar las reglas y excepciones si es necesario.
4. Pulsar Activar protección y aceptar la autorización VPN del sistema.
5. En Android 13 o superior, responder a la solicitud de permiso de notificaciones.
6. Consultar los contadores y el registro para comprobar qué dominios se procesan.
7. Detener mediante el botón de la aplicación o la acción de la notificación.

Denegar las notificaciones no impide iniciar el servicio, pero limita su visibilidad.

Las aplicaciones y el sistema pueden conservar resoluciones en caché. Guardar una regla no invalida esas cachés ni cierra conexiones ya establecidas.

## Privacidad

- No hay servidor VPN remoto ni envío centralizado del tráfico.
- No se incluye telemetría ni exportación del registro.
- Las reglas y los contadores se almacenan en las preferencias privadas de la aplicación.
- El registro de dominios se mantiene en memoria y desaparece cuando termina el proceso.
- El proveedor DNS seleccionado recibe las consultas permitidas.
- El DNS UDP/TCP no está cifrado: terceros con visibilidad de la red pueden observarlo.
- No se instalan certificados ni se intercepta el contenido HTTPS.

Una VPN local de filtrado DNS no proporciona anonimato ni sustituye una VPN de transporte cifrado.

## Limitaciones

- No bloquea de forma fiable anuncios servidos desde el mismo dominio que el contenido.
- No garantiza eliminar anuncios de video de YouTube u otras plataformas.
- No acelera, acorta ni salta anuncios dentro de otras aplicaciones.
- Las apps que usan DNS propio, DoH, DoT o direcciones IP directas pueden eludir el filtro.
- No ofrece firewall por aplicación, filtrado HTTP/HTTPS ni eliminación visual de espacios publicitarios.
- Requiere conectividad IPv4 hacia alguno de los proveedores configurados.
- No reensambla paquetes IP fragmentados.
- No admite uso simultáneo con otra VPN.
- No admite VPN siempre activa. No debe activarse Bloquear conexiones sin VPN, porque el tráfico no-DNS permanece fuera del túnel.
- Si el sistema termina el servicio, no se garantiza que el filtrado continúe.

## Compilación

### Requisitos

- JDK 17.
- Android SDK Platform 35.
- Android SDK Build Tools 34.0.0.
- Gradle 8.9 y Android Gradle Plugin 8.7.3.
- Python 3.9 o superior si se utilizan los lanzadores incluidos.
- Conexión a Internet para descargar las herramientas y dependencias de compilación.

### Linux y macOS

Desde la raíz del proyecto, configurar el SDK y comprobar que `JAVA_HOME` apunta a un JDK 17:

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
unset ANDROID_SDK_ROOT

chmod +x gradlew
./gradlew assembleDebug
```

En macOS u otras instalaciones, ajustar `ANDROID_HOME` a la ubicación real del SDK.

### Windows

```bat
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT="

gradlew.bat assembleDebug
```

También puede configurarse el SDK en `local.properties`:

```properties
sdk.dir=/ruta/al/Android/Sdk
```

Las configuraciones del SDK deben apuntar a la misma instalación. No se debe versionar `local.properties`.

Los lanzadores incluidos `gradlew` y `gradlew.bat` utilizan Python para descargar Gradle desde su distribución oficial, verificar SHA-256 y ejecutarlo. Con Gradle 8.9 instalado globalmente se puede usar `gradle assembleDebug` sin Python.

### Android Studio

1. Abrir la raíz del proyecto.
2. Instalar Platform 35 y Build Tools 34.0.0 desde SDK Manager.
3. Seleccionar JDK 17 para Gradle.
4. Sincronizar y ejecutar el módulo `app`.

Si el IDE requiere el wrapper convencional de Gradle, ejecutar `./gradlew wrapper` o `gradlew.bat wrapper`. Ese comando genera el wrapper oficial y sustituye los lanzadores incluidos.

### Instalación del APK debug

Linux/macOS:

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Windows:

```bat
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

## Pruebas

### Motor DNS y paquetes

Con JDK 17 y Python disponibles:

```sh
python3 tests/run.py
```

En Windows:

```bat
python tests\run.py
```

Estas pruebas compilan los módulos Java independientes de Android y comprueban reglas, excepciones, IDN, formato hosts, preguntas DNS, NXDOMAIN, EDNS, checksums, framing TCP, consultas divididas, secuencias con wrap y cierre FIN.

No cubren el ciclo de vida de VpnService ni la integración con el sistema Android.

### Verificación en dispositivo

- Comprobar navegación a dominios permitidos con la protección activa.
- Consultar un dominio de la lista con DNS seguro del cliente desactivado y revisar el registro de bloqueo.
- Autorizar ese dominio mediante una excepción y repetir tras eliminar la caché del cliente.
- Cambiar entre Wi-Fi y datos móviles y comprobar consultas nuevas.
- Detener desde la aplicación y desde la notificación.
- Revocar la autorización VPN desde los ajustes del sistema.
- Rotar la pantalla y comprobar la conservación de reglas pendientes de guardar.

Para consultar los mensajes del servicio:

```sh
adb logcat -s LocalGuard:I AndroidRuntime:E
```

Para ejecutar el análisis estático Android:

```sh
./gradlew lintDebug
```

La inclusión de pruebas no constituye una certificación de funcionamiento ni una auditoría de seguridad.

## Estructura del proyecto

```text
app/src/main/
├── AndroidManifest.xml
├── assets/
│   └── domains.txt
├── java/dev/localguard/
│   ├── MainActivity.java
│   ├── GuardService.java
│   ├── AppState.java
│   ├── DomainRules.java
│   ├── Dns.java
│   ├── Wire.java
│   ├── TcpDns.java
│   └── Upstream.java
└── res/
    ├── drawable/ic_shield.xml
    └── values/styles.xml

tests/
├── CoreTests.java
└── run.py

tools/
└── gradle_bootstrap.py
```

## Licencia

El código y la lista inicial se distribuyen bajo la licencia MIT. Consultar `LICENSE`.

Las herramientas de compilación y los componentes de terceros conservan sus propias licencias. Cualquier lista externa añadida al repositorio debe distribuirse respetando su licencia de origen.
