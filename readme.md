# Apuntes del curso

## Conceptos básicos

### Direcciones IP (IPV4 e IPV6)

Las direcciones IP son identificadores numéricos únicos que se utilizan para identificar dispositivos en una red, como ordenadores, routers, servidores y otros dipositivos conectados a Internet.

Existen dos versiones de direcciones IP: IPv4 e IPv6.

La versión IPv4 utiliza un formato de dirección de 32 bits y se utiliza actualmente en la mayoría de las redes.
La versión IPv6 utiliza un formatio de dirección de 128 bits y se está implementando gradualmente en todo el mundo para hacer frente a la escasez de direcciones IPv4.

Las direcciones IPv4 se representan como cuatro números separados por puntos, como 192.168.0.1 mientras que las direcciones IPv6 se representan en notación hexadecimal y se separan por dos puntos, como 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

```bash
echo "$(echo "obase=2; 192" | bc).$(echo "obase=2; 168" | bc).$(echo "obase=2; 0" | bc).$(echo "obase=2; 5" | bc)

> 11000000.10101000.00000000.00000101

echo "2^32" | bc

echo "2^128" | bc

```

![Estructura de dirección IPv4](https://ccnadesdecero.es/wp-content/uploads/2019/12/Direcci%C3%B3n-IPv4.jpg)

![Estructura de dirección IPv6](https://www.sunucun.com.tr/blog/wp-content/uploads/2024/04/IPv6-1536x864.png)

### Direcciones MAC (OUI y NIC)

La dirección MAC es un número hexadecimal de 12 dígitos (número binario de 6 bytes), que está representado principalmente por notación hexadecimal de dos puntos.

Los primeros 6 dígitos (digamos 00:40:96) del MAC Address identifican al fabricante, llamado OUI (Identificador Único Organizacional). El comité de la Autoridad de Registro de IEEE asigna estos prefijos MAC a sus proveedores registrados.

Los 6 dígitos más a la derecha representan el controlador de interfaz de red, que es asignado por el fabricante.

Es decir, los primeros 3 bytes (24 bits) representan el fabricante de la tarjeta, y los últimos 3 bytes (24 bits) identifican la tarjeta particular de ese fabricante. Cada grupo de 3 bytes se puede representar con 6 dígitos hexadecimales, formando un número hexadecimal de 12 dígitos que representan la MAC completa.

![Estructura de dirección MAC](https://ccnadesdecero.es/wp-content/uploads/2020/03/Direcci%C3%B3n-MAC-Ethernet.png)

Para una búsqueda de fabricante utilizando direcciones MAC, se requieren al menos los primeros 3 bytes (6 caracteres) de la dirección MAC. Una de las herramientas que vemos en esta clase para logra dicho fin es 'macchanger', una herramienta de GNU/Linux para la visualización y manipulación de direcciones MAC.

```bash
macchanger -l | grep -i vmware
```

### Protocolos comunes (UDP, TCP) y el famoso Three-Way Handshake

Los protocolos TCP (Transmission Control Protocol) y UDP (User Datagram Protocol) son dos de los protocolos de red más comunes utilizados en la transferencia de datos a través de redes de ordenadores.

El protocolo TCP, es un protocolo orientado a la conexión que proporciona una entrega de datos confiable, mientras que el protocolo UDP, es un protocolo no orientado a conexión el cual no garantiza la entrega de datos.

Una parte crucial del protocolo TCP es el Three-Way Handshake, un procedimiento utilizado para establecer una conexión entre dos dispositivos. Este procedimiento consta de tres pasos: SYN, SYN-ACK, ACK, en los qe se sincronizan los números de secuencia y de reconocimiento de los paquetes entre los dispositivos. El Three-Way Handshake es fundamental para estabalecer una conexión confiable y segura a través de TCP.

Puertos TCP comunes:

* 21: FTP (File Transfer Protocol) - Permite la transferencia de archivos entre sistemas.
* 22: SSH (Secure Shell) - Un protocolo de red seguro que permite a los usuarios conectarse y administrar sistemas de forma remota.
* 23: Telnet - Un protocolo utilizado para la conexión remota a dispositivos de red.
* 80: HTTP (HyperText Transfer Protocol) - El protocolo que se utiliza para la transferencia de datos en la World Wide Web.
* 443: HTTPS (HyperText Transfer Protocol Secure) - La versión segura de HTTP, que utiliza encriptación SSL/TLS para proteger las comunicaciones web.

* 110: POP3
* 139,445: SMB
* 143: IMAP

Puertos UDP comunes:

* 53: DNS (Domain Name System) - Un sistema que traduce nombres de dominio en direcciones IP.
* 67/68: DHCP (Dynamic Host Configuration Protocol) - Un protocolo utilizado para asignar direcciones IP y otros parámetros de configuración a los dispositivos en una red.
* 69: TFTP (Trivial File Transfer Protocol) - Un protocolo simple utilizado para transferir archivos entre dispositivos en una red.
* 123: NTP (Network Time Protocol) - Un protocolo utilizado para sincronizar los relojes de los dispositivos en una red.
* 161: SNMP (Simple Network Management Protocol) - Un protocolo utilizado para administrar y supervisar dispositivos en una red.

Cabe destacar que estos son solo algunos de los más comunes. Existen muchos más puertos los cuales operan tanto por TCP como por UDP.

A medida que avancemos en el curso, tendremos la oportunidad de ver muchos otros puertos y protocolos utilizados en redes de ordenadores. Asimismo, veremos técnincas para analizar y explotar vulnerabilidades en su implementación.

### El modelo OSI - ¿En qué consiste y cómo se estructura la actividad de red en capas?

En redes de ordenadores, el modelo OSI (Open Systems Interconnection) es una estructura de siete capas que se utiliza para describir el proceso de comunicación entre dispositivos. Cada capa proporciona servicios y funciones específicas, que permiten a los dispositivos comunicarse a través de la red.

A continuación, se describen brevemente las siete capas del modelo OSI.

1. Capa Física: Es la capa más baja del modelo OSI, que se encarga de la transmisión de datos a través del medio físico de la red, como cables de cobre o fibra óptica.
2. Capa de Enlace de Datos: Esta capa se encarga de la transferencia confiable de datos entre dispositivos en la misma red. También proporciona funciones para la detección y corrección de errores en los datos transmitidos.
3. Capa de red: La capa de red se ocupa del enrutamiento de paquetes de datos a través de múltiples redes. Esta capa utiliza direcciones lógicas, como direcciones IP, para identificar dispositivos y rutas de red.
4. Capa de Transporte: La capa de transporte se encarga de la entrega confiable de datos entre dispositivos finales, proporcionando servicios como el control del flujo y la corrección de errores.
5. Capa de sesión: Esta capa se encarga de establecer y mantener las sesiones de comunicación entre dispositivos. También proporcionan servicios de gestión de sesiones, como la autenticación y la autorización.
6. Capa de presentación: La capa de presentación se encarga de la representación de datos, proporcionando funciones como la codificación y decodificación de datos, la comprensión y el cifrado.
7. Capa de aplicación: La capa de aplicación proporciona servicios para aplicaciones de usuario finales, como correo electrónico, navegadores web y transferencia de archivos.

Comprender la estructura en capas del modelo OSI es esencial para cualquier analista de seguridad, ya que permite tener una visión completa del funcionamiento de la red y de las posibles vulnerabilidades que pueden existir en cada una de las etapas.

Esto nos permite identificar de manera efectiva los puntos débiles de la red y aplicar medidas de seguridad adecuadas para protegerla de posibles ataques.

### Subnetting - ¿Qué es y cómo se interpreta una máscara de red?

Subnetting es una técnica utilizada para dividir una red IP en subredes más pequeñas y manejables. Esto se logra mediante el uso de máscaras de red, que permiten definir qué bits de la dirección IP corresponden a la red y cuáles a los hosts.

Para interpretar una máscara de red, se deben identificar los bits que están en la "1". Estos bits representan la porción de la dirección IP que corresponde a la red. Por ejemplo, una máscara de red de 255.255.255.0 indica que los primeros tres octetos de la dirección IP corresponden a la red, mientras que el último octeto se utiliza para identificar los hosts.

Ahora bien, cuando hablamos de CIDR (acrónimos de Classless Inter-Domain Routing), a lo que nos referimos es a un método de asignación de direcciones IP más eficiente y flexible que el uso de clases de redes IP fijas. Con CIDR, una dirección IP se representa mediante una dirección IP base y una máscara de red, que se escriben juntas separadas por una barra (/).

Por ejemplo, la dirección IP 192.168.1.1 con una máscara de red de 255.255.255.0 se escribiría como 172.168.1.1/24.

La máscara de red se representa en notación de prefijo, que indica el número de bits que están en "1" en la máscara. En este caso, la máscara de red 255.255.255.0 tiene 24 bits en "1" (los primeros tres octetos), por lo que su notación de prefijo es /24.

Para calcular la máscara de red a partir de una notación de prefijo, se deben escribir los bits "1", en los primeros bits de una dirección IP de 32 bits y los bits "0" en los bits restantes. Por ejemplo, la máscara de red /24 se calcularía como 11111111.11111111.11111111.00000000 en binario, lo que equivale a 255.255.255.0 en decimal.

En las siguientes clases, profundizaremos mucho más en todo esto, viendo múltiples ejemplos y casos prácticos con los que poder curiosear.

| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 | Total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 255 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 255 |
| 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 255 |
| 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### Subnetting - CIDRs y cálculo total de hosts

En cuanto a clases de direcciones IP, existen tres tipos de máscaras de red: Clase A, Clase B y Clase C.

* Las redes de clase A usan una máscara de subred predeterminada de 255.0.0.0 y tienen de 0 a 127 como su primer octeto. La dirección 10.52.36.11, por ejemplo, es una dirección de clase A. Su primer octeto es 10, que está entre 1 y 126, ambos incluidos.
* Las redes de clase B usan máscara de subred predeterminada de 255.255.0.0 y tienen de 128 a 191 como su primer octeto. La dirección 172.16.52.63, por ejemplo, es una dirección de clase B. Su primer octeto es 172, que está entre 128 y 191, ambos inclusive.
* Las redes de clase C usan una máscara de subred predeterminada de 255.255.255.0 y tienen de 192 a 223 como su primer octeto. La dirección 192.168.123.132, por ejemplo, es una dirección de clase C. Su primer octeto es 192, que está entre 192 y 223, ambos incluidos.

Es importante tener en cuenta que, además de estos tres tipos de máscaras de red, también existen máscaras de red personalizadas que se pueden utilizar para crear subredes de diferentes tamaños dentro de una red.

Tal y como mencionamos en la descripción de la clase anterios sobre los CIDRs, se trata de un método de asignación de direcciones IP que permite dividir una dirección IP en una parte que identifica la red y otra parte que identifica el host. Esto se logra mediante el uso de una máscara de red, que se representa en notación CIDR com una dirección IP base seguirda de un número que indica la cantidad de bits que corresponden a la red.

Con CIDR, se pueden asignar direcciones IP de forma más precisa, lo que reduce la cantidad de direcciones IP desperdiciadas y facilita la administración de la red.

El número que sigue a la dirección IP base en la notación CIDR se llama prefijo o longitud de prefijo, y representa el número de bits en la máscara de red que están en "1".

Por ejemplo, una dirección IP con un prefijo de /24 indica que los primeros 24 bits de la dirección IP corresponden a la red, mientras que los 8 bits restantes se utilizan para identificar los hosts.

Para calcular la cantidad de hosts disponibles en una red CIDR, se deben contar el número de bits "0" en la máscara de red y elevar 2 a la potencia ese número. Esto se debe a que cada bit "0" en la máscara de red representa un bit que se puede utilizar para identificar un host.

Por ejemplo, una máscara de red de 255.255.255.0 (/24) tiene 8 bits en "0", lo que significa que hay 2^8 = 256 direcciones IP disponibles para los hosts en la red.

A continuación, se representan algunos ejemplos prácticos de CIDR:

* Una dirección IP con un prefijo de /28 (255.255.240) permite hasta 16 direcciones IP para los host (2^4), ya que los primeros 28 bits corresponden a la red.
* Una dirección IP con un prefijo de /26 (255.255.255.192) permite hasta 64 direcciones IP para los hosts (2^6), ya que los primeros 26 bits corresponden a la red.
* Una dirección IP con un prefijo de /22 (255.255.252.0) permite hasta 1024 direcciones IP para los hosts (2^10), ya que los primeros 22 bits corresponden a la red.^

Si aún te quedan dudas y necesitas reforzar el contenido con más ejemplos prácticos, no te preocupes, en las clases siguientes estaremos entrando muchos más en materia.

### Subnetting - Máscaras de subred, tipos de clase e interpretación de prefijos de red

En esta clase, explicamos cómo calcular para la dirección IP 192.168.1.0/26, su máscara de red, el número total de hosts a repartir, el identificador de red y la dirección Broadcast.

A continuación, se detalla paso a paso cómo hemos ido calculando cada apartador:

* 1 Cálculo de la máscara de red:

La direccion IP que se nos dió es 192.168.1.0/26, lo que significa que los primero 26 bits de la dirección IP corresponden a la red y los últimos 6 bits corresponden a los hosts.

Para calcular la máscara de red, necesitamos colocar los primeros 26 bits en 1 y los últimos 6 bits en 0. En binario, esto se ve así:

11111111.11111111.11111111.11000000

Cada octeto de la máscara de red se compone de 8 bits. El valor de cada octeto se determina convirtiendo los 8 bits a decimal. En este caso, los primeros 24 bits son todos 1s, lo que significa que el valor decimal de cada uno de estos octetos es 255. El último octeto tiene los últimos 6 bits en 0, lo que significa que su valor decimal es 192.

Por lo tanto, la máscara de red para esta dirección IP es 255.255.255.192.

* 2 Cálculo del total de hosts a repartir:

En este caso, se pueden utilizar los 6 bits que quedan disponibles para representar la parte de host. En una máscara de red de 26 bits, los 6 bits restantes representan 2^6 – 2 = 62 hosts disponibles para asignar.

El número máximo de hosts disponibles se calcula como 2^(n) – 2, donde n es la cantidad de bits utilizados para representar la parte de host en la máscara de red.

* 3 Cálculo del Network ID:

Para calcular el Network ID, lo que debemos hacer es aplicar la máscara de red a la dirección IP de la red. En este caso, la máscara de red es 255.255.255.192, lo que significa que los primeros 26 bits de la dirección IP pertenecen a la parte de red.

Para calcular el Network ID, convertimos tanto la dirección IP como la máscara de red en binario y luego hacemos una operación “AND” lógica entre los dos. La operación “AND” compara los bits correspondientes en ambas direcciones y devuelve un resultado en el que todos los bits coincidentes son iguales a “1” y todos los bits no coincidentes son iguales a “0“.

En este caso, la dirección IP es 192.168.1.0 en decimal y se convierte en binario como 11000000.10101000.00000001.00000000. La máscara de red es 255.255.255.192 en decimal y se convierte en binario como 11111111.11111111.11111111.11000000.

Luego, aplicamos la operación “AND” entre estos dos valores binarios bit a bit. Los bits correspondientes en ambos valores se comparan de la siguiente manera:

```bash
11000000.10101000.00000001.00000000 (dirección IP)
11111111.11111111.11111111.11000000 (Máscara de red)
-----------------------------------
11000000.10101000.00000001.00000000 (Resultado de la operación AND)
```

El resultado final es el Network ID, que es 192.168.1.0. Este es el identificador único de la subred a la que pertenecen los hosts.

* 4 Cálculo de la Broadcast Address:

La Broadcast Address es la dirección de red que se utiliza para enviar paquetes a todos los hosts de la subred. Para calcularla, necesitamos saber el Network ID y la cantidad de hosts disponibles en la subred.

En el ejemplo que estamos trabajando, ya hemos calculado el Network ID como 192.168.1.0. La cantidad de hosts disponibles se calcula como 2^(n) – 2, donde n es la cantidad de bits utilizados para representar la parte de host en la máscara de red. En este caso, n es igual a 6, ya que hay 6 bits disponibles para la parte de host.

Para calcular la Broadcast Address, debemos asignar todos los bits de la parte del host de la dirección IP a “1“. En este caso, la dirección IP es 192.168.1.0 y se convierte en binario como 11000000.10101000.00000001.00000000.

Para encontrar la dirección Broadcast, llenamos con unos la parte correspondiente a los bits de host, es decir, los últimos 6 bits:

11000000.10101000.00000001.00111111 (dirección IP con bits de host asignados a “1“)

Luego, convertimos este valor binario de regreso a decimal y obtenemos la dirección de Broadcast: 192.168.1.63. Esta es la dirección a la que se enviarán los paquetes para llegar a todos los hosts de la subred.

### Subnetting - Interpretación de los rangos de red que el cliente nos ofrece para auditar

Esta clase no consideramos que necesite material de apoyo, pues se abordan varios ejercicios prácticos con los que poder practicar y reforzar todo lo visto hasta ahora.

[Os dejamos por aquí la página web correspondiente al conversor de CIDR a IPv4](https://www.ipaddressguide.com/cidr)

Os animamos a que tratéis de practicar con muchos más ejemplos, es la única forma de hacer que todos estos conceptos os queden bien claros.

### Subnetting - Redes extrañas y casos particulares

En esta clase, vamos a terminar de rellenar los datos correspondientes a las direcciones IP que nos quedaron pendientes de la clase anterior. Asimismo, vamos a estar explicando un caso particular de redes extrañas, para que sepáis cómo proceder con su interpretación.

Trataremos de calcular para la notación 13.13.13.13/13 la máscara de red, el número total de hosts a repartir, el Network ID y la Broadcast Address.

Considerando todo lo aprendido hasta el momento, ¡ha llegado la hora de aplicar los conocimientos adquiridos! Demuestra que has comprendido los conceptos y que estás listo para avanzar, enfrentándote al cuestionario que se te presentará en la siguiente clase.

¡Mucha suerte!

[Tabla hecha con savitar](https://docs.google.com/spreadsheets/d/1aIeTBWYn7fueLlGtrbuIIT1KRxHKyOfigl_6BhG6-Dk/edit?usp=sharing)

### TIPS de subnetting y cálculo veloz de direccionamiento en redes

En esta clase, veremos algunas técnicas adicionales para calcular velozmente el Network ID, la máscara de red y la Broadcast Address, en base a una dirección IP y CIDR que el cliente nos pase. De esta forma, no será necesario hacer uso del Excel que previamente construimos, logrando tener en un menor tiempo los valores correspondientes a cada componente de direccionamiento.

A continuación, se proporciona el recurso que utilizamos en esta clase:

* [IP Calculator](https://docs.google.com/spreadsheets/d/1aIeTBWYn7fueLlGtrbuIIT1KRxHKyOfigl_6BhG6-Dk/edit?usp=sharing)

Ejemplo 1:

Ip dada por el cliente: 172.14.15.16/17

```bash
echo "obase=2;172" | bc
```

Representando la Ip en Binario:

10101100.00001110.00001111.00010000 (172.14.15.16)
11111111.11111111.10000000.00000000 (255.255.128.0) Máscara de Red
###########################
10101100.00001110.00000000.00000000 [AND] (172.14.0.0 - Network ID)

10101100.00001110.01111111.11111111 (172.14.127.255 - Broadcast Address)

Ejemplo 2:

Ip dada por el cliente: 192.112.114.29/13

```bash
echo "obase=2;192" | bc
```

Representando la Ip en Binario:

11000000.01110000.01110010.00011101 (192.112.114.29)
11111111.11111000.00000000.00000000 (255.248.0.0) Máscara de Red
###########################
11000000.011100000.00000000.00000000 [AND] (192.112.0.0 - Network ID)

11000000.01110111.11111111.11111111 (192.119.255.255 - Broadcast Address)

Ejemplo 3:

Ip dada por el cliente: 13.51.47.131/4

```bash
echo "obase=2;13" | bc
```

Representando la Ip en Binario:

00001101.00110011.00101111.10000011 (13.51.47.131)
11110000.00000000.00000000.00000000 (240.0.0.0) Máscara de Red
###########################
00000000.00000000.00000000.00000000 [AND] (0.0.0.0 - Network ID)

00001111.11111111.11111111.11111111 (15.255.255.255 - Broadcast Address)

Cuando un cliente nos hable de IP sepamos donde operar.

## Reconocimiento

### Nmap y sus diferentes modos de escaneo

Nmap es una herramienta de escaneo de red gratuita y de código abierto que se utiliza en prueba de penetración (pentesting) para explorar y auditar redes y sistemas informáticos.

Con Nmap, los profesionales de seguridad pueden identificar los hosts conectados a una red, los servicios que se están ejecutando en ellos y las vulnerabilidades que podrían ser explotadas por un atacante. La herramienta es capaz de detectar una amplia gama de dispositivos, incluyendo enrutadores, servidores web, impresoras, cámaras IP, sistemas operativos y otros dispositivos conectados a una red.

Asimismo, esta herrmienta posee una variedad de funciones y características avanzadas que permitan a los profesionales de seguridad adaptar la misma a sus necesidades específicas. Estas incluyen técnicas de escaneo agresivas, capacidades de scripting personalizadas, y un conjunto de herramientas auxiliares que pueden ser utilizadas para obtener información adicional sobre los host objetivo.

Un puerto puede estar: Abierto, cerrado o filtrado

```bash
route -n # Nos lista rutas
iwconfig # Nos lista las interfaces de nuestro equipo
ifconfig # Nos lista las interfaces de nuestro equipo
arp-scan -I ens33 --localnet # Enumerar dispositivos en la red

nmap -p1-100 192.168.1.1 # Rango de puertos a escanear
nmap -p- 192.168.1.1 # -p- se usa para englobar todos los puertos
nmap --top-ports 500 192.168.1.1 # Se usa para escanear los 500 puertos más comunes
nmap --top-port 500 --open 192.168.1.1 # Se usa solo para ver puertos abiertos en la consulta
nmap -p- --open 192.168.1.1 -v # -v se usa para mostrar el progreso del escaneo
nmap -p- --open 192.168.1.1 -v -n # -n se usa para negar la resolución DNS
nmap -p- -T5 --open 192.168.1.1 -v -n # -T5 indica la velocidad con la que queremos realizar el escaneo siendo 0, 1, 2, 3, 4, 5
nmap -p- -T5 -sT --open 192.168.1.1 -v -n # sT TCP connected scan, se establece el three way handshake típico, se lanza un SYN si un puerto esta cerrado nos regresa un RST, de lo contrario con un SYN, que es igual a que esta abierto, y de nuestro lado mandamos un ACK que es established

# Pasos para capturar el trafico y depositarlo en un archivo y luego jugar con wireshark
#Crear una captura con tcpdum
tcpdump -i ens33 -w Captura.cap -v # -v Verbose para ver el numero de paquetes que estoy capturando, -w write para escribir donde quiero depositar el contenido, -i es la interface de la que estamos haciendo el escaneo, damos a enter para capturar paquetes
nmap -p- -sT --open 192.168.1.1 -v -n # luego damos enter a la venta con esta consulta

# Cancelamos el analisis de la ventana con tcdump

# Jugamos con wireshark y abrimos la captura.cap
wireshark Captura.cap &>/dev/null & disown # redirigimos el stder y stdout al dev null y lo dejamos en segundo plano con disown

wireshark -r Captura.cap &> /dev/null & disown

# En busqueda podemos filtar por puertos con tcp.port == 22

nmap -p- -T5 --open 192.168.1.1 -v -n -Pn # Asume que todas la direcciones estan UP con -Pn

# Escaneando puertos UDP
nmap -p- --open -sU 192.168.1.1 -v -n -Pn # -sU para escanear puertos UDP
nmap -sn 192.168.1.0/24 # -sn para ver si el dispositivo esta encendido en la red local
nmap -sn 192.168.1.0/24 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1.3}\.\d{1,3}' # Con grep filtramos solo para ver las IPs
nmap -sn 192.168.1.0/24 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1.3}\.\d{1,3}' | sort # Con sort ordenamos las IPs

nmap -p22,80 -sV 192.168.1.1 # -sV para realizar un escaneo de versiones

```

### Técnicas de evasión de Firewalls (MTU, Data, Length, Source Port, Decoy, etc.)

Cuando se realizan pruebas de penetracion, uno de los mayores desafios es evadir la deteccion de Firewalls, que son disenados para proteger las redes y sistemas de posibles amenazas. Para superar este obstaculo, Nmap ofrece variedad de tecnicas de evasion que permiten a los profesionales de seguridad realizar escaneos sigilosos y evitar asi la deteccion de los mismos.

Algunos de los parametros vistos en esta clase son los siguientes:

* MTU (-mtu): La tecnica de evasion de MTU o "Maximum Transmission Unit" implica ajustar el tamano de los paquetes que se envian para evitar la deteccion por parte del Firewall. Nmap permite configurar manualmente el tamano maximo de los paquetes para garantizar que sean lo suficientemente pequenos para pasar por el Firewall sin ser detectados.

```bash
nmap -p22 192.168.1.1 --mtu 8 # El numero debe ser multiplo de 8
```

* Data Length (-data-length): Esta tecnica se basa en ajustar la longitud de los datos enviados para que sean lo suficientemente cortos como para pasar por el Firewall sin ser detectados. Nmap permite a los usuarios configurar manualmente la longitud de los datos enviados para que sean lo suficientemente pequenos para evadir la deteccion del Firewall.

Nmap siempre manda solicitudes con tamano de paquetes de 58, asi los firewall detectan que hay reconocimiento con nmap

```bash
nmap -p22 192.168.1.1 --data-length 21 # 58+21
```

* Source Port (-source-port): Esta tecnica consiste en configurar manualmente el numero de puerto de origen de los paquetes enviados para evitar la deteccion por parte del Firewall. Nmap permite a los usuarios especificar manualmente un puerto de origen aleatorio o un puerto especifico para evadir la deteccion del Firewall.

```bash
nmap -p22 192.168.1.1 --source-port 53 # Este comando abre el puerto 53 de nuestro equipo para comunicarnos con el 22, este comando es util cuando por firewall solo hay puertos especificados desde los que debe venir una solicitud

# Filtros en Wireshark
tpc.port == 22 # Filtro por puerto
```

* Decoy (-D): Esta tecnica de evasion en Nmap permite al usuario enviar paquetes falsos a la red para confundir a los sistemas de deteccion de intrusos y evitar la deteccion del Firewall. El comando -D permite al usuario enviar paquetes falsos junto con los paquetes reales de escaneo para ocultar su actividad.

```bash
nmap -p22 192.168.1.1 -D 192.168.1.20 # Util cuando no queremos que descubra que IP lanzo el reconocimiento, o cuando el firewall tiene a IPs especificas para ver los puertos filtrados como abiertos.

# Filtros en Wireshark
ip.dst == 192.168.1.1 # En wireshark buscamos los paquetes con ip destino
```

* Fragmented (-f): Esta tecnica se basa en fragmentar los paquetes enviados para que el Firewall no pueda reconocer el trafico como un escaneo. La opcion -f en Nmap permite fragmentar los paquetes y enviarlos por separado para evitar la deteccion del Firewall.

```bash
nmap -p22 192.168.1.1 -f

# Filtros en Wireshark
ip.flags.mf == 1 # Filtrar por paquetes fragmentados
```

* Spoof-Mac (-spoof-mac): Esta tecnica de evasion se base en cambiar la direccion MAC del paquete para evitar la deteccion del Firewall. Nmap permite al usuario configurar manualmente la direccion MAC para evitar ser detectado por el Firewall.

```bash
nmap -p22 192.168.1.1 --spoof-mac Dell
```

* Stealth Scan (-sS): Esta tecnica es una de las mas utilizadas para realizar escaneos sigilosos y evitar la deteccion del Firewall. El comando -sS permite a los usuarios realizar un escaneo de tipo SYN sin establecer una conexion completa, lo que permite evitar la deteccion del Firewall.

SYN > (RST (Closed)) > SYN/ACK > ACK
SYN > SYN/ACK > RST

```bash
nmap -p --open -sS --min-rate 5000 -v -n -Pn 192.168.1.1 # Recomendacion savitar
```

* min-rate(-min-rate): Esta tecnica permite al usuario controlar la velocidad de los paquetes enviados para evitar la deteccion del Firewall. El comando -min-rate permite al usuario reducir la velocidad de los paquetes enviados para evitar ser detectado por el Firewall.

Es importante destacar que, ademas de las tecnicas de evasion mencionadas anteriormente, existen muchas otras opciones en Nmap que pueden ser utilizadas para realizar pruebas de penetracion efectivas y evadir la deteccion del Firewall. Sin embargo, las tecnicas que hemos mencionado son algunas de las mas populares y ampliamente utilizadas por los profesionales de seguridad para superar los obstaculos que presentan los Firewalls en la realizacion de pruebas de penetracion.

### Uso de scripts y categorias en nmap para aplicar reconocimiento

Una de las categorias mas poderosas de Nmap es su capacidad para automatizar tareas utilizando scripts personalizados. Los scripts de Nmap permiten a los profesionales de seguridad automatizar las tareas de reconocimiento y descubrimiento en la red, ademas de obtener informacion valiosa sobre los sistemas y servicios que se estan ejecutando en ellos. El parametro --scrip de Nmap permite al usuario seleccionar un conjunto de scripts para ejecutar en un objetivo de escaneo especifico.

Existen diferentes categorias de scripts disponibles en Nmap, cada una disenada para realizar una tarea especifica. Algunas de las categorias mas comunes incluyen:

* default: Esta es la categoria predeterminada en Nmap, que incluye una gran cantidad de scripts de reconocimiento basicos y utiles para la mayoria de los escaneo.

* discovery: Esta categoria se enfoca en descubrir informacion sobre la red, como la deteccion de hosts y dispositivos activos, y la resolucion de nombres de dominio.

* safe: Esta categoria incluye scripts que son considerados seguros y que no realizan actividades invasivas que puedan desencadenar una alerta de seguridad en la red.

* intrusive: Esta categoria incluye scripts mas invasivos que pueden ser detectados facilmente por un sistema de deteccion de intrusos o un Firewall, pero que pueden proporcionar informacion valiosa sobre vulnerabilidades y debilidades en la red.

* vuln: Esta categoria se enfoca especificamente en la deteccion de vulnerabilidades y debilidades en los sistemas y servicios que se estan ejecutando en la red.

En conclusion, el uso de scripts y categorias en Nmap es una forma efectiva de automatizar tareas de reconocimiento y descubrimiento en la red. El parametro -script permite al usuario seleccionar un conjunto de scripts personalizados para ejecutar en un objetivo de escaneo especifico, mientras que las diferentes categorias disponibles en Nmap se enfocan en realizar tareas especificas para obtener informacion valiosa sobre la red.

```bash
locate .nse # Para buscar los scripts de nmap
locate .nse | xargs grep "categories"

nmap -p22 192.168.1.1 -sC # Hace un escaneo con los scripts mas significativos
nmap -p22 192.168.1.1 -sC -sV # Puede ser compactado como -sCV
nmap -p22 192.168.1.1 -sCV

nmap -p22 192.168.1.1 --script='vuln and safe' # ejecuta scripts de esa categoria
nmap -p80 192.168.1.1 --script http-enum #
```

### Creación de tus propios scripts en Lua para nmap (skip)

Nmap permite a los profesionales de seguridad personalizar y extender sus capacidades mediante la creación de scripts personalizados en el lenguaje de programación Lua. Lua es un lenguaje de scripting simple, flexible y poderoso que es fácil de aprender y de usar para cualquier persona interesada en crear scripts personalizados para Nmap.

Para utilizar Lua como un script personalizado en Nmap, es necesario tener conocimientos básicos del lenguaje de programación Lua y comprender la estructura básica que debe tener el script. La estructura básica de un script de Lua en Nmap incluye la definición de una tabla, que contiene diferentes campos y valores que describen la funcionalidad del script.

Los campos más comunes que se definen en la tabla de un script de Lua en Nmap incluyen:

* description: Este campo se utiliza para proporcionar una descripción corta del script y su funcionalidad.
* categories: Este campo se utiliza para especificar las categorías a las que pertenece el script, como descubrimiento, explotación, enumeración, etc.
* author: Este campo se utiliza para identificar al autor del script.
* license: Este campo se utiliza para especificar los términos de la licencia bajo la cual se distribuye el script.
* dependencies: Este campo se utiliza para especificar cualquier dependencia de biblioteca o software que requiera el script para funcionar correctamente.
* actions: Este campo se utiliza para definir la funcionalidad específica del script, como la realización de un escaneo de puertos, la detección de vulnerabilidades, etc.

Una vez que se ha creado un script de Lua personalizado en Nmap, se puede invocar utilizando el parámetro –script y el nombre del archivo del script. Con la creación de scripts personalizados en Lua, es posible personalizar aún más las capacidades de Nmap y obtener información valiosa sobre los sistemas y servicios en la red.

### Alternativas para la enumeracion de puertos usando descriptores de archivo (skip)

La enumeración de puertos es una tarea crucial en las pruebas de penetración y seguridad de redes. Tal y como hemos visto, Nmap es una herramienta de línea de comandos ampliamente utilizada para esta tarea, pero existen alternativas para realizar la enumeración de puertos de manera efectiva sin utilizar herramientas externas.

Una alternativa a la enumeración de puertos utilizando herramientas externas es aprovechar el poder de los descriptores de archivos en sistemas Unix. Los descriptores de archivo son una forma de acceder y manipular archivos y dispositivos en sistemas Unix. En particular, la utilizacion de /dev/tcp permite la conexion a un host y puerto específicos como si se tratra de un archivo en el sistema.

Para realizar la enumeración de puertos utilizando /dev/tcp en Bash, es posible crear un script que realice una conexión a cada puerto de interés y compruebe si el puerto está abierto o cerrado en función de si se puede enviar o recibir datos. Una forma de hacer esto es mediante el uso de comandos como "echo" o "cat", aplicando redireccionamiento al /dev/tcp. El código de estado devuelto por el comando se puede utilzar para determinar si el puerto está abierto o cerrado.

Aunque esta alternativa puede ser menos precisa y más lenta que el uso de herramientas especializadas como Nmap, es una opcion interesante y viable para aquellos que buscan una solución rápida y sencilla para la enumeración de puertos en sistemas Unix. Además, este enfoque puede proporcionar una mejor comprensión de cómo funcionan los descriptores de archivos en los sistemas Unix y cómo se pueden utilizar para realizar tareas de red.

### Descubrimiento de equipos en la red local (ARP e ICMP) y tips

El descubrimiento de equipos en la red local es una tarea fundamental en la gestión de redes y en las pruebas de seguridad. Existen diferentes herramientas y técnicas para realizar esta tarea, que van desde el escaneo de puertos hasta el análisis de tráfico de red.

En esta clase, nos enfocaremos en las técnicas de descubrimiento de equipos basadas en los protocolos ARP e ICMP. Además, se presentarán diferentes herramientas que pueden ser útiles para esta tarea, como Nmap, netdiscover, arp-scan y masscan.

Entre los modos de escaneo que se explican en la clase, se encuentran el uso del parámetro '-sn' de Nmap, que permite realizar un escaneo de hosts sin realizar el escaneo de puertos. También se presentan las herramientas netdiscover, arp-scan, que utilizan el protocolo ARP para descubrir hosts en la red.

Cada herramienta tiene sus propias ventajas y limitaciones. Por ejemplo, netdiscover es una herramienta simple y fácil de usar, pero puede ser menos precisa que arp-scan o masscan. Por otro lado, arp-scan y masscan son herramientas más potentes, capaces de descubrir hosts más rápido y en redes más grandes, pero también son más complejas y pueden requerir más recursos.

En definitiva, el descubrimiento de equipos en la red local es una tarea fundamental para cualquier administrador de redes o profesional de seguridad de la información. Con las técnicas y herramientas adecuadas, es posible realizar esta tarea de manera efectiva y eficiente.

```bash
hostname -I
ifconfig

namp -sn 192.168.0.0/24 # Investigamos por pingswip nos reporta que equipos estan activos como clientes

arp-scan -I ens33 --localnet # Nos reporta que equipos estan activos tambien, nos reporta duplicados

arp-scan -I ens33 --localnet --ignoredups # Ignora duplicados

ping -c 1 192.168.0.5

timeout 1 bash -c "ping -c 1 192.168.0.1" &>/dev/null # Si la ip no existe solo tardará un segundo en ejecutar el comando

echo $? # Nos devuelve el codigo de estado del comando anterior ejecutado, 0 es exitoso !0 es un error

timeout 1 bash -c "ping -c 1 192.168.0.1" &>/dev/null && echo "[+] El host está activo"
```

Creamos script para hacer un escaner de hosts activos en la red

hostDiscovery.sh

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n [!] Saliendo...\n"
    tput cnorm; exit 1
}

tput civis

# Ctrl + C
trap ctrl_c SIGINT

for i in $(seq 1 254); do
    timeout 1 bash -c "ping -c 1 192.168.0.$i" &>/dev/null && echo "[+] Host 192.168.0.$i -ACTIVE" &
done

wait

tput cnorm
```

hostDiscovery.sh contemplando que no hay ICMP

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n [!] Saliendo...\n"
    tput cnorm; exit 1
}

tput civis

# Ctrl + C
trap ctrl_c SIGINT

for i in $(seq 1 254); do

    for port in 21 22 23 25 80 139 443 445 8080; do
    
        timeout 1 bash -c "echo '' > /dev/tcp/192.168.0.$i/$port" &>/dev/null && echo "[+] Host 192.168.0.$i - Port $port (OPEN)" &
    done
done

wait

tput cnorm

#tester
```

### Validación del objetivo (Fijando un target en HackerOne)

En esta clase exploraremos la plataforma HackerOne, una plataforma de BugBounty que permite a empresas y organizaciones que desean ser auditadas, "Conectar" con hackers éticos para encontrar vulnerabilidades de seguridad en sus sistemas y aplicaciones de forma legal.

Antes de iniciar una auditoría en esta plataforma, es fundamental fijar un objetivo claro, además de definir el alcance de la auditoría. Esto se logra a través del concepto de "Scope", que establece los límites de la auditoría, así como los sistemas y aplicaciones que pueden ser auditados.

En esta clase, se explicará cómo validar un objetivo en HackerOne y cómo definir el alcance de la auditoría a través del Scope. Además, se discutirán los impedimentos y limitaciones que se pueden encontrar durante la fase de auditoría, evitando así posibles malentendidos durante el proceso de reporte de vulnerabilidades.

[Enlace a la web de HackerOne](https://www.hackerone.com/)

### Descubrimiento de correos electrónicos

En esta clase exploraremos la importancia de la recolección de información en la fase de OSINT durante una auditoría, en particular, la recolección de correos electrónicos. Los correos electrónicos pueden ser una valiosa fuente de información para la vulneración de posibles paneles de autenticación y la realización de campañas de Phishing.

Durante la clase se presentan diferentes herramientas online que pueden ayudar en este proceso. Por ejemplo, se explica cómo usar 'hunter.io' para buscar correos electrónicos asociados a un dominio en particular. También se muestra cómo utilizar 'intelx.io' para buscar información relacionada con direcciones de correo electrónico, nombres de usuarios y otros detalles.

Otra herramienta interesante que se presenta en la clase es 'phonebook.cz', que permite buscar correos electrónicos y otros datos de contacto relacionados con empresas de todo el mundo.

Finalmente, se habla sobre el plugin 'Clearbit Connect' para Gmail, que permite obtener información de contacto en tiempo real y añadirla directamente a los contactos de Gmail.

A continuación, se proporcionan los enlaces a las herramientas online vistas en esta clase:

[Hunter](https://hunter.io/)

[Intelligence X](https://intelx.io/)

[Phonebook.cz](https://phonebook.cz/)

[Clearbit Connect](https://hunter.io/)

En conclusión, la recolección de correos electrónicos es una tarea importante en la fase inicial de OSINT y puede proporcionar información valiosa. Sin embargo, es importante tener en cuenta que la recolección de correos electrónicos por sí sola no permite identificar directamente posibles vulnerabilidades en una red o sistema.

Validadores de correos existentes

[Email checker](https://email-checker.net/check)

[Verify email address](https://www.verifyemailaddress.org/)

COMO ATACANTE TU DEBES OBSESIONARTE CON LAS VICTIMAS, INVESTIGAR CUENTAS, DONDE ESTAN PARA CORRELACIONAR DATOS, PARA SABER QUE PUNTOS DE CONEXION PUEDEN UNIRSE

### Reconocimiento de imágenes

En esta clase, exploraremos cómo las tecnologías de reconocimiento de imágenes pueden ser utilizadas para obtener información valiosa sobre las personas y los lugares.

Una de las herramientas en línea que vemos en esta clase es 'PimEyes'. PimEyes es una plataforma en línea que utiliza tecnología de reconocimiento facial para buscar imágenes similares en Internet en función de una imagen que se le proporciona como entrada. Esta herramienta puede ser útil en la detección de información personal de una persona, como sus perfiles en redes sociales, direcciones de correo electrónico, números de teléfono, nombres y apellidos etc.

El funcionamiento de PimEyes se basa en el análisis de patrones faciales, que son comparados con una base de datos de imágenes para encontrar similitudes. La plataforma también permite buscar imágenes de personas que aparecen en una foto en particular, lo que puede ser útil en la investigación de casos de acoso o en la búsqueda de personas desaparecidas.

[Enlace a la web de PimEyes](https://pimeyes.com/en)

### Enumeración de subdominios

Importante: Recientemente, hemos notado un problema con la herramienta "sublist3r" del repositorio que presentamos en el vídeo: no está mostrando los subdominios del dominio que introduces durante el proceso de reconocimiento.

Aunque es probable que este error se corrija pronto, para quienes necesiten usar la herramienta sin inconvenientes en este momento, os sugiero descargarla desde este repositorio alternativo:

[Sublist3r](https://github.com/huntergregal/Sublist3r)

La enumeración de subdominios es una de las fases cruciales en la seguridad informática para identificar los subdominios asociados a un dominio principal.

Los subdominios son parte de un dominio más grande y a menudo están configurados para apuntar a diferentes recursos de la red, como servidores web, servidores de correo electrónico, sistemas de bases de datos, sistemas de gestión de contenido, entre otros.

Al identificar los subdominios vinculados a un dominio principal, un atacante podría obtener información valiosa para cada uno de estos, lo que le podría llevar a encontrar **vectores de ataque potenciales**. Por ejemplo, si se identifica un sobdminio que apunta a un servidor web vulnerable, el atacante podría utilizar esta información para intentar explotar la vulnerabildidad y acceder al servidor en cuestión.

Existen diferentes herramientas y técnicas para la enumeración de subdominios, tanto pasivas como activas. Las **herramientas pasivas** permiten obtener información sobre los subdominios sin enviar ninguna solicitud a los servidores identificados, mientras que las **herramientas activas** envían solicituddes a los servidores identificados para encontrar subdominios bajo el dominio principal.

Algunas de las **herramientas pasivas** más utilizadas para la enumeración de subdominios incluyen la búsqueda en motores de búsqueda como Google, Bing o Yahoo, y la búsqueda en registros DNS públicos como **PassiveTotal** o **Censys**. Estas herramientas permiten identificar subdominios asociados con un dominio, aunque no siempre son exhaustivas. Además, existen herramientas como **CTFR** que utilizan registros de certificados **SSL/TLS** para encontrar subdominios asociados a un dominio.

También se pueden utilizar páginas online como **Phonebook.cz** e **Intelx.io**, o herramientas como **sublist3r**, para buscar información relacionada con los dominios, incluyendo subdominios.

Por otro lado, las **herramientas activas** para la enumeración de subdominios incluyen herramientas de fuzzing como **wfuzz** o **gobuster**. Estas herramientas envían solicitudes a los servidores mediante ataques de fuerza bruta, con el objetivo de encontrar subdominios válidos bajo el dominio principal.

A continuación, os adjuntamos los enlaces a las herramientas vistas en esta clase:

[Phonebook (Herramienta pasiva)](https://phonebook.cz/)

[Intelx (Herramienta pasiva)](https://intelx.io/)

[CTFR](https://github.com/UnaPibaGeek/ctfr)

[Gobuster](https://github.com/OJ/gobuster)

[Wfuzz](https://github.com/xmendez/wfuzz)

[Sublist3r](https://github.com/huntergregal/Sublist3r)

### Credenciales y brechas de seguridad

La seguridad de la información es un tema crítico en el mundo digital actual, especialmente cuando se trata de datos sensibles como **contraseñas, información financiera** o de **identidad**. Los ataques informáticos son una amenaza constante para cualquier empresa u organización, y una de las principales técnicas utilizadas por los atacantes es la **explotación de las credenciales** y **brechas de seguridad**.

Una de las formas más comunes en que los atacantes aprovechan las brechas de seguridad es mediante el uso de leaks de bases de datos. Estos leaks pueden ser el resultado de errores de configuración, vulnerabilidades en el software o ataques malintencionados. Cuando una base de datos se ve comprometida, los atacantes pueden acceder a una gran cantidad de información sensible, como nombres de usuario, contraseñas y otra información personal.

Una vez que los atacantes tienen acceso a esta información, pueden utilizarla para realizar ataques de fuerza bruta, phising y otros ataques de ingeniería social para acceder a sistemas y cuentas protegidas. En algunos casos, los atacantes pueden incluso vender esta información en el **mercado negro** para que otros atacantes la utilicen.

Es importante entender que muchas de estas bases de datos filtradas y vendidas en línea **son accesibles públicamente** y en algunos casos, incluso se venden por una pequeña cantidad de dinero. Esto significa que cualquier persona puede acceder a esta información y utilizarla para llevar a cabo ataques malintencionados.

A continuación, se proporciona el enlace a la utilidad online de ejemple que se muestra en esta clase:

[DeHashed](https://www.dehashed.com/)

### Identificación de las tecnologías en una página web

Desde el punto de vista de la seguridad, es fundamental conocer las **tecnologías** y **herramientas** que se utilizan en una página web. La identificación de estas tecnologías permite a los expertos en seguridad evaluar los riesgos potenciales de un sitio web, identificar vulnerabilidades y diseñar estrategias efectivas para proteger la información sensible y los datos críticos.

Existen diversas herramientas y utilidades en línea que permiten identificar las tecnologías utilizadas en una página web. Algunas de las herramientas más populares incluyen **Whatweb**, **Wappalyzer** y **builtwith.com**. Estas herramientas escanean la página web y proporcionan información detallada sobre las tecnologías utilizadas, como el lenguaje de programación, el servidor web, los sistemas de gestión de contenido, entre otros.

La herramienta **whatweb** es una utilidad de análisis de vulnerabilidades que escanea la página web y proporciona información detallada sobre las tecnologías utilizadas. Esta herramienta también puede utilizarse para identificar posibles vulnerabilidades y puntos débiles en la página web.

**Wappalyzer**, por otro lado, es una extensión del navegador que detecta y muestra las tecnologías utilizadas en la página web. Esta herramienta es especialmente útil para los expertos en seguridad que desean identificar rápidamente las tecnologías utilizadas en una página web sin tener que realizar un escaneo completo.

**Builtwith.com** es una herramienta en línea que también permite identificar las tecnologías utilizadas en una página web. Esta herramienta proporciona información detallada sobre las tecnologías utilizadas, así como también estadísticas útiles como el tráfico y la popularidad de la página web.

A continuación, os proporcionamos los enlaces correspondientes a las herramientas vistas en esta clase:

[Whatweb](https://github.com/urbanadventurer/WhatWeb)

[Wappalyzer](https://addons.mozilla.org/es/firefox/addon/wappalyzer/)

[Builtwith](https://builtwith.com/)

### Fuzzing y enumeración de archivos en un servidor web (1/2)

En esta clase, hacemos uso de las herramientas **Wfuzz** y **Gobuster** para aplicar **Fuzzing**. Está técnica se utiliza para descubrir rutas y recursos ocultos en un servidor web mediante ataques de fuerza bruta. El objetivo es encontrar recursos ocultos que podrían ser utilizados por atacantes malintencionados para obtener acceso no autorizado al servidor.

**Wfuzz** es una herramienta de descubrimiento de contenido y una herramienta de inyección de datos. Básicamente, se utiliza para automatizar los procesos de prueba de vulnerabilidades en aplicaciones web.

Permite realizar ataques de fuerza bruta en párametros y directorios de una aplicación web para identificar recursos existentes. Una de las **ventajas** de Wfuzz es que es altamente personalizable y se puede ajustar a diferentes necesidades de pruebas. Algunas de las **desventajas** de Wfuzz incluyen la necesidad de comprender la sintaxis de sus comandos y que puede parecer más lenta en comparación con otras herramientas de descubrimiento de contenido.

Por otro lado, **Gobuster** es una herramienta de descubrimiento de contenido que también se utiliza para buscar archivos y directorios ocultos en una aplicación web. Al igual que Wfuzz, Gobuster se basa en ataques de fuerza bruta para encontrar archivos y directorios ocultos. Una de las principales **ventajas** de Gobuster es su velocidad, ya que es conocida por ser una de las herramientas de descubrimiento de contenido más rápidas. También es fácil de usar y su sintaxis es simple. Sin embargo, una desventaja de Gobuster es que puede no ser tan personalizable como Wfuzz.

En resumen, tanto Wfuzz como Gobuster son herramientas útiles para pruebas de vulnerabilidades en aplicaciones web, pero tienen diferencias en su enfoque y características. La elección de una u otra dependerá de tus necesidades y preferencias personales.

A continuación, te proporcionamos el enlace a estas herramientas:

[Wfuzz](https://github.com/xmendez/wfuzz)

[Gobuster](https://github.com/OJ/gobuster)

```bash
./gobuster dir -u https://miwifi.com/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 # Ataque de fuerza bruta, con 200 hilos

./gobuster dir -u https://miwifi.com/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -b 403,404 # Ataque de fuerza bruta, con 200 hilos, contemplando un slah al final de la ruta

./gobuster dir -u https://miwifi.com/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x html -s 200 -b '' #
```

```bash

wfuzz --help

wfuzz -c -t 200 # 200 tareas en paralelo

wfuzz -c -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ # Para enumerar con un diccionario, colocamos la palabra FUZZ al final para sustituir ahi los intentos del diccionario

# Para cancelar aplica un Ctrl+C, despues un Ctrl+Z, lo cual deja la tarea en segundo plano, y al final aplica un kill % para finalizar las tareas en segundo plano

wfuzz -c --hc=404,403 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ # Ocultamos los codigos de estado 404

wfuzz -c --hc=404,403 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ/ # Ocultamos los codigos de estado 404

wfuzz -c --sl=216 --hc=404,403 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ/

wfuzz -c --hl=216 --hc=404,403 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ/

wfuzz -c --hl=216 --hc=404,403 -t 200 -z file,/usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt https://miwifi.com/FUZZ/

wfuzz -c --hl=216 --hc=404,403 -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,html-txt-php https://miwifi.com/FUZZ.FUZ2Z

wfuzz -c -t 200 -z range,1-20000 'https://www.mir.com/shop/buy/detail?product_id=FUZZ' # Para probar con lista de producto que existan
```

### Fuzzing y enumeración de archivos en un servidor web (2/2)

En esta clase, veremos cómo se pueden utilizar diferentes parámetros de **Wfuzz** para ajustar el alcance y la profundidad de nuestro reconocimiento en aplicaciones web. Algunos de los parámetros que cubriremos incluyen el parámetro '-sl', para filtrar por un número de líneas determinado, el parámetro '-hl' para ocultar un número de líneas determinado y por último el parámetro '-z' para indicar el tipo de dato que queremos usar de cara al reconocimiento que nos interese aplicar, abarcando opciones como diccionarios, listas y rangos numéricos.

Adicionalmente, otra de las herramientas que examinaremos en esta clase, perfecta para la enumeración de recursos disponibles en una plataforma en línea, es **Burpsuite**. BurpSuite es una plataforma que integra características especializadas para realizar pruebas de penetración en aplicaciones web. Una de sus particularidades es la función de **análisis de páginas en línea**, empleada para identificar y enumerar los recursos accesibles en una página web.

Burpsuite cuenta con dos versiones: Una versión gratuita (BurpSuite Community Edition) y una versión de pago (Burpsuite Professional).

#### Burpsuite Community Edition

Es la versión gratuita de esta plataforma, viene incluida por defecto en el sistema operativo. Su función principal es desempeñar el papel de **proxy HTTP** para la aplicación, facilitando la realización de pruebas de penetración.

Un proxy HTTP es un filtro de contenido de alto rendimiento, ampliamente usado en el hacking con el fin de interceptar el tráfico de red. Esto permite analizar, modificar, aceptar o rechazar todas las solicitudes y respuestas de la aplicación que se esté auditando.

Alguna de las ventajas que la versión gratuita ofrecen son:

* Gratuitidad: La versión Community Edition es gratuita, lo que la convierte en una opción accesible para principiantes y profesionales con presupuestos limitados.
* Herramientas básicas: Incluye las herramientas esenciales para realizar pruebas de penetración en aplicaciones web, como el Proxy, el Repeater y el Sequencer.
* Intercepción y modificación de tráfico: Permite interceptar y modificar las solicitudes y respuestas HTTP/HTTPS, facilitando la identificación de vulnerabilidades y la exploración de posibles ataques.
* Facilidad de uso: La interfaz de usuario de la Community Editio es intuitiva y fácil de utilizar, lo que facilita su adopción por parte de usuarios con diversos niveles de experiencia.
* Aprendizaje y familiarización: La versión gratuita permite a los usuarios aprender y familiarizarse con las funcionalidades y técnicas de pruebas de penetración antes de dar el salto a la versión Professional.
* Comunidad de usuarios: La versión Community cuenta con una amplia comunidad de usuarios que comparten sus conocimientos y experiencias en foros y blogs, lo que puede ser de gran ayuda para resolver problemas y aprender nuevas técnicas.

A pesar de que la Community Edition no ofrece todas las funcionalidades y ventajas de la versión Professional, sigue siendo una opción valiosa para aquellos que buscan comenzar en el ámbito de las pruebas de penetración o que necesitan realizar análisis de seguridad básicos sin incurrir en costos adicionales.

#### Burpsuite Professional

BurpSuite Proffessional es la versión de pago desarrollada por la empresa PortSwigger. Incluye, además del prox  y HTTP, algunas herramientas de pentesting web como:

* Escáner de seguridad automatizado: Permite identificar vulnerabilidades en aplicaciones web de manera rápida y eficiente, lo que ahorra tiempo y esfuerzo.
* Integración con otras herramientas: Puede integrarse con otras soluciones de seguridad y entornos de desarrollo para mejorar la eficacia de las pruebas.
* Extensibilidad: A través de su API, BurpSuite Professional permite a los usuarios crear y añadir extensiones personalizadas para adaptarse a necesidades específicas.
* Actualizaciones frecuentes: La versión profesional recibe actualizaciones periódicas que incluyen nuevas funcionalidades y mejoras de rendimiento.
* Soporte técnico: Los usuarios de BurpSuite Professional tienen acceso a un soporte técnico de calidad para resolver dudas y problemas.
* Informes personalizables: La herramienta permite generar informes detallados y personalizados sobre las pruebas de penetración y los resultados obtenidos.
* Interfaz de usuario intuitiva: La interfaz de BurpSuite Professional es fácil de utilizar y permite a los profesionales de seguridad trabajar de manera eficiente.
* Herramientas avanzadas: Incluye funcionalidades avanzadas, como el módulo de intrusión, el rastreador de vulnerabilidades y el generador de payloads, que facilitan la identificación y explotación de vulnerabilidades en aplicaciones web.

En conclusión, tanto la Community Edition como la versión Professional de BurpSuite ofrecen un conjunto de herramientas útiles y eficientes para realizar pruebas de penetración en aplicaciones web. Sin embargo, la versión Professional brinda ventajas adicionales.

La elección entre ambas versiones dependerá del alcance y las necesidades específicas del proyecto o de la empresa. Si se requiere un conjunto básico de herramientas para pruebas de seguridad ocasionales, la Community Edition podría ser suficiente. No obstante, si se busca una solución más completa y personalizable, con soporte técnico y herramientas avanzadas para un enfoque profesional y exhaustivo, la versión Professional sería la opción más adecuada.

```bash
go build -ldflags "-s -w" . # Para compilar archivo con menor peso
upx ffuf # Hacerlo aun menos pesado

./ffuf

./ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://miwifi.com/FUZZ

./ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://miwifi.com/FUZZ -v

./ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://miwifi.com/FUZZ/

./ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://miwifi.com/FUZZ/ --mc=200

```

### Google Dorks / Google Hacking (Los 18 Dorks más usados)

El ‘Google Dork‘ es una técnica de búsqueda avanzada que utiliza operadores y palabras clave específicas en el buscador de Google para encontrar información que normalmente no aparece en los resultados de búsqueda regulares.

La técnica de ‘Google Dorking‘ se utiliza a menudo en el hacking para encontrar información sensible y crítica en línea. Es una forma eficaz de recopilar información valiosa de una organización o individuo que puede ser utilizada para realizar pruebas de penetración y otros fines de seguridad.

Al utilizar Google Dorks, un atacante puede buscar información como nombres de usuarios y contraseñas, archivos confidenciales, información de bases de datos, números de tarjetas de crédito y otra información crítica. También pueden utilizar esta técnica para identificar vulnerabilidades en aplicaciones web, sitios web y otros sistemas en línea.

Es importante tener en cuenta que la técnica de Google Dorking no es ilegal en sí misma, pero puede ser utilizada con fines maliciosos. Por lo tanto, es crucial utilizar esta técnica con responsabilidad y ética en el contexto de la seguridad informática y el hacking ético.

```bash

site:tinder.com

site:tinder.com filetype:txt

site:tinder.com filetype:pdf

intext:tinder.com filetype:pdf

intext:tinder.com filetype:pdf

```

[pentestools.com](https://pentest-tools.com/)

[pentestools.com google dorks](https://pentest-tools.com/information-gathering/google-hacking)

```bash
wget enlace_archivo_pdf
exiftool rutadearchivopdf # Nos muestra los metadatos
```

[Exploit Database](https://www.exploit-db.com/)

Nosotros usaremos searchexploit para usar la herramienta por consola de Exploit Database

### Identificación y verificación externa de la versión del sistema operativo

El tiempo de vida (TTL) hace referencia a la cantidad de tiempo o “saltos” que se ha establecido que un paquete debe existir dentro de una red antes de ser descartado por un enrutador. El TTL también se utiliza en otros contextos, como el almacenamiento en caché de CDN y el almacenamiento en caché de DNS.

Cuando se crea un paquete de información y se envía a través de Internet, está el riesgo de que siga pasando de enrutador a enrutador indefinidamente. Para mitigar esta posibilidad, los paquetes se diseñan con una caducidad denominada tiempo de vida o límite de saltos. El TTL de los paquetes también puede ser útil para determinar cuánto tiempo ha estado en circulación un paquete determinado, y permite que el remitente pueda recibir información sobre la trayectoria de un paquete a través de Internet.

Cada paquete tiene un lugar en el que se almacena un valor numérico que determina cuánto tiempo debe seguir moviéndose por la red. Cada vez que un enrutador recibe un paquete, resta uno al recuento de TTL y lo pasa al siguiente lugar de la red. Si en algún momento el recuento de TTL llega a cero después de la resta, el enrutador descartará el paquete y enviará un mensaje ICMP al host de origen.

¿Qué tiene que ver esto con la identificación del sistema operativo? Bueno, resulta que diferentes sistemas operativos tienen diferentes valores predeterminados de TTL. Por ejemplo, en sistemas operativos Windows, el valor predeterminado de TTL es 128, mientras que en sistemas operativos Linux es 64.

Por lo tanto, si enviamos un paquete a una máquina y recibimos una respuesta que tiene un valor TTL de 128, es probable que la máquina esté ejecutando Windows. Si recibimos una respuesta con un valor TTL de 64, es más probable que la máquina esté ejecutando Linux.

Este método no es infalible y puede ser engañado por los administradores de red, pero puede ser útil en ciertas situaciones para identificar el sistema operativo de una máquina.

A continuación, se os comparte la página que mostramos en esta clase para identificar el sistema operativo correspondiente a los diferentes valores de TTL existentes.

[Subin’s Blog](https://subinsb.com/default-device-ttl-values/)

Asimismo, os compartimos el script de Python encargado de identificar el sistema operativo en función del TTL obtenido:

[WhichSystem](https://pastebin.com/HmBcu7j2)

```bash
nmap -O # Para ver el sistema operativo de manera muy agresiva

arp-scan -I ens33 --localnet --ignoredups
```

Investigar como manipular los ttl

Crear mi propio reconocedor de SO en bash y subirlo a github

### Cuestionario de reconocimiento

Agregar preguntas con sus respuestas

## Configuración de laboratorios locales en Docker

### Introducción a Docker

Docker es una plataforma de contenedores de software que permite crear, distribuir y ejecutar aplicaciones en entornos aislados. Esto significa que se pueden empaquetar las aplicaciones con todas sus dependencias y configuraciones en un contenedor que se puede mover fácilmente de una máquina a otra, independientemente de la configuración del sistema operativo o del hardware.

Algunas de las ventajas que se presentan a la hora de practicar hacking usando Docker son:

* Aislamiento: los contenedores de Docker están aislados entre sí, lo que significa que si una aplicación dentro de un contenedor es comprometida, el resto del sistema no se verá afectado.
* Portabilidad: los contenedores de Docker se pueden mover fácilmente de un sistema a otro, lo que los hace ideales para desplegar entornos vulnerables para prácticas de hacking.
* Reproducibilidad: los contenedores de Docker se pueden configurar de forma precisa y reproducible, lo que es importante en el hacking para poder recrear escenarios de ataque.

En las próximas clases, se mostrará cómo instalar Docker, cómo crear y administrar contenedores, y cómo usar Docker para desplegar entornos vulnerables para practicar hacking.

### Instalación de Docker en Linux

Para instalar Docker en Linux, se puede utilizar el comando “apt install docker.io“, que instalará el paquete Docker desde el repositorio de paquetes del sistema operativo. Es importante mencionar que, dependiendo de la distribución de Linux que se esté utilizando, el comando puede variar. Por ejemplo, en algunas distribuciones como CentOS o RHEL se utiliza “yum install docker” en lugar de “apt install docker.io“.

Una vez que Docker ha sido instalado, es necesario iniciar el demonio de Docker para que los contenedores puedan ser creados y administrados. Para iniciar el demonio de Docker, se puede utilizar el comando “service docker start“. Este comando iniciará el servicio del demonio de Docker, que es responsable de gestionar los contenedores y asegurarse de que funcionen correctamente.

Durante la clase, se mostrará cómo verificar que Docker ha sido instalado correctamente, además de comprobar si el demonio de Docker está en ejecución.

```bash
apt intall docker.io -y

service docker start

docker images

which docker

docker ps
```

### Definiendo la estructura básica de Dockerfile

Un archivo Dockerfile se compone de varias secciones, cada una de las cuales comienza con una palabra clave en mayúsculas, seguida de uno o más argumentos.

Algunas de las secciones más comunes en un archivo Dockerfile son:

* FROM: se utiliza para especificar la imagen base desde la cual se construirá la nueva imagen.
* RUN: se utiliza para ejecutar comandos en el interior del contenedor, como la instalación de paquetes o la configuración del entorno.
* COPY: se utiliza para copiar archivos desde el sistema host al interior del contenedor.
* CMD: se utiliza para especificar el comando que se ejecutará cuando se arranque el contenedor.

Además de estas secciones, también se pueden incluir otras instrucciones para configurar el entorno, instalar paquetes adicionales, exponer puertos de red y más.

En esta clase, se mostrará cómo crear un archivo Dockerfile desde cero, además de ver cómo utilizar las diferentes secciones y palabras clave para configurar la imagen. En la siguiente clase, veremos cómo construir y ejecutar un contenedor a partir de la imagen creada.

```bash

mkdir docker
cd !$
nvim DockerFile

FROM ubuntu:latest

MAINTEINER Marcelo Vazquez aka S4vitar "s4vitar@hack4u.io"

```

### Creación y construcción de imágenes

Para crear una imagen de Docker, es necesario tener un archivo Dockerfile que defina la configuración de la imagen. Una vez que se tiene el Dockerfile, se puede utilizar el comando “docker build” para construir la imagen. Este comando buscará el archivo ‘Dockerfile’ en el directorio actual y utilizará las instrucciones definidas en el mismo para construir la imagen.

Algunas de las instrucciones que vemos en esta clase son:

* docker build: es el comando que se utiliza para construir una imagen de Docker a partir de un Dockerfile.

La sintaxis básica es la siguiente:

➜ docker build [opciones] ruta_al_Dockerfile

El parámetro “-t” se utiliza para etiquetar la imagen con un nombre y una etiqueta. Por ejemplo, si se desea etiquetar la imagen con el nombre “mi_imagen” y la etiqueta “v1“, se puede usar la siguiente sintaxis:

➜ docker build -t mi_imagen:v1 ruta_al_Dockerfile

El punto (“.“) al final de la ruta al Dockerfile se utiliza para indicar al comando que busque el Dockerfile en el directorio actual. Si el Dockerfile no se encuentra en el directorio actual, se puede especificar la ruta completa al Dockerfile en su lugar. Por ejemplo, si el Dockerfile se encuentra en “/home/usuario/proyecto/“, se puede usar la siguiente sintaxis:

➜ docker build -t mi_imagen:v1 /home/usuario/proyecto/

* docker pull: es el comando que se utiliza para descargar una imagen de Docker desde un registro de imágenes.

La sintaxis básica es la siguiente:

➜ docker pull nombre_de_la_imagen:etiqueta

Por ejemplo, si se desea descargar la imagen “ubuntu” con la etiqueta “latest”, se puede usar la siguiente sintaxis:

➜ docker pull ubuntu:latest

* docker images: es el comando que se utiliza para listar las imágenes de Docker que están disponibles en el sistema.

La sintaxis básica es la siguiente:

➜ docker images [opciones]

Durante la construcción de la imagen, Docker descargará y almacenará en caché las capas de la imagen que se han construido previamente, lo que hace que las compilaciones posteriores sean más rápidas.

En la siguiente clase, veremos cómo desplegar contenedores en base a las imágenes que previamente hayamos creado.

```bash

docker build -t my_first_image . # Todo debe estar en minusculas

docker images # Nos mostraría las imágenes creadas

docker pull debian:latest # Tira de los registros de docker para instalar la máquina de debian

```

### Carga de instrucciones en Docker y desplegando nuestro primer contenedor

Ya habiendo construido en la clase anterior nuestra primera imagen, ¡ya estamos preparados para desplegar nuestros contenedores!

El comando “docker run” se utiliza para crear y arrancar un contenedor a partir de una imagen. Algunas de las opciones más comunes para el comando “docker run” son:

* “-d” o “–detach“: se utiliza para arrancar el contenedor en segundo plano, en lugar de en primer plano.
* “-i” o “–interactive“: se utiliza para permitir la entrada interactiva al contenedor.
* “-t” o “–tty“: se utiliza para asignar un seudoterminal al contenedor.
* “–name“: se utiliza para asignar un nombre al contenedor.

Para arrancar un contenedor a partir de una imagen, se utiliza el siguiente comando:

➜ docker run [opciones] nombre_de_la_imagen

Por ejemplo, si se desea arrancar un contenedor a partir de la imagen “mi_imagen“, en segundo plano y con un seudoterminal asignado, se puede utilizar la siguiente sintaxis:

➜  docker run -dit mi_imagen

Una vez que el contenedor está en ejecución, se puede utilizar el comando “docker ps” para listar los contenedores que están en ejecución en el sistema. Algunas de las opciones más comunes son:

* “-a” o “–all“: se utiliza para listar todos los contenedores, incluyendo los contenedores detenidos.
* “-q” o “–quiet“: se utiliza para mostrar sólo los identificadores numéricos de los contenedores.

Por ejemplo, si se desea listar todos los contenedores que están en ejecución en el sistema, se puede utilizar la siguiente sintaxis:

➜  docker ps -a

Para ejecutar comandos en un contenedor que ya está en ejecución, se utiliza el comando “docker exec” con diferentes opciones. Algunas de las opciones más comunes son:

* “-i” o “–interactive“: se utiliza para permitir la entrada interactiva al contenedor.
* “-t” o “–tty“: se utiliza para asignar un seudoterminal al contenedor.

Por ejemplo, si se desea ejecutar el comando “bash” en el contenedor con el identificador “123456789“, se puede utilizar la siguiente sintaxis:

➜ docker exec -it 123456789 bash

En la siguiente clase, veremos algunos de los comandos mayormente usados para la gestión de contenedores.

```bash
docker images

cat Dockerfile

docker run -dit --name myContainer my_first_image #d para dejar en segundo plano, i interactive para poderme conectar a una consola virtual con t

asdfaf34r34rsadf435t345sdfasf345q34024903

docker ps

docker exec -it myContainer bash

root@asdfaf34r34rsadf435t345sdfasf345q34024903:/# hostname -I
root@asdfaf34r34rsadf435t345sdfasf345q34024903:/# apt update
root@asdfaf34r34rsadf435t345sdfasf345q34024903:/# apt install net-tools -y
root@asdfaf34r34rsadf435t345sdfasf345q34024903:/# apt install iputils-ping -y

docker ps

nano DockerFile

FROM ubuntu:latest

MAINTEINER Marcelo Vazquez aka S4vitar "s4vitar@hack4u.io"

RUN apt update && apt install -y net-tools \
    iputils-ping \
    curl \
    git \
    nano \


docker build -t my_first_image:v2 . # Para correr otra mv

docker images

docker ps

docker run -dit --name mySecondContainer my_first_image:v2
docker ps

docker exec -it mySecondContainer bash

```

### Comandos comunes para la gestión de contenedores

A continuación, se detallan algunos de los comandos vistos en esta clase:

* docker rm $(docker ps -a -q) –force: este comando se utiliza para eliminar todos los contenedores en el sistema, incluyendo los contenedores detenidos. La opción “-q” se utiliza para mostrar sólo los identificadores numéricos de los contenedores, y la opción “–force” se utiliza para forzar la eliminación de los contenedores que están en ejecución. Es importante tener en cuenta que la eliminación de todos los contenedores en el sistema puede ser peligrosa, ya que puede borrar accidentalmente contenedores importantes o datos importantes. Por lo tanto, se recomienda tener precaución al utilizar este comando.
* docker rm id_contenedor: este comando se utiliza para eliminar un contenedor específico a partir de su identificador. Es importante tener en cuenta que la eliminación de un contenedor eliminará también cualquier cambio que se haya realizado dentro del contenedor, como la instalación de paquetes o la modificación de archivos.
* docker rmi $(docker images -q): este comando se utiliza para eliminar todas las imágenes de Docker en el sistema. La opción “-q” se utiliza para mostrar sólo los identificadores numéricos de las imágenes. Es importante tener en cuenta que la eliminación de todas las imágenes de Docker en el sistema puede ser peligrosa, ya que puede borrar accidentalmente imágenes importantes o datos importantes. Por lo tanto, se recomienda tener precaución al utilizar este comando.
* docker rmi id_imagen: este comando se utiliza para eliminar una imagen específica a partir de su identificador. Es importante tener en cuenta que la eliminación de una imagen eliminará también cualquier contenedor que se haya creado a partir de esa imagen. Si se desea eliminar una imagen que tiene contenedores en ejecución, se deben detener primero los contenedores y luego eliminar la imagen.

En la siguiente clase, veremos cómo aplicar port fowarding y cómo jugar con monturas. El port forwarding nos permitirá redirigir el tráfico de red desde un puerto específico en el host a un puerto específico en el contenedor, lo que nos permitirá acceder a los servicios que se ejecutan dentro del contenedor desde el exterior.

Las monturas, por otro lado, nos permitirán compartir un directorio o archivo entre el sistema host y el contenedor, lo que nos permitirá persistir la información entre ejecuciones de contenedores y compartir datos entre diferentes contenedores.

```bash
docker stop id
id
docker ps -a

docker rm id --force
docker ps -a

docker ps -a -q
docker rm $(docker ps -a -q)

docker rm $(docker ps -a -q) --force

docker rmi imagenes_hijo
docker rmi imagen_padre
docker rmi $(doker images -q)

```

### Port Forwarding en Docker y uso de monturas

El port forwarding, también conocido como reenvío de puertos, nos permite redirigir el tráfico de red desde un puerto específico en el host a un puerto específico en el contenedor. Esto nos permitirá acceder a los servicios que se ejecutan dentro del contenedor desde el exterior.

Para utilizar el port forwarding, se utiliza la opción “-p” o “–publish” en el comando “docker run“. Esta opción se utiliza para especificar la redirección de puertos y se puede utilizar de varias maneras. Por ejemplo, si se desea redirigir el puerto 80 del host al puerto 8080 del contenedor, se puede utilizar la siguiente sintaxis:

➜ docker run -p 80:8080 mi_imagen

Esto redirigirá cualquier tráfico entrante en el puerto 80 del host al puerto 8080 del contenedor. Si se desea especificar un protocolo diferente al protocolo TCP predeterminado, se puede utilizar la opción “-p” con un formato diferente. Por ejemplo, si se desea redirigir el puerto 53 del host al puerto 53 del contenedor utilizando el protocolo UDP, se puede utilizar la siguiente sintaxis:

➜ docker run -p 53:53/udp mi_imagen

Las monturas, por otro lado, nos permiten compartir un directorio o archivo entre el sistema host y el contenedor. Esto nos permitirá persistir la información entre ejecuciones de contenedores y compartir datos entre diferentes contenedores.

Para utilizar las monturas, se utiliza la opción “-v” o “–volume” en el comando “docker run“. Esta opción se utiliza para especificar la montura y se puede utilizar de varias maneras. Por ejemplo, si se desea montar el directorio “/home/usuario/datos” del host en el directorio “/datos” del contenedor, se puede utilizar la siguiente sintaxis:

➜ docker run -v /home/usuario/datos:/datos mi_imagen

Esto montará el directorio “/home/usuario/datos” del host en el directorio “/datos” del contenedor. Si se desea especificar una opción adicional, como la de montar el directorio en modo de solo lectura, se puede utilizar la opción “-v” con un formato diferente. Por ejemplo, si se desea montar el directorio en modo de solo lectura, se puede utilizar la siguiente sintaxis:

➜ docker run -v /home/usuario/datos:/datos:ro mi_imagen

En la siguiente clase, veremos cómo desplegar máquinas vulnerables usando Docker-Compose.

Docker Compose es una herramienta de orquestación de contenedores que permite definir y ejecutar aplicaciones multi-contenedor de manera fácil y eficiente. Con Docker Compose, podemos describir los diferentes servicios que componen nuestra aplicación en un archivo YAML y, a continuación, utilizar un solo comando para ejecutar y gestionar todos estos servicios de manera coordinada.

En otras palabras, Docker Compose nos permite definir y configurar múltiples contenedores en un solo archivo YAML, lo que simplifica la gestión y la coordinación de múltiples contenedores en una sola aplicación. Esto es especialmente útil para aplicaciones complejas que requieren la interacción de varios servicios diferentes, ya que Docker Compose permite definir y configurar fácilmente la conexión y la comunicación entre estos servicios.

```bash
nano DockerFile

FROM ubuntu:latest

MAINTEINER Marcelo Vazquez aka S4vitar "s4vitar@hack4u.io"

RUN apt update && apt install -y net-tools \
    iputils-ping \
    curl \
    git \
    nano \
    apache2 \
    php

EXPOSE 80

ENTRYPOINT service apache2 start



docker build -t webserver .

docker images

docker ps -a
docker images --filter "dangling=true"
docker images --filter "dangling=true" -q
docker rmi $(docker images --filter "dangling=true" -q)
Deleted: sha256:asdfa02020a020340f03240






nano DockerFile

FROM ubuntu:latest

MAINTEINER Marcelo Vazquez aka S4vitar "s4vitar@hack4u.io"

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y net-tools \
    iputils-ping \
    curl \
    git \
    nano \
    apache2 \
    php

EXPOSE 80

ENTRYPOINT service apache2 start && /bin/bash




docker build -t webserver .
docker images
docker run -dit -p 80:80 --name myWebServer webserver
docker ps
docker port myWebServer
```

### Despliegue de máquinas virtuales vulnerables con Docker-Compose(1/2)

AVISO: En caso de que veáis que no estáis pudiendo instalar ‘nano‘ o alguna utilidad en el contenedor, eliminad todo el contenido del archivo ‘/etc/apt/sources.list‘ existente en el CONTENEDOR y metedle esta línea:

[deb](http://archive.debian.org/debian/) jessie contrib main non-free

Posteriormente, haced un ‘apt update‘ y probad a instalar nuevamente la herramienta que queráis, ya no os debería de dar problemas.

Si estáis enfrentando dificultades con el contenedor de Elasticsearch y notáis que el contenedor no se crea después de ejecutar ‘docker-compose up -d‘, intentad modificar un parámetro del sistema con el siguiente comando en la consola:

* sudo sysctl -w vm.max_map_count=262144‘.

Después de hacerlo, intentad de nuevo ejecutar ‘docker-compose up -d‘, se debería solucionar el problema.

A continuación, os proporcionamos el enlace al proyecto de Github que estamos usando para esta clase:

* [Vulhub](https://github.com/vulhub/vulhub)

Asimismo, por aquí os compartimos el enlace al recurso donde se nos ofrece el script en Javascript encargado de establecer la Reverse Shell:

* [NodeJS Reverse Shell](https://github.com/appsecco/vulnerable-apps/tree/master/node-reverse-shell)

```bash
git clone https://github.com/vulhub/vulhub/tree/master/kibana/CVE-2018-17246 # Me dará error cambiar por

svn checkout https://github.com/vulhub/vulhub/trunk/kibana/CVE-2018-17246

docker-compose up -d
```

### Despliegue de máquinas virtuales vulnerables con Docker-Compose(2/2)

A continuación, os compartimos el enlace del proyecto correspondiente a la vulnerabilidad de ImageMagick (ImageTragick) que tocamos en esta clase:

[Proyecto de Github](https://github.com/vulhub/vulhub/tree/master/imagemagick/imagetragick)

### Cuestionario de Docker

Agregar preguntas con sus respuestas

## Enumeración de sevicios comunes y gestores de contenido

```bash

#!/bin/bash
#Colours

greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

ttl=$(ping $1 -c 1 | grep 'ttl=' | awk '{print $3}' FS='=' | awk '{print $1}' FS=' ')

clear

echo -e "${greenColour}[-------------------------------]${endColour}\n${blueColour}IP \t->${endColour} ${redColour}$1${endColour}\n${blueColour}TTL \t->${endColour} ${redColour}$ttl ${endColour}"

if [ $ttl -eq 30 ]; then
    echo -e "\tOS -> AIX"
    echo -e "\tOS -> DEC Pathworks"
    echo -e "\tOS -> HP-UX"
    echo -e "\tOS -> OSF/1"
    echo -e "\tOS -> Stratus"
    echo -e "\tOS -> Ultrix"
    echo -e "\tOS -> VMS/Wollongo ng"
fi

if [ $ttl -eq 32 ]; then
    echo -e "\tOS -> Windows"
fi

if [ $ttl -eq 60 ]; then
    echo -e "\tOS -> AIX"
    echo -e "\tOS -> Irix"
    echo -e "\tOS -> MacOS/MacTCP"
    echo -e "\tOS -> OSF/1"
    echo -e "\tOS -> Stratus"
    echo -e "\tOS -> SunOS"
    echo -e "\tOS -> Ultrix"
    echo -e "\tOS -> VMS/TCPware"
fi

if [ $ttl -eq 64 ]; then
    echo -e "\tOS -> Compa"
    echo -e "\tOS -> Foundry"
    echo -e "\tOS -> FreeBSD"
    echo -e "\tOS -> HP-UX"
    echo -e "\tOS -> Juniper"
    echo -e "\tOS -> Linux"
    echo -e "\tOS -> MacOS/MacTCP"
    echo -e "\tOS -> Netgear FVG318"
    echo -e "\tOS -> OS/2"
    echo -e "\tOS -> Solaris"
    echo -e "\tOS -> Stratus"
    echo -e "\tOS -> VMS/Multinet"
    echo -e "\tOS -> VMS/TCPware"
fi

if [ $ttl -eq 128 ]; then
    echo -e "\tOS -> VMS/Wollongo ng"
    echo -e "\tOS -> VMS/UCX"
    echo -e "\tOS -> Windows"
fi

if [ $ttl -eq 200 ]; then
    echo -e "\tOS -> MPE/IX (HP)"
fi

if [ $ttl -eq 254 ]; then
    echo -e "\tOS -> Cisco"
fi

if [ $ttl -eq 255 ]; then
    echo -e "\tOS -> AIX"
    echo -e "\tOS -> BSDI"
    echo -e "\tOS -> FreeBSD"
    echo -e "\tOS -> HP-UX"
    echo -e "\tOS -> Irix"
    echo -e "\tOS -> Linux"
    echo -e "\tOS -> NetBSD"
    echo -e "\tOS -> OpenBSD"
    echo -e "\tOS -> OpenVMS"
    echo -e "\tOS -> Solaris"
    echo -e "\tOS -> Stratus"
    echo -e "\tOS -> SunOS"
    echo -e "\tOS -> Ultrix"
fi

echo -e "${greenColour}[-------------------------------]${endColour}\n\n"

```

### Enumeración del servicio FTP

En esta clase, hablaremos sobre el protocolo de transferencia de archivos (FTP) y cómo aplicar reconocimiento sobre este para recopilar información.

FTP es un protocolo ampliamente utilizado para la transferencia de archivos en redes. La enumeración del servicio FTP implica recopilar información relevante, como la versión del servidor FTP, la configuración de permisos de archivos, los usuarios y las contraseñas (mediante ataques de fuerza bruta o guessing), entre otros.

A continuación, se os proporciona el enlace al primer proyecto que tocamos en esta clase:

[Docker-FTP-Server](https://github.com/garethflowers/docker-ftp-server)

```bash
# FILE ftp_server
docker run \
    --detach \
    --env FTP_PASS=iloveyou \
    --env FTP_USER=gerry \
    --env PUBLIC_IP=192.168.0.1 \
    --name my-ftp-server \
    --publish 20-21:20-21/tcp \
    --publish 40000-40009:40000-40009/tcp \
    --volume /data:/home/user \
    garethflowers/ftp-server

# Escaneamos la máquina con nmap
nmap -sCV -p21 127.0.0.1

#Hemos vulnerado esta máquina usando fuerza bruta con Hydra
hydra -l gerry -P pass.txt ftp://127.0.0.1 -t 10
```

Una de las herramientas que usamos en esta clase para el primer proyecto que nos descargamos es ‘Hydra‘. Hydra es una herramienta de pruebas de penetración de código abierto que se utiliza para realizar ataques de fuerza bruta contra sistemas y servicios protegidos por contraseña. La herramienta es altamente personalizable y admite una amplia gama de protocolos de red, como HTTP, FTP, SSH, Telnet, SMTP, entre otros.

El siguiente de los proyectos que utilizamos para desplegar el contenedor que permite la autenticación de usuarios invitados para FTP, es el proyecto ‘docker-anon-ftp‘ de ‘metabrainz‘. A continuación, se os proporciona el enlace al proyecto:

[Docker-ANON-FTP](https://github.com/metabrainz/docker-anon-ftp)

```bash
docker run -d -p 20-21:20-21 -p 65500-65515:65500-65515 -v /tmp:/var/ftp:ro inanimate/vsftpd-anon

# Revisamos que la máquina haya levantado
docker ps

# Una vez levantada la máquina procedo con el escaneo de puertos
nmap -sCV -p21 127.0.0.1

# Resultados
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Cant get directory listing: PASV IP 172.17.0.2 is not the same as 127.0.0.1
Service Info: Host: Welcome

# Nos damos cuenta que tiene el usuario anonymous permitido y nos conectamos
ftp 127.0.0.1 
# Nos responde
Connected to 127.0.0.1.
220 Welcome to an awesome public FTP Server
# Digitamos el usuario anonymous
Name (127.0.0.1:ethicalmachine): anonymous
# Introducimos la contraseña vacia
331 Please specify the password.
Password: 
# Obtenemos acceso
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

```bash
# Para cerrar los contenedores creados

docker ps
# Obtenemos solo los identificadores
docker ps -a -q
# Para borrar todos los contenedores abiertos usamos
docker rm $(docker ps -a -q) --force
# Volvemos a listar con docker ps y vemos que no hay contenedores en ejecución ya

# Listamos imagenes creadas
docker images
# Para borrar las imagenes creadas, vemos el identificador
docker rmi 48f8914e001b
# Listamos imagenes nuevamente y observamos que una imagen ha sido eliminada

```

### Enumeración del servicio SSH

En esta clase, exploraremos el protocolo SSH (Secure Shell) y cómo realizar reconocimiento para recopilar información sobre los sistemas que ejecutan este servicio.

SSH es un protocolo de administración remota que permite a los usuarios **controlar** y **modificar** sus servidores remotos a través de Internet mediante un mecanismo de **autenticación seguro**. Como una alternativa más segura al protocolo **Telnet**, que transmite información sin cifrar, SSH utiliza **técnicas criptográficas** para garantizar que todas las comunicaciones hacia y desde el servidor remoto estén cifradas.

SSH proporciona un mecanismo para autenticar un usuario remoto, transferir entradas desde el cliente al host y retransmistir la salida de vuelta al cliente. Esto es especialmente útil para administrar sistemas remotos de manera segura y eficiente, sin tener que estar físicamente presentes en el sitio.

A continuación, se os proporciona el enlace directo a la web donde copiamos todo el comando de 'docker' para desplegar nuestro contenedor:

[Docker Hub OpenSSH-Sever](https://hub.docker.com/r/linuxserver/openssh-server)

```bash
docker run -d \
  --name=openssh-server \
  --hostname=gerard-host \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true \
  -e USER_PASSWORD=iloveyou \
  -e USER_NAME=gerardo \
  -e LOG_STDOUT= `#optional` \
  -p 2222:2222 \
  -v /path/to/openssh-server/config:/config \
  --restart unless-stopped \
  lscr.io/linuxserver/openssh-server:latest

```

```bash
# Paso a paso de la máquina corrida con el comando anterior
docker ps

ssh gerardo@127.0.0.1 -p 2222
#introducimos clave iloveyou
nmap -p2222 -v -sV 127.0.0.1
# RESULTADOS
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-27 20:00 CST
NSE: Loaded 46 scripts for scanning.
Initiating Ping Scan at 20:00
Scanning 127.0.0.1 [2 ports]
Completed Ping Scan at 20:00, 0.00s elapsed (1 total hosts)
Initiating Connect Scan at 20:00
Scanning localhost (127.0.0.1) [1 port]
Discovered open port 2222/tcp on 127.0.0.1
Completed Connect Scan at 20:00, 0.00s elapsed (1 total ports)
Initiating Service scan at 20:00
Scanning 1 service on localhost (127.0.0.1)
Completed Service scan at 20:00, 0.18s elapsed (1 service on 1 host)
NSE: Script scanning 127.0.0.1.
Initiating NSE at 20:00
Completed NSE at 20:00, 0.00s elapsed
Initiating NSE at 20:00
Completed NSE at 20:00, 0.01s elapsed
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00013s latency).

#APLICAMOS FUERZA BRUTA CON HYDRA
hydra -l gerardo -P pass.txt ssh://127.0.0.1 -s 2222
#RESULTADOS
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-27 19:59:30
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 250 login tries (l:1/p:250), ~16 tries per task
[DATA] attacking ssh://127.0.0.1:2222/
[2222][ssh] host: 127.0.0.1   login: gerardo   password: iloveyou
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-27 20:00:02

```

Cabe destacar que a través de la versión de SSH, también podemos identificar el codename de la distribución que se está ejecutando en el sistema.

Por ejemplo, si la versión del servidor SSH es "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", podemos determinar que el sistema está ejecutando una distribución de Ubuntu. El número de versión "4buntu0.5" se refiere a la revisión específica del paquete de SSH en esa distribución de Ubuntu. A partir de esto, podemos identificar el **codename** de la distribución de Ubuntu, que en este caso sería "Focal" para Ubuntu 20.04.

Todas estas búsquedas las aplicamos sobre el siguiente dominio:

[Launchpad](https://launchpad.net/ubuntu)

```bash
# Contruimos una imagen nueva para revisar el codename y hacer reconocimiento
nano Dockerfile

FROM ubuntu:14.04

MAINTAINER Jose Gerardo Salvador Perez Sanchez

EXPOSE 22

RUN apt update && apt install -y net-tools \
    iputils-ping \
    curl \
    git \
    nano \
    ssh

ENTRYPOINT service ssh start && /bin/bash

#GUARDAMOS CTRL S
docker run -dit -p22:22 --name mySSHServer my_ssh
nmap -sCV -p22 localhost

#RESULTADOS
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-27 20:27 CST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00020s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 8b:1a:1b:a9:81:e9:6b:34:ca:d9:1d:2d:5d:21:76:5b (DSA)
|   2048 88:2f:99:e4:78:6d:d0:00:19:74:5a:3e:9a:b8:5b:d8 (RSA)
|   256 50:57:fd:27:70:76:d9:77:98:32:0a:3b:4f:46:4c:ed (ECDSA)
|_  256 cf:00:31:50:10:70:c8:ff:c2:18:bb:d9:d2:db:60:d0 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds

#Especificamente notamos la linea de escaneo 22/tcp
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)

# Para saber la version en la que estamos buscamos en google 
OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 # mas la palabra launchpad
```

### Enumeración del servicio HTTP y HTTPS

HTTP (Hypertext Transfer Protocol) es un protocolo de comunicación utilizado para la transferencia de datos en la World Wide Web. Se utiliza para la transferencia de contenido de texto, imágenes, vídeos, hipervínculos, etc. El puerto predeterminado para HTTP es el puerto 80.

HTTPS (Hypertext Transfer Protocol Secure) es una versión segura de HTTP que utiliza SSL / TLS para cifrar la comunicación entre el cliente y el servidor. Utiliza el puerto 443 por defecto. La principal diferencia entre el HTTP y HTTPS es que HTTPS utiliza una capa de seguridad adicional para cifrar los datos, lo que los hace más seguros para la transferencia.

Una de las herramientas que vemos en esta clase para inspeccionar el certificado SSL es 'Openssl'. OpenSSL es una biblioteca de software libre y de código abierto que se utiliza para implementar protocolos de seguridad en línea, como TLS (Transport Layer Security), SSL(Secure Sockets Layer). La biblioteca OpenSSL proporciona una implementación de estos protocolos para permitir que las aplicaciones se comuniquen de manera segura y encriptada a través de la red.

Uno de los comandos que vemos en esta clase haciendo uso de esta herramienta es el siguiente:

```bash
openssl s_client -connect ejemplo.com:443
```

Con este comando, podemos inspeccionar el certificado SSL de un servidor web. El comando se conecta al servidor en el puerto 443 y muestra información detallada sobre el certificado SSL, como la validez del certificado, la fecha de caducidad, el tipo de cifrado, etc.

Asimismo, otras de las herramientas que vemos en esta clase son 'sslyze' y 'sslscan'.

* Sslyze es una herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servido. Proporciona información detallada sobre el cifrado utilizado, los protocolos admitidos y los certificados SSL.
* SSLScan es otra herramienta de análisis de seguridad SSL que se utiliza para evaluar la configuración SSL de un servidor. Proporciona información detallada sobre los protocolos SSL/TLS admitidos, el cifrado utilizado y los certificados SSL.

La principal diferencia entre sslyze y sslscan se enfoca en la evaluación de la seguridad SSL/TLS un servidor web mediante una exploración exhaustiva de los protocolos y configuraciones SSL/TLS, mientras que sslscan se enfoca en la identificacion de los protocolos SSL/TLS admitidos por el servidor y los cifrados utilizados.

La identificación de las informaciones arrojadas por las herramientas de análisis SSL/TLS es de suma importancia, ya que nos puede permitir detectar vulnerabilidades en la configuración de un servidor y tomar medidas para proteger nuestra información confidencial.

Por ejemplo, Heartbleed es una vulnerabilidad de seguridad que afecta a la biblioteca OpenSSL y permite a los atacantes acceder a la memoria de un servidor vulnerable. Si un servidor web es vulnerable a Heartbleed y lo detectamos a través de estas herramientas, esto significa que un atacante podría potencialmente acceder a información confidencial, como claves privadas, nombres de usuario y contraseñas, etc.

A continuación, se proporciona el enlace al proyecto de GitHub donde desplegamos el laboratorio vulnerable a Heartbleed:

[CVE-2014-0160](https://github.com/vulhub/vulhub/tree/master/openssl/CVE-2014-0160)

Savitar comenta que la enumeracion de http y https tenemos herramientas ya usadas como:

* whatweb
* wfuzz
* fuff
* gobuster
* dirb
* dirbuster
* dirsearch

Lo primero que hace en la pagina de tinder es ver el candado, lo pincha, le da a conexion segura, mas informacion, view certificate.

Revisa el certificado en el apartado Common Name, checa si tiene subdominios

Revisa el Log Id y el nombre, comenta que el Let's encrypt, el cual te habilita gratuitamente el candado verde para que parezca segura, pero es un error de seguridad

Empieza a usar herramientas de cli

```bash
openssl s_client -connect tinder.com:443 # Revisa la información mostrada, es otra forma de inspeccionar el certificado

sslyze tinder.com # Analizamos el certificado tambien

sslscan tinder.com # Nos muestra los protocolos habilitados y las vulnerabilidades que podría presentar
```

EJERCICIO

Nos vamos al enlace de vulhub

```bash
#Nos clonamos el repositorio
svn checkout https://github.com/vulhub/vulhub/trunk/openssl/CVE-2014-0160
cd E

```

### Enumeración del servicio SMB

SMB significa Server Message Block, es un protocolo de comunicación de red utilizado para compartir archivos, impresoras y otros recursos entre dispositivos de red. Es un protocolo propietario de Microsoft que se utiliza en sistemas operativos Windows.

Samba, por otro lado, es una implementación libre y de código abierto del protocolo SMB, que se utiliza principalmente en sistemas operativos basados en Unix y Linux. Samba proporciona una manera de compartir archivos y recursos entre dispositivos de red que ejecutan sistemas operativos diferentes, como Windows y Linux

Aunque SMB y Samba comparten una funcionalidad similar, existen algunas diferencias notables. SMB es un protocolo propietario de Microsoft, mientras que Samba es un proyecto de software libre y de código abierto. Además, SMB es una implementación más completa y compleja del protocolo, mientras que Samba es una implementación más ligera y limitada.

A continuación, se os comparte el enlace correspondiente al proyecto de Github que utilizamos para desplegar un laboratorio de práctica con el que poder enumerar y explotar el servicio Samba:

[Samba Authenticated RCE](https://github.com/vulhub/vulhub/tree/master/samba/CVE-2017-7494)

Una de las herramientas que utilizamos para la fase de reconocimiento es 'smbmap'. Smbmap es una herramienta de línea de comandos utilizada para enumerar recursos compartidos y permisos en un servidor SMB (Server Message Bloc) o Samba. Es una herramienta muy útil para la enumeración de redes y para la identificación de posibles vulnerabilidades de seguridad.

Con smbmap, puedes enumerar los recursos compartidos en un servidor SMB y obtener información detallada sobre cada recurso, como los permisos de acceso, los usuario y grupos autorizados, y los archivos y carpetas compartidos. También puedes utilizar smbmap para identificar recursos compartidos que no requieren autenticación, lo que puede ser un problema de seguridad.

Además, smbmap permite a los administradores de sistemas y a los auditores de seguridad verificar rápidamente la configuración de permisos en los recursos compartidos en un servidor SMB, lo que puede ayudar a identificar posibles vulnerabilidades de seguridad y a tomar medidas para remediarlas.

A continuación, se proporciona una breve descripción de algunos de los parámetros comunes de smbmap:

* -H: Este parámetro se utiliza para especificar la dirección IP o el nombre de host del servidor SMB al que se quiere conectar.
* -P: Este parámetro se utiliza para especificar el puerto TCP utilizado para la conexión SMB. El puerto predeterminado para SMB es el 445, pero si el servidor SMB está configurado para utilizar un puerto diferente, este parámetro debe ser utilizado para especificar el puerto correcto.
* -u: Este parámetro se utiliza para especificar el nombre de usuario para la conexión SMB.
* -p: Este parámetro se utiliza para especificar la contraseña para la conexión SMB.
* -s: Este parámetro se utiliza para especificar el recurso compartido específico que se quiere enumerar. Si no se especifica, smbmap intentará enumerar todos los recursos compartidos en el servidor SMB.

Asimismo, otra de las herramientas que se ven en esta clase es 'smbclient'. Smbclient es otra herramienta de línea de comandos utilizada para interactuar con servidores SMB y Samba, pero a diferencia de smbmap que se utiliza principalmente para enumeración, smbclient proporciona una interfaz de línea de comandos para interactuar con los recursos compartidos SMB y Samba, lo que permite la descarga y subida de archivos, la ejecución de comandos remotos, la navegación por el sistema de archivos remoto, entre otras funcionalidades.

En cuanto a los parámentros más comunes de smbclient, algunos de ellos son:

* -L: Este parámetro se utiliza para enumerar los recursos compartidos disponibles en el servidor SMB o Samba.
* -U: Este parámetro se utiliza para especificar el nombre de usuario y la contraseña utilizados para la autenticación con el servidor SMB o Samba.
* -c: Este parámetro se utiliza para especificar un comando que se ejecutará en el servidor SMB o Samba.

Estos son algunso de los parámetros más comunes utilizados en smbcliente, aunque hay otros disponibles. La lista completa de parámetros y sus descripciones se pueden encontrar en la documentación oficial de la herramienta.

Por último, otra de las herramientas que utilizamos al final de la clase para enumerar Samba es 'Crackmapexec'. Crackmapexec (también conocido como CME) es una herramienta de prueba de penetración de línea de comandos que se utiliza para realizar auditorías de seguridad en entornos de Active Directory. CME se basa en las bibliotecas de Python 'impacket' y es compatible con sistemas operativos Windows, Linux y MacOS.

CME puede utilizarse para realizar diversas tareas de auditoría en entornos de Active Directory, como enumerar usuarios y grupos, buscar contraseñas débiles, detectar sistemas vulnerables y buscar vectores de ataque. Ademas, CME también puede utilizarse para ejectar ataques de diccionario de contraseñas, ataques de Pass-the-Hash y para explotar vulnerabilidades conocidas en sistemas Windows. Asimismo, cuenta con una amplia variedad de módulos y opciones de configuración, lo que la convierte en una herramienta muy flexible para la auditoría de seguridad de entornos de Active Directory. La herramienta permite automatizar muchas de las tareas de auditoría comunes, lo que ahorra tiempo y aumenta la eficiencia del proceso de auditoría.

A continuación, os compartimos el enlace directo a la Wiki para que podáis instalar la herramienta:

[CrackMapExec](https://wiki.porchetta.industries/getting-started/installation/installation-on-unix)

```bash
svn checkout https://github.com/vulhub/vulhub/trunk/master/samba/CVE-2017-7494

cd CVE

docker-compose up -d

docker ps

smbclient -L 127.0.0.1 -N

# Nos arroja por consola poca información

smbmap -H 127.0.0.1

# Nos arroja mas detalle

smbclient //127.0.0.1/myshare -N
dir
get
put

apt install cifs-utils

mkdir /mnt/mounted

mount -t cifs //127.0.0.1/myshare /mnt/mounted # Cuidado al realizar esto porque si borras lo del mnt puedes borrar lo del servidor real

umount /mnt/mounted

mount -t cifs //127.0.0.1/myshare /mnt/mounted -o username=null,password=null,domain=,rw

ls mounted

```

### Enumeración de gestores de contenido (CMS) – WordPress (1/2)

En esta clase estaremos enseñando técnicas de enumeración para el gestor de contenido (CMS) WordPress. Un gestor de contenido es una herramienta que permite la creación, gestión y publicación de contenidos digitales en la web, como por ejemplo páginas web, blogs, tiendas en línea, entre otros.

WordPress es un CMS de código abierto muy popular que fue lanzado en 2003. Es utilizado por millones de sitios web en todo el mundo y se destaca por su facilidad de uso y flexibilidad. Con WordPress, los usuarios pueden crear y personalizar sitios web sin necesidad de conocimientos de programación avanzados. Además, cuenta con una amplia variedad de plantillas y plugins que permiten añadir funcionalidades adicionales al sitio.

El proyecto que utilizamos en esta clase para enumerar un WordPress es el siguiente:

[DVWP](https://github.com/vavkamil/dvwp)

Una de las herramientas que utilizamos en esta clase para enumerar este gestor de contenido es Wpscan. Wpscan es una herramienta de código abierto que se utiliza para escanear sitios web en busca de vulnerabilidades de seguridad en WordPress.

Con Wpscan, podemos realizar una enumeración completa del sitio web y obtener información detallada sobre la instalación de WordPress, como la versión utilizada, los plugins y temas instalados y los usuarios registrados en el sitio. También nos permite realizar pruebas de fuerza bruta para descubrir contraseñas débiles y vulnerabilidades conocidas en plugins y temas.

Wpscan es una herramienta muy útil para los administradores de sitios web que desean mejorar la seguridad de su sitio WordPress, ya que permite identificar y corregir vulnerabilidades antes de que sean explotadas por atacantes malintencionados. Además, es una herramienta fácil de usar y muy efectiva para identificar posibles debilidades de seguridad en nuestro sitio web.

El uso de esta herramienta es bastante sencillo, a continuación se indica la sintaxis básica:

```bash
wpscan --url https://example.com
```

Si deseas enumerar usuarios o plugins vulnerables en WordPress utilizando la herramienta wpscan, puedes añadir los siguientes parámetros a la línea de comandos:

```bash
wpscan --url https://example.com --enumerate u
```

En caso de querer enumerar plugins existentes los cuales sean vulnerables, puedes añadir el siguiente parámetro a la línea de comandos:

```bash
wpscan --url https://example.com --enumerate vp
```

Asimismo, otro de los recursos que contemplamos en esta clase es el archivo xmlrpc.php. Este archivo es una característica de WordPress que permite la comunicación entre el sitio web y aplicaciones externas utilizando el protocolo XML-RPC.

El archivo xmlrpc.php es utilizado por muchos plugins y aplicaciones móviles de WordPress para interactuar con el sitio web y realizar diversas tareas, como publicar contenido, actualizar el sitio y obtener información.

Sin embargo, este archivo también puede ser abusado por atacantes malintencionados para aplicar fuerza bruta y descubrir credenciales válidas de los usuarios del sitio. Esto se debe a que xmlrpc.php permite a los atacantes realizar un número ilimitado de solicitudes de inicio de sesión sin ser bloqueados, lo que hace que la ejecución de un ataque de fuerza bruta sea relativamente sencilla.

En la siguiente clase estaremos desarrollando un script en Bash desde cero para realizar este tipo de ataques.
