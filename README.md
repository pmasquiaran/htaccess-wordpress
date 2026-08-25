# Documentación Técnica .htaccess Maestro para WordPress

![Licencia MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Este repositorio contiene un archivo `.htaccess` con una configuración maestra de nivel de producción optimizada para WordPress. Combina políticas avanzadas de seguridad cibernética, mitigación de amenazas y optimización de rendimiento en un único módulo defensivo y de aceleración web.

---

## Tabla de Contenidos
1. [Whitelist Estratégica Agnóstica](#1-whitelist-estratégica-agnóstica)
2. [Cortafuegos 8G Firewall v1.4 (Perishable Press)](#2-cortafuegos-8g-firewall-v14)
3. [Complementos de Rendimiento, Seguridad y Ajustes Core](#3-complementos-de-rendimiento-seguridad-y-ajustes-core)
   - [Forzado de HTTPS](#31-forzado-de-https)
   - [Bloqueo de Archivos Sensibles](#32-bloqueo-de-archivos-sensibles)
   - [Protección contra Fuerza Bruta](#33-protección-contra-fuerza-bruta)
   - [Prevención de Ejecución de PHP](#34-prevención-de-ejecución-de-php)
   - [Soporte y Conversión Automática a WebP](#35-soporte-y-conversión-automática-a-webp)
   - [Compresión Inteligente (mod_deflate)](#36-compresión-inteligente-mod_deflate)
   - [Caché del Navegador (mod_expires)](#37-caché-del-navegador-mod_expires)
   - [Cabeceras HTTP de Seguridad (mod_headers)](#38-cabeceras-http-de-seguridad-mod_headers)
4. [Reglas Nativas de WordPress (Permalink Engine)](#4-reglas-nativas-de-wordpress)

---

## 1. Whitelist Estratégica Agnóstica

Esta sección define una variable de entorno (`E=WHITELIST:1`) cuando la petición entrante coincide con un endpoint, cookie o parámetro crítico legítimo. **Su objetivo principal es evitar falsos positivos en el cortafuegos 8G.**

```apache
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteBase /

	# 1. Endpoints de rutas físicas y API REST
	RewriteCond %{REQUEST_URI} wp-json/(.*)? [NC,OR]
	RewriteCond %{REQUEST_URI} wp-json/sliderrevolution/ [NC,OR]
	RewriteCond %{REQUEST_URI} wp-admin/admin-ajax\.php$ [NC,OR]
	RewriteCond %{REQUEST_URI} wp-admin/(load-scripts|load-styles|post|post-new|plugin-install|update)\.php$ [NC,OR]

	# 2. Rutas nativas de comercio electrónico (WooCommerce)
	RewriteCond %{REQUEST_URI} /(cart|carrito|checkout|finalizar-compra|mi-cuenta|my-account) [NC,OR]

	# 3. Parámetros de URLs dinámicas (Elementor, WPBakery, Slider Revolution, etc.)
	RewriteCond %{QUERY_STRING} (^|&)(add-to-cart=|wc-ajax=|elementor|action=|wc-api=|vc_action=|vcv-) [NC,OR]
	RewriteCond %{QUERY_STRING} (^|&)(srengine=|slideid=|sr_page=|revslider=) [NC,OR]

	# 4. Integraciones de Feeds y OAuth (Smash Balloon Pro)
	RewriteCond %{REQUEST_URI} /(instagram-feed|facebook-feed|youtube-feed|custom-facebook-feed) [NC,OR]
	RewriteCond %{QUERY_STRING} (^|&)(access_token=|code=|oauth_token=|state=|graph\.facebook|api\.instagram) [NC,OR]
	RewriteCond %{QUERY_STRING} (^|&)(sbi_|sbf_|sby_|_wpnonce=) [NC,OR]

	# 5. Modulos de eventos (The Events Calendar & Pro)
	RewriteCond %{REQUEST_URI} /(evento|eventos|event|events) [NC,OR]
	RewriteCond %{QUERY_STRING} (^|&)(tribe_|tribe-bar-|tribe_geosearch|tribe_event_display) [NC,OR]

	# 6. Cookies de sesión críticas
	RewriteCond %{HTTP_COOKIE} woocommerce_ [NC]

	# Asignación del flag de exención
	RewriteRule .* - [E=WHITELIST:1]
</IfModule>
```

---

## 2. Cortafuegos 8G Firewall v1.4

Implementación del conjunto de reglas del **8G Firewall** desarrollado por Jeff Starr (*Perishable Press*). Cada bloque evalúa diferentes capas de la petición HTTP y devuelve un estado `403 Forbidden` (`[F]`) si detecta patrones maliciosos (SQLi, XSS, Path Traversal, User-Agents dañinos, etc.).

Cada bloque inicia verificando si la variable `WHITELIST` está activa para omitir el filtrado en peticiones legítimas:
```apache
RewriteCond %{ENV:WHITELIST} 1
RewriteRule .* - [S=1]
```

### Capas inspeccionadas:
* **Core Ajustes:** Desactiva firma del servidor (`ServerSignature Off`) y desactiva el listado de directorios (`Options -Indexes`).
* **Query String (`8G:[QUERY STRING]`):** Detecta inyecciones de código, llamadas arbitrarias a funciones PHP, manipulaciones SQL y payloads codificados.
* **Request URI (`8G:[REQUEST URI]`):** Bloquea accesos a extensiones no autorizadas, herramientas de hacking conocidas, archivos de configuración expuestos y directorios del sistema.
* **User Agent (`8G:[USER AGENT]`):** Filtra bots maliciosos, crawlers no deseados y herramientas de escaneo automático.
* **Remote Host (`8G:[REMOTE HOST]`):** Restringe peticiones provenientes de redes de servidores asociadas a tráfico automatizado o sospechoso.
* **HTTP Referrer (`8G:[HTTP REFERRER]`):** Bloquea spam de referrers y ataques de inyección mediante la cabecera Referer.
* **HTTP Cookie (`8G:[HTTP COOKIE]`):** Previene inyecciones maliciosas pasadas dentro de las cookies del navegador.
* **Request Method (`8G:[REQUEST METHOD]`):** Permite métodos estándar y bloquea métodos inseguros como `CONNECT`, `DEBUG`, `MOVE`, `TRACE`, `TRACK`.

---

## 3. Complementos de Rendimiento, Seguridad y Ajustes Core

### 3.1. Forzado de HTTPS
Redirige cualquier petición entrante no cifrada (HTTP) hacia HTTPS con un código de respuesta permanente `301`.
```apache
<IfModule mod_rewrite.c>
	RewriteCond %{HTTPS} off
	RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
```

### 3.2. Bloqueo de Archivos Sensibles
Deniega el acceso directo desde el exterior a archivos críticos del core, archivos de configuración, instaladores y endpoints legacy vulnerable como `xmlrpc.php`.
```apache
<FilesMatch "^(wp-config\.php|php\.ini|\.user\.ini|^install\.php|setup\-config\.php|readme\.html|license\.txt|xmlrpc\.php)$">
	Require all denied
</FilesMatch>
```

### 3.3. Protección contra Fuerza Bruta
Bloquea peticiones `POST` dirigidas a los formularios de login y comentarios (`wp-login.php`, `wp-comments-post.php`) que provengan de dominios externos o que no identifiquen su `User-Agent`.
```apache
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} POST
	RewriteCond %{REQUEST_URI} (wp-comments-post|wp-login)\.php [NC]
	RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?%{HTTP_HOST} [NC]
	RewriteCond %{HTTP_USER_AGENT} ^$
	RewriteRule .* - [F]
</IfModule>
```

### 3.4. Prevención de Ejecución de PHP
Evita que se ejecuten scripts PHP alojados dentro de directorios de almacenamiento de archivos (`uploads/`) o subdirectorios internos (`wp-includes/`), neutralizando webshells subidas mediante vulnerabilidades en plugins.
```apache
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_URI} ^/prototipo/contenido/uploads/.*\.php$ [NC,OR]
	RewriteCond %{REQUEST_URI} ^/prototipo/wp-includes/.*\.php$ [NC]
	RewriteCond %{REQUEST_URI} !^/prototipo/wp-includes/(wp-tinymce|js/tinymce/plugins|css|images) [NC]
	RewriteRule .* - [F]
</IfModule>
```

### 3.5. Soporte y Conversión Automática a WebP
Verifica si el navegador soporta el formato `.webp` mediante la cabecera `Accept`. Si la imagen `.webp` correspondiente existe en el servidor, la entrega de forma transparente en lugar del `.jpg` o `.png` solicitado.
```apache
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTP_ACCEPT} image/webp
    RewriteCond %{REQUEST_FILENAME} \.(jpe?g|png)$
    RewriteCond %{REQUEST_FILENAME}.webp -f
    RewriteRule ^(.+)\.(jpe?g|png)$ $1.webp [T=image/webp]
</IfModule>

<IfModule mod_headers.c>
    Header append Vary Accept env=REDIRECT_accept
</IfModule>
```

### 3.6. Compresión Inteligente (`mod_deflate`)
Comprime los assets basados en texto (HTML, CSS, JS, JSON, SVG, Fuentes) antes de enviarlos al navegador, reduciendo drásticamente el peso de la transferencia.

```apache
<IfModule mod_filter.c>
	<IfModule mod_deflate.c>
		AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css
		AddOutputFilterByType DEFLATE text/javascript application/javascript application/x-javascript
		AddOutputFilterByType DEFLATE application/json application/xml
		AddOutputFilterByType DEFLATE image/svg+xml image/x-icon
		AddOutputFilterByType DEFLATE application/vnd.ms-fontobject application/x-font-ttf font/opentype

		SetOutputFilter DEFLATE

		BrowserMatch ^Mozilla/4 gzip-only-text/html
		BrowserMatch ^Mozilla/4\.0[678] no-gzip
		BrowserMatch \bMSIE !no-gzip !gzip-only-text/html

		Header append Vary User-Agent
	</IfModule>
</IfModule>
```

### 3.7. Caché del Navegador (`mod_expires`)
Configura las políticas de almacenamiento en caché para recursos estáticos (imágenes, fuentes, hojas de estilo) para optimizar la velocidad de carga repetida y métricas LCP/CLS. Garantiza además que los archivos PHP y HTML dinámicos no se almacenen en caché para evitar inconsistencias en carritos o sesiones.

* **Imágenes y Fuentes:** 1 año (`access plus 1 year`).
* **Estilos CSS y JS:** 1 mes (`access plus 1 month`).
* **Documentos Dinámicos (PHP/HTML):** Se fuerza `no-store, no-cache, must-revalidate` para evitar problemas de actualización inmediata.

```apache
<IfModule mod_expires.c>
	ExpiresActive on
	ExpiresDefault "access plus 1 month"

	ExpiresByType image/jpg "access plus 1 year"
	ExpiresByType image/jpeg "access plus 1 year"
	ExpiresByType image/png "access plus 1 year"
	ExpiresByType image/gif "access plus 1 year"
	ExpiresByType image/webp "access plus 1 year"
	ExpiresByType image/svg+xml "access plus 1 year"
	ExpiresByType image/x-icon "access plus 1 year"

	ExpiresByType font/ttf "access plus 1 year"
	ExpiresByType font/otf "access plus 1 year"
	ExpiresByType font/woff "access plus 1 year"
	ExpiresByType font/woff2 "access plus 1 year"
	ExpiresByType application/font-woff "access plus 1 year"
	ExpiresByType application/vnd.ms-fontobject "access plus 1 year"

	ExpiresByType text/css "access plus 1 month"
	ExpiresByType text/javascript "access plus 1 month"
	ExpiresByType application/javascript "access plus 1 month"
	ExpiresByType application/x-javascript "access plus 1 month"

	ExpiresByType application/pdf "access plus 1 month"
	ExpiresByType image/vnd.microsoft.icon "access plus 1 year"

	<FilesMatch "\.(php|html)$">
		Header set Cache-Control "private, no-store, no-cache, must-revalidate, max-age=0"
		Header set Pragma "no-cache"
		ExpiresActive Off
	</FilesMatch>
</IfModule>
```

### 3.8. Cabeceras HTTP de Seguridad
Aplica capas avanzadas de protección del lado del cliente mediante cabeceras HTTP:

| Cabecera | Valor / Configuración | Propósito |
| :--- | :--- | :--- |
| `X-Frame-Options` | `SAMEORIGIN` | Previene ataques de Clickjacking impidiendo el renderizado en iframes externos. |
| `X-Content-Type-Options` | `nosniff` | Evita la interpretación incorrecta de tipos MIME (MIME Sniffing). |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controla la fuga de información sensible enviada en las peticiones salientes. |
| `Permissions-Policy` | Desactiva características de hardware | Deshabilita acceso a micrófono, cámara, geolocalización, etc. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Fuerza el uso exclusivo de HTTPS (HSTS) en el navegador por 1 año. |
| `X-XSS-Protection` | `1; mode=block` | Activa el filtro Cross-Site Scripting en navegadores legacy. |
| `Content-Security-Policy` | `upgrade-insecure-requests` | Fuerza a actualizar automáticamente peticiones mixtas HTTP a HTTPS. |
| `X-Powered-By` / `Server` | Unset | Oculta la versión de PHP y la firma del servidor web para evitar Fingerprinting. |

```apache
<IfModule mod_headers.c>
	Header always set X-Frame-Options "SAMEORIGIN"
	Header always set X-Content-Type-Options "nosniff"
	Header always set Referrer-Policy "strict-origin-when-cross-origin"
	Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), display-capture=(), gyroscope=(), accelerometer=(), magnetometer=(), fullscreen=(self)"
	Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
	Header always set X-XSS-Protection "1; mode=block"
	Header set Connection keep-alive
	Header always set Content-Security-Policy "upgrade-insecure-requests"

	Header unset X-Powered-By
	Header always unset X-Powered-By
	Header unset Server
	Header always unset Server
</IfModule>

FileETag None
```

---

## 4. Reglas Nativas de WordPress

Estructura por defecto requerida para la resolución de enlaces permanentes (*Permalinks*) y el enrutamiento hacia el controlador principal (`index.php`).

```apache
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /prototipo/
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /prototipo/index.php [L]
</IfModule>
# END WordPress
```

---

## 📌 Metadatos del Proyecto

* **Autor:** Pablo Masquiarán
* **Sitio Web:** [https://pmasquiaran.dev/](https://pmasquiaran.dev/)
* **Versión:** 2.1
* **Licencia:** [MIT License](LICENSE)

*Documentación generada para la optimización de bases estándar de WordPress en producción.*
