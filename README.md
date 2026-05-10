# Herramientas Profesionales de Ciberseguridad

Colección de herramientas de línea de comandos para acceder a APIs públicas de seguridad, diseñadas para ser rápidas y profesionales.

##Repo de apis
https://github.com/public-apis/public-apis

## Requisitos

- Python 3.7+
- Biblioteca `requests`

Instalar dependencias:
```bash
pip install requests
```

## Estructura

La herramienta principal es `cli.py` que proporciona una interfaz de línea de comandos con subcomandos organizados por categorías:

```
cibersec-tools/
├── cli.py          # Interfaz principal
├── README.md       # Este archivo
└── (otros archivos opcionales)
```

## Uso General

```bash
python cli.py <comando> <subcomando> [opciones]
```

## Categorías y Comandos

### 1. Inteligencia de Amenazas y OSINT (`intel`)
- `shodan` - Buscar en Shodan
- `censys` - Buscar en Censys  
- `binary` - Buscar en BinaryEdge
- `greynoise` - Consultar IP en GreyNoise
- `virustotal` - Escanear en VirusTotal

### 2. Análisis de Malware (`malware`)
- `urlscan` - Escanear URL en URLScan.io
- `malbazaar` - Consultar hash en MalwareBazaar

### 3. Evaluación de Vulnerabilidades (`vuln`)
- `nvd` - Buscar CVE en NVD (pública)
- `vuldb` - Buscar en VulDB

### 4. Seguridad de Red y Reputación de IP (`network`)
- `abuseipdb` - Verificar IP en AbuseIPDB
- `ipinfo` - Consultar información de IP (servicio gratuito)

### 5. Seguridad de Aplicaciones Web (`web`)
- `safebrowsing` - Verificar URL con Google Safe Browsing
- `urlscan_result` - Obtener resultado de URLScan.io

### 6. Autenticación y Seguridad de Cuentas (`auth`)
- `hibp` - Verificar brechas en HaveIBeenPwned

### 7. Criptografía y Cifrado (`crypto`)
- `hashdecrypt` - Intentar descifrar hash (ejemplo ilustrativo)

### 8. Detección de Fraude (`fraud`)
- `fraudlabs` - Verificar fraude por IP con FraudLabs Pro

### 9. Herramientas para Desarrolladores (`dev`)
- `github` - Buscar repositorios en GitHub
- `hackerone` - Información sobre programas HackerOne

### 10. Recursos para Investigación y Ley (`legal`)
- `legal --info` - Información sobre recursos legales disponibles

## Ejemplos de Uso

### Buscar en Shodan
```bash
python cli.py intel shodan "webcam city:London" --key TU_API_KEY_SHODAN
```

### Verificar IP en AbuseIPDB
```bash
python cli.py network abuseipdb 8.8.8.8 --key TU_API_KEY_ABUSEIPDB
```

### Escanear URL en URLScan.io
```bash
python cli.py malware urlscan https://ejemplo.com --key TU_API_KEY_URLSCAN
```

### Verificar brechas en HaveIBeenPwned
```bash
python cli.py auth hibp usuario@ejemplo.com
```

### Consultar información de IP (gratuita)
```bash
python cli.py network ipinfo 8.8.8.8
```

### Buscar CVE en NVD
```bash
python cli.py vuln nvd CVE-2021-34527
```

## Notas Importantes

1. **API Keys**: La mayoría de los servicios requieren registro y obtención de una API key. Estas deben mantenerse seguras y no compartirse públicamente.

2. **Límites de Uso**: Las APIs gratuitas tienen límites de tasa (rate limits). Revise la documentación de cada servicio para conocer los límites específicos.

3. **Uso Ético**: Estas herramientas están diseñadas para uso en pruebas de seguridad autorizadas, investigación de amenazas y defensa de sistemas. Su uso para actividades maliciosas es ilegal y éticamente inaceptable.

4. **Responsabilidad**: El usuario es responsable de cumplir con los términos de servicio de cada API y las leyes aplicables en su jurisdicción.

5. **Desarrollo**: Este es un punto de partida. Para uso en producción, considere agregar:
   - Manejo más robusto de errores
   - Caché de resultados
   - Logging detallado
   - Soporte para proxies
   - Exportación a diferentes formatos (JSON, CSV, etc.)

## Personalización

Puede extender esta herramienta agregando:
- Más APIs específicas para su campo de trabajo
- Funcionalidades de reporte y generación de tickets
- Integración con sistemas de SIEM o ticketing
- Interfaz web o API REST para uso interno

---
*Herramientas desarrolladas para profesionales de ciberseguridad que buscan eficiencia y acceso rápido a fuentes de inteligencia pública.*
