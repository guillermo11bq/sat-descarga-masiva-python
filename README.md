# sat-descarga-masiva-python
Libreria de python que permite hacer descarga masiva de CFDIs a travez del Web Service del SAT en México.

*Note: I'm not sure if I should be writing this in English or Spanish since its use is primarily for accountable systems in Mexico. if you don't speak Spanish and you need to use this library, by all means, contact me.*
## Estado Actual
La libreria ya ha sido utilizada y funciona al 100%. Sin embargo tiene muchas areas de oportunidad que se iran solventando conforme tenga tiempo y si gustas colaborar, eres bienvenido :)

El objetivo actual de este repositorio es optimizar y mejorar el codigo para que sea mas facil de utilizar y pueda ser instalada a traves de pip.

Adicionalmente hace falta trabajar en la documentacion y, de ser posible, eliminar la dependencia de la libreria "chilkat2" pues es de codigo cerrado y hay que descargarla ya compilada e instalar de manera independiente.

## Instalación
Requiere las siguientes librerias:
* [Chilkat2](https://www.chilkatsoft.com/chilkat2-python.asp) (Se instala manualmente)

*Si utilizas entorno virtual hay que descomprimir el binario .so o .exe en tu carpeta site-packages*
* lxml
* pyOpenSSL
* requests

## Uso
Los desarrolladores de SmarterWeb escribieron sobre [como utilizar este Web Service](https://developers.sw.com.mx/knowledge-base/descarga-masiva-sat-solicitud/). Ahi puedes observar los pasos generales a seguir para hacer la descarga masiva.

Respecto a las particularidades de la libreria presente, cada parte del proceso esta representado por una clase.

Ejemplo de uso:
```
login = Login.TokenRequest()
token = login.soapRequest(b'certificate', 'llave privada formato PEM')

```
Se planea cambiar esta estructura para hacer mas *pythonica*