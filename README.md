# Suazo Barber 504

## Iniciar la web y el panel

Se necesita Node.js 20 o posterior. Desde esta carpeta ejecuta `npm start` y abre `http://localhost:3000/admin`.

La primera vez aparecerá el formulario para crear el acceso del dueño. Esa configuración inicial solo se permite desde este ordenador. El servidor guarda una contraseña cifrada y un secreto en `owner-config.json`; no guarda la contraseña escrita. Después podrás iniciar sesión desde `/admin` y la web estará en `http://localhost:3000/`.

El panel permite editar el nombre, el título y descripción de la página, el texto de portada y los servicios. Los cambios se guardan en `content.json`.

## Publicación

La web necesita un hosting que ejecute Node.js, permita almacenamiento persistente y use HTTPS; no se puede publicar como HTML estático independiente. En producción configura `OWNER_EMAIL`, `OWNER_PASSWORD` (mínimo 14 caracteres), `SESSION_SECRET` (mínimo 32 caracteres) y `NODE_ENV=production` en la configuración privada del hosting, o provisiona `owner-config.json` de forma segura. No subas ese archivo ni contraseñas o secretos al repositorio. Usa una sola instancia de Node; al reiniciar el servidor se cierran las sesiones activas.
