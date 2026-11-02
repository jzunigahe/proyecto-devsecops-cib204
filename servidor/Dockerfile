# ============================================================================
#  Dockerfile  -  Servicio de cifrado
#  >>> VERSION CORREGIDA <<<
#  [VULN-11] imagen base con version fija y ligera (node:24-alpine).
#  [VULN-12] solo se copian los archivos necesarios (+ .dockerignore).
#  [VULN-13] el contenedor corre con un usuario sin privilegios (node).
# ============================================================================

# Etapa 1: instalar solo las dependencias de produccion
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY servidor.js cifrado.js auth.js config.js db.js ./

# Etapa 2: imagen final minima
FROM node:24-alpine
# Se quita npm de la imagen final: no se usa en ejecucion y trae
# dependencias propias que Trivy reportaria.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
WORKDIR /app
COPY --from=build --chown=node:node /app /app
USER node
EXPOSE 3000
CMD ["node", "servidor.js"]
