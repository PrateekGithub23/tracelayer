# TraceLayer UI image: build static assets with Node, serve them with an unprivileged nginx (uid 101,
# port 8080), and reverse-proxy /api to the backend so the browser sees a single origin.
FROM node:20.20.2-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31.7-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY proxy_headers.inc /etc/nginx/conf.d/proxy_headers.inc
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
