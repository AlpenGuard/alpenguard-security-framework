FROM node:20-bookworm AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
COPY apps/console/package.json apps/console/package.json

RUN npm install

COPY apps/console apps/console

RUN npm --workspace @alpenguard/console run build

FROM nginx:1.27-alpine

COPY apps/console/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/console/dist /usr/share/nginx/html

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
