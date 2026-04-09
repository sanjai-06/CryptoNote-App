FROM node:20-alpine AS builder

WORKDIR /app

# Copy root-level package.json (frontend deps are at root)
COPY package*.json ./

RUN npm install

# All frontend files live inside src-ui/ — copy them into /app
COPY src-ui/index.html ./
COPY src-ui/vite.config.ts ./
COPY src-ui/tsconfig.json ./
COPY src-ui/tsconfig.node.json ./
COPY src-ui/src/ ./src/

RUN npx vite build --config vite.config.ts

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]