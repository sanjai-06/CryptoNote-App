FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (includes devDeps for TypeScript compile)
COPY package*.json ./
RUN npm install

# Copy source and compile
COPY . .
RUN npm run build

# ── Production stage ──────────────────────────────────────────────────────────
FROM node:20-alpine AS production

WORKDIR /app

# Copy only production dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy compiled output from builder
COPY --from=builder /app/dist ./dist

# Non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3000

CMD ["node", "dist/index.js"]
