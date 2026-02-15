# SecureBank - Production Dockerfile
FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy app
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Default: use SQLite. Override with DATABASE_URL for PostgreSQL
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
