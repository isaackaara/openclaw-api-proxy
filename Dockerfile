FROM node:20-alpine

WORKDIR /app

# Install dependencies first (layer cache)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source
COPY index.js ./
COPY services.json ./

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "index.js"]
