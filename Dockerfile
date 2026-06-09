FROM node:18-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./

COPY . .

RUN npm install && npm run build

FROM node:18-alpine

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY package.json ./
COPY package-lock.json ./

RUN npm install --production

RUN addgroup -S app && adduser -S app -G app
USER app

EXPOSE 3000

CMD ["node", "dist/index.js"]