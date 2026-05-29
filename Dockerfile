FROM node:18-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm install --production && npm run build

COPY . .

FROM node:18-alpine

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/package-lock.json ./

RUN npm install --production

RUN addgroup app && adduser -S app -G app
USER app

EXPOSE 3000

CMD ["node", "dist/index.js"]