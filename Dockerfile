FROM node:24-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

FROM node:24-alpine
WORKDIR /app
RUN apk add --no-cache curl bash iproute2 ca-certificates && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin && \
    apk del curl bash

COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

ENV NODE_ENV=production
CMD ["node", "src/index.js"]
