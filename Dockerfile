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

# The base image bundles the npm CLI globally, which pulls in its own tar/
# brace-expansion/etc. dependencies - Trivy flags CVEs in those even though
# nothing here ever invokes npm at runtime (CMD is `node`, not `npm start`).
# Removing it closes those findings for real instead of leaving known-dead
# code sitting in the image.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

ENV NODE_ENV=production
CMD ["node", "src/index.js"]
