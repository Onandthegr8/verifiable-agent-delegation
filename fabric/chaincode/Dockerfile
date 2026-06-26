# Chaincode-as-a-Service image for the agent-delegation chaincode.
#
# Built and run by the fabric-samples test-network `deployCCAAS` flow: the peer
# connects to this container over gRPC instead of building the chaincode itself
# (the legacy peer-side `docker build` path is incompatible with Docker Engine
# 29.x). The container runs fabric-chaincode-node in SERVER mode, non-TLS, on
# the port the test-network passes in (CC_SERVER_PORT=9999); the peer dials it
# at {{.peername}}_agentdelegation_ccaas:9999 on the fabric_test network.
FROM node:20 AS builder
WORKDIR /usr/src/app
COPY package.json tsconfig.json ./
COPY src ./src
RUN npm install && npm run build

FROM node:20 AS production
ARG CC_SERVER_PORT=9999
WORKDIR /usr/src/app
COPY package.json ./
COPY --from=builder /usr/src/app/dist ./dist
RUN npm install --omit=dev && npm cache clean --force
ENV PORT=$CC_SERVER_PORT
EXPOSE $CC_SERVER_PORT
ENV NODE_ENV=production
# CHAINCODE_SERVER_ADDRESS and CHAINCODE_ID are injected by `docker run` from
# deployCCAAS; start:server runs fabric-chaincode-node in non-TLS server mode.
CMD ["npm", "run", "start:server"]
