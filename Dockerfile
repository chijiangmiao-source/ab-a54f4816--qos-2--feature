# 星载遥测中继 MQTT 5 QoS2 审计服务
# 零运行时依赖：仅使用 Node.js 内置模块
FROM node:20-alpine

WORKDIR /app

# 仅复制运行所需文件（零依赖，无需 npm install）
COPY package.json ./
COPY server ./server
COPY public ./public
COPY test ./test
COPY scripts ./scripts

# 证据库持久化目录（Compose 中挂载命名卷）
RUN mkdir -p /app/data && chown -R node:node /app
USER node

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    EVIDENCE_FILE=/app/data/evidence.jsonl

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/server.js"]
