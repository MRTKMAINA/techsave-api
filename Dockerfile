FROM node:22-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json server.js ./
ENV NODE_ENV=production
EXPOSE 10000
USER node
CMD ["node", "server.js"]
