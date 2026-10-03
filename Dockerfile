FROM --platform=linux/amd64 python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 FRP_VERSION=0.71.0
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates \
 && curl -sL "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_amd64.tar.gz" -o /tmp/frp.tgz \
 && tar -xzf /tmp/frp.tgz -C /opt && mv /opt/frp_${FRP_VERSION}_linux_amd64 /opt/frp && rm /tmp/frp.tgz \
 && apt-get purge -y curl && apt-get autoremove -y -qq && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY tunnel-gateway.py start.sh ./
RUN chmod +x start.sh
CMD ["./start.sh"]
