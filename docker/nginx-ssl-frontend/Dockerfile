FROM nginx AS builder

RUN apt-get update
RUN apt-get install -y openssl
RUN openssl req -nodes -x509 -newkey rsa:4096 -keyout /etc/ssl/nginx.key -out /etc/ssl/nginx.crt -days 3650 -subj "/C=CA/ST=Ontario/L=Ottawa/O=CCCS/CN=assemblyline.local"

FROM nginx

ENV FQDN=localhost
ENV MAX_BODY_SIZE=100M
ENV FRONTEND_HOST=al_frontend
ENV SOCKET_HOST=al_socketio
ENV UI_HOST=al_ui
ENV MCP_HOST=al_mcp
ENV KIBANA_HOST=kibana
ENV ACCESS_LOG=off
ENV ERROR_LOG=/dev/stderr
ENV ERROR_LEVEL=notice
ENV READ_TIMEOUT=60s
ENV CONNECT_TIMEOUT=60s
ENV SEND_TIMEOUT=60s

COPY http_redirect.conf /etc/nginx/conf.d/
COPY default.conf.template /etc/nginx/templates/

COPY --from=builder /etc/ssl/ /etc/ssl/

EXPOSE 443
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
