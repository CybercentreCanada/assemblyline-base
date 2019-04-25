FROM nginx:1.15.10

ENV DOLLAR $
ENV FQDN localhost
ENV MAX_BODY_SIZE 100M
ENV SOCKET_HOST al_socketio
ENV UI_HOST al_ui

COPY http_redirect.conf /etc/nginx/conf.d/
COPY default.template /tmp/
COPY nginx.crt /etc/ssl/
COPY nginx.key /etc/ssl/

EXPOSE 443
EXPOSE 80
