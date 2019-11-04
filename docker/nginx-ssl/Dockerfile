FROM nginx:1.17.5

ENV DOLLAR $
ENV FQDN localhost
ENV MAX_BODY_SIZE 100M
ENV SOCKET_HOST al_socketio
ENV UI_HOST al_ui
ENV KIBANA_HOST kibana

COPY http_redirect.conf /etc/nginx/conf.d/
COPY default.template /tmp/
COPY nginx.crt /etc/ssl/
COPY nginx.key /etc/ssl/

EXPOSE 443
EXPOSE 80

CMD /bin/bash -c "envsubst < /tmp/default.template > /etc/nginx/conf.d/default.conf && cat /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'"