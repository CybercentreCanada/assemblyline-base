FROM nginx:1.15.10

ENV DOLLAR $

COPY kibana.conf /etc/nginx/conf.d/
COPY default.template /tmp/
COPY nginx.crt /etc/ssl/
COPY nginx.key /etc/ssl/

EXPOSE 443
EXPOSE 80
