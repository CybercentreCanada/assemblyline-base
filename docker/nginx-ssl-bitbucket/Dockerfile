FROM nginx:1.15.10

COPY default.conf /etc/nginx/conf.d/
COPY http_redirect.conf /etc/nginx/conf.d/
COPY nginx.crt /etc/ssl/
COPY nginx.key /etc/ssl/

EXPOSE 443
EXPOSE 80

CMD /bin/bash -c "cat /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'"