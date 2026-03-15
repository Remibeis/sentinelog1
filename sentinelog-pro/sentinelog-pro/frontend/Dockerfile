FROM nginx:alpine

COPY index.html /usr/share/nginx/html/index.html

# Config nginx avec proxy vers le backend API
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
