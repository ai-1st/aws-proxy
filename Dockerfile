FROM openresty/openresty:alpine-fat

# Install dependencies for OpenResty
RUN /usr/local/openresty/luajit/bin/luarocks install luasocket && \
    /usr/local/openresty/luajit/bin/luarocks install lua-cjson

# Create directory for SSL certificates
RUN mkdir -p /etc/nginx/ssl

# Copy configuration and scripts
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY build/aws-proxy.key /etc/nginx/ssl/aws-proxy.key
COPY build/aws-proxy.crt /etc/nginx/ssl/aws-proxy.crt

# Expose ports
EXPOSE 80 443 8443

# Run OpenResty
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]