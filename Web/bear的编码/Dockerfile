FROM ctftraining/base_image_nginx_mysql_php_73

COPY src /var/www/html
COPY flag.sh /flag.sh

# ENV FLAG="ctf{p0p_ch@1n_1s_fun}"

RUN chmod +x /flag.sh && \
    chown -R www-data:www-data /var/www/html
CMD ["/flag.sh"]
