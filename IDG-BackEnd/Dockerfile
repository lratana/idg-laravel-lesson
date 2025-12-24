FROM php:8.2.0-apache

# Mod Rewrite
RUN a2enmod rewrite

# Get Linux Library
RUN apt-get update -y && apt-get install -y \
    libicu-dev \
    libmariadb-dev \
    unzip zip \
    zlib1g-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libzip-dev

# Get PHP Extension
RUN docker-php-ext-install gettext intl pdo_mysql gd pcntl zip

# Configure and install the GD image processing library with support for FreeType fonts and JPEG images
# This enables PHP to manipulate and create images dynamically

# Set the Apache document root to the public directory for serving web application files
# Update all Apache virtual host configuration files to use the new document root path
# Update the main Apache configuration and available configurations to reference the new document root
RUN docker-php-ext-configure gd --enable-gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd

ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Get Composer
COPY --from=composer:2.2 /usr/bin/composer /usr/bin/composer

# Get NodeJS
COPY --from=node:23.10.0 /usr/local /usr/local

# Copy Project Files
COPY . /var/www/html

# Set Working Directory
WORKDIR /var/www/html
