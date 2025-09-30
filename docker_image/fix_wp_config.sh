#!/bin/bash

# Quick fix script for wp-config.php syntax errors
# This can be run inside the container to fix the wp-config.php file

echo "Fixing wp-config.php syntax error..."

# Backup the original file
cp /var/www/html/wp-config.php /var/www/html/wp-config.php.backup

# Remove any existing coverage instrumentation
sed -i '/include.*coverage_instrumentation.php/d' /var/www/html/wp-config.php

# Remove the closing ?> if it exists and add our include properly
# Handle both ?> and ?> with whitespace
sed -i 's/\s*?>\s*$//' /var/www/html/wp-config.php

# Add a newline if the file doesn't end with one
if [ -n "$(tail -c1 /var/www/html/wp-config.php)" ]; then
    echo "" >> /var/www/html/wp-config.php
fi

# Add the coverage instrumentation
echo "include('/fuzzer/coverage_instrumentation.php');" >> /var/www/html/wp-config.php

echo "wp-config.php has been fixed!"
echo "Testing PHP syntax..."
php -l /var/www/html/wp-config.php

if [ $? -eq 0 ]; then
    echo "✅ wp-config.php syntax is now valid!"
else
    echo "❌ wp-config.php still has syntax errors"
    echo "Restoring backup..."
    cp /var/www/html/wp-config.php.backup /var/www/html/wp-config.php
fi
