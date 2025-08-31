
#!/bin/bash

echo "Fixing all detached HEAD repositories..."

# Fix OpenSSL
echo "Fixing OpenSSL..."
cd temp_repos/openssl
git checkout master
cd ../..

# Fix SQLite
echo "Fixing SQLite..."
cd temp_repos/sqlite
git checkout master
cd ../..

# Fix Log4j
echo "Fixing Log4j..."
cd temp_repos/log4j
git checkout master
cd ../..

# Fix cURL
echo "Fixing cURL..."
cd temp_repos/curl
git checkout master
cd ../..

# Fix zlib
echo "Fixing zlib..."
cd temp_repos/zlib
git checkout master
cd ../..

echo "All repositories fixed!"
