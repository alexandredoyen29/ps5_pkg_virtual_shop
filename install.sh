#!/bin/bash

echo Removing old PS5 PKG Virtual Shop installation
rm -rf /opt/ps5_pkg_virtual_shop
rm -f /usr/lib/systemd/system/ps5_pkg_virtual_shop.service

echo Installing PS5 PKG Virtual Shop under /opt/ps5_pkg_virtual_shop
mkdir -p /opt/ps5_pkg_virtual_shop
cp -r ./static /opt/ps5_pkg_virtual_shop
cp ./app.py /opt/ps5_pkg_virtual_shop
cp ./start_daemon.sh /opt/ps5_pkg_virtual_shop/
chmod +x /opt/ps5_pkg_virtual_shop/start_daemon.sh
sed -re "s?./app.py?/opt/ps5_pkg_virtual_shop/app.py?g" -i /opt/ps5_pkg_virtual_shop/start_daemon.sh

echo Installing the PS5 PKG Virtual Shop service
cp ./ps5_pkg_virtual_shop.service /usr/lib/systemd/system
systemctl daemon-reload
systemctl enable --now ps5_pkg_virtual_shop.service
