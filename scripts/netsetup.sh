#!/bin/bash

sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip link set tap0 up

sudo ip addr add 192.168.100.1/24 dev tap0