#!/bin/sh

ip addr add 10.0.0.1/24 dev eth0
ip addr add 10.0.0.2/24 dev eth0
ip addr add 10.0.0.3/24 dev eth0

echo "10.0.0.1  leaf" >> /etc/hosts
echo "10.0.0.2  aggregator" >> /etc/hosts
echo "10.0.0.3  leader" >> /etc/hosts

tc qdisc add dev eth0 root netem delay 100ms limit 1000000
tc qdisc add dev lo root netem delay 100ms limit 1000000

ulimit -n 200000

configurations="300 396 512 653 820 1018 1250"
cores="2 4 6 8"

for x in $configurations; do
    for y in $cores; do
        echo "Running Configuration: $x Cores: $y"
        exec /usr/local/bin/tree "$x" "$y" | grep "final"
    done
done