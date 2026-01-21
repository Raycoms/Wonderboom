#!/bin/sh

ip addr add 10.0.0.1/24 dev eth0
ip addr add 10.0.0.2/24 dev eth0
ip addr add 10.0.0.3/24 dev eth0

echo "10.0.0.1  leaf" >> /etc/hosts
echo "10.0.0.2  aggregator" >> /etc/hosts
echo "10.0.0.3  leader" >> /etc/hosts

tc qdisc add dev eth0 root netem delay 100ms
#rate 100mbit
ulimit -n 200000

configurations="512 650 820 1018 1250"
cores="4"
participationrate="6"

for x in $configurations; do
    for y in $cores; do
        for z in $participationrate; do
            echo "Running Configuration: $x Cores: $y Participation Rate $z"
            exec /usr/local/bin/tree "$x" "$y" "$z" | grep "final"
        done
    done
done