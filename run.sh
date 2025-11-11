#!/bin/sh
#tc qdisc add dev eth0 root netem delay 200ms
#tc qdisc add dev lo root netem delay 200ms
ulimit -n 100000

configurations="1018 1250"
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
