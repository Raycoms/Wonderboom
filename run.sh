#!/bin/sh

ip addr add 10.0.0.1/24 dev eth0
ip addr add 10.0.0.2/24 dev eth0
ip addr add 10.0.0.3/24 dev eth0
ip addr add 10.0.0.4/24 dev eth0
ip addr add 10.0.0.5/24 dev eth0
ip addr add 10.0.0.6/24 dev eth0

echo "10.0.0.1  leaf" >> /etc/hosts
echo "10.0.0.2  leaf_aggregator" >> /etc/hosts
echo "10.0.0.3  aggregator0" >> /etc/hosts
echo "10.0.0.4  aggregator1" >> /etc/hosts
echo "10.0.0.5  aggregator2" >> /etc/hosts
echo "10.0.0.6  aggregator3" >> /etc/hosts

tc qdisc add dev eth0 root netem delay 100ms
tc qdisc add dev lo root netem delay 100ms

ulimit -n 100000

# 256 run with missing configs tomorrow!
configurations="224 240 256 272 288 304 320"
cores="2 4 6 8 10 12 14"
program="wonderboom horn"

for prog in $program; do
  for x in $configurations; do
      for y in $cores; do
            echo "Running Configuration: $x Cores: $y"
            exec /usr/local/bin/tree "$x" "$y" "$prog" | grep "final"
      done
  done
done
