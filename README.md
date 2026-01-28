# Wonderboom

## Simulation Tool for Worst Case Analysis of Signature Aggregation Trees

This Setup uses Docker. 
> Run docker build -t wonderboom .

to build Wonderboom and then run it with.

> docker run --cap-add=NET_ADMIN -it wonderboom

The shallow Ethereum aggregation tree is implemented on the ethereum-basic branch.
By building it with: 
> Run docker build -t ethereum .

You can use the runall.sh script to run both scripts in the background.
You should have at least 6 cores and 4GB of RAM available to run the simulation with 2 cores (4 Simulation Cores + 2 Execution Cores).

You can edit the run configurations in the run.sh file to alter the tree fanout or number of cores.
You have to rebuild the docker image after doing that to run the program in this configuration.

The program takes a few minutes to start up initially to generate all N key pairs and signatures.


Tested on Arch Linux.