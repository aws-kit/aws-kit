# Intro

A set of aws command line tools to save your clicks AWS consoles.



#Installation

` pip install pip install git+https://github.com/aws-kit/aws-kit.git`

# Tools introduction

## vpc-peering

Set up VPC peering between AWS VPCs. Normally, the operation scenario is:

- Login as vpc peering requester
- Locate the VPC to peer
- Initiate the VPC peering, by filling the accepter's acc, region and vpc
- Logout and log in as vpc peering accepter
- Accept the vpc peering
- Go back to the vpc requester console
- For each subnet that needs be paired between the requester (A) and requested (B),
  - Find out the route table of the subnet in A
  - Find out the cidr of subnet in B
  - Add the entry in route table of A by the cidr of B, and add the peering id as the destination
  - The above steps need be done at both A=>B direction and B=>A direction. (time 2)
  - The above steps need be done if A has cross-zone replication. (time 2, again)
  - If the requester and starter has other peerings with other VPCs, the route table is getting complex.

The vpc-peering tool can help you setup peering with templates. Saves time, eliminate error!

### Usage

Generate config template in an interactive way. Or simply look at sample.yaml to see what it looks like.
`$ vpc-peering`

Check if the configuration works for current vpcs.
`$ vpc-peering -c <config.yaml> -a plan`
This will check current vpcs and see if there are issues if the config.yaml is to be applied.

Clear current peerings (if already exist, or hanging, or in a weird state):
`$ vpc-peering -c <config.yaml> -a delete`

Apply current peerings. If an peering is already there, then stop.
`$ vpc-peering -c <config.yaml> -a apply`


Apply current peerings. If an peering is already there, then drop it in the first place.
`$ vpc-peering -c <config.yaml> -a apply --force`


License
==============
MIT License.