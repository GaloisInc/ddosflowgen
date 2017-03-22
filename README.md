# ddosflowgen

## Disclaimer

This is a tool developed for internal research purposes only. Galois will not
provide support or assistance for this tool.

## Description

**ddosflowgen** models a DDoS attack and generates synthetic traffic datasets
from N views (each of the networks involved in the attack). You can define the
number of attacking networks and adjust parameters such as attack vectors
present, amplification factor, and the number of attack sources per network.
A human-readable "topology" source file defines the parameters for the attack.

3DCoP and ddosflowgen operate at the endpoint networks, which (approximately)
means the AS's near the attack sources and near the victim. Note that we aren't
concerned with what happens at intermediate networks such as Tier 1's and
routing hops along the path.

ddosflowgen takes a clean traffic **noise dataset** and generates synthetic
attack traffic in human-readable SiLK format. The resulting flow records
contain a mix of noise plus attack traffic, with IP addresses rewritten for
each network's perspective. We model:

* amplifiers - UDP reflectors/amplifiers such as DNS and NTP
* bots that flood - UDP floods such as DNS queries, like Mirai attacking
* probes - bots trying TCP connections to random dests, like Mirai scanning

## Prerequisites

You must have

1. Sample traffic data to serve as your **noise dataset**, and
2. An installation of [SiLK](https://tools.netsa.cert.org/silk/)

## Address rewriting

You must provide a SiLK-format log of normal traffic. This becomes the basis
for all time-synchronized output. PCAP, NetFlow, IPFIX can be easily converted
to SiLK. ddosflowgen will rewrite all IP addresses found in the
**noise dataset**, performing the following transformations:

* rewrites the local address to IP space used by 3DCoPs ("own network")
* rewrites the remote addresses so that each 3DCoP sees a different set
* generates synthetic attack flows from the vantage point of each 3DCoP

This implementation uses /16 or Class B **own networks**.

For example, let's say there are three networks involved in the DDoS: a hosting
provider at 172.20.x.x, a hosting provider at 172.21.x.x, and a university at
172.22.x.x. (These are locations where we can run 3DCoP.)

If the **noise dataset** contains some inbound traffic such as
`tcp 1.2.3.4:52476 -> 5.6.7.8:25`, this template is used to generate synthetic
"normal" traffic at each network.

The first hosting provider sees `tcp 181.92.225.124:52476 -> 172.20.137.22:25`
inbound. The external IP is the result of a re-mapping performed via hashing.
The internal IP has been re-mapped to the 172.20.0.0/16 address space.

The second hosting provider sees `tcp 201.247.70.52:52476 -> 172.21.177.141:25`
inbound, again with the re-mappings.

The external IPs are random, but consistent throughout each generated dataset.
This preserves the existing types of traffic making up each view's traffic.
For example, an SMTP conversation that appeared in the original will appear
intact at each generated view as well.

Synthetically generated attack traffic will also use IP addresses that are
consistent with each network. For example, if the two hosting providers above
are attacking the university, the university will see inbound traffic such as:
```
udp 172.20.199.174:53 -> 172.22.99.99:12345
udp 172.21.125.128:53 -> 172.22.99.99:12345
```

Each outbound traffic log will match, as well. The two hosting providers will
see outbound udp floods that match these IPs and ports. ddosflowgen produces
traffic logs that are consistent between all networks so that we can test
whether 3DCoP is able to achieve collaborative detection and mitigation.

## Definitions

**noise dataset** is the original dataset from your own captures, a
traffic repository or external provider. This may come in a variety
of formats such as IPFIX, NetFlow, pcap, etc. It should represent only
normal, non-attack traffic. This becomes the noise profile that all
synthetic traffic is written on top of.

**generated dataset** is the output from ddosflowgen, consisting of `tuc`
output files for each node defined in the attack topology. This output dataset
contains both normal and attack traffic.

The **SiLK capture** are the static artifacts (SiLK database and alert.log)
that result from feeding a generated dataset into SiLK. The database under
`silk_repository` can be stored in a tar file, and Analysis Pipeline's
alert.log should be captured as well. Together these can be used to
re-play the dataset. See: Re-Playing a SiLK Capture.

**own network** is the IP network block or range that one 3DCoP is responsible
for. This is the IP range that an organization owns, and is considered
internal for traffic analysis, e.g. `172.16` meaning that 172.16.xxx.xxx
are all internal to this 3DCoP.

# Steps for using ddosflowgen

Steps 1 and 2 are used to prepare the **noise dataset**.

## Step 1: Import Traffic into SiLK

The **noise datasets** (see definition) come in a variety of formats. No matter
the original format, we will first load the traffic records into SiLK.

Start with an empty SiLK database and configure `sensors.conf` to
recognize the correct `internal-ipblocks` that are appropriate for the
noise dataset. This is vital, as we need SiLK to properly categorize
the inbound vs outbound traffic. You might find it useful to run:

```
# This command is part of 3DCoP
reset-silk.sh --no-archive
```

Next, feed the noise dataset into SiLK. Refer to the SiLK sensor
configuration for the types of input it can process. We assume that your
SiLK installation is configured to accept incoming flow records at the path
`/opt/dddcop/silk/incoming/` (this will use the directory polling method).

```
# For IPFIX noise dataset
rwipfix2silk --silk-output /opt/dddcop/silk/incoming/new.rw original.yaf

# For PCAP noise dataset
rwp2yaf2silk --in=day.pcap --out=silk.rw
mv silk.rw /opt/dddcop/silk/incoming
```

Wait until SiLK has finished processing the input. Run `top` if unsure.

## Step 2: Export the Noise Dataset from SiLK

Next, export SiLK flows to text files. To make sure you are grabbing the full
range of the database, observe which time stamps (file names) exist under
`/opt/dddcop/silk/silk_repository`

```
# Export inbound traffic from SiLK to text
rwfilter --sensor=S0 --type=in,inweb,inicmp --start-date=2016/06/07 \
	--end-date=2016/06/07 --protocol=0- --pass=stdout | rwcut > inbound

# Export outbound traffic from SiLK to text
rwfilter --sensor=S0 --type=out,outweb,outicmp --start-date=2016/06/07 \
	--end-date=2016/06/07 --protocol=0- --pass=stdout | rwcut > outbound
```

The resulting text files are human-readable and should be verified for
accuracy. Beware traffic being miscategorized in ext2ext (which can be
checked with `--type=ext2ext`), as this can be corrected in your `sensors.conf`
with `internal-ipblocks`.

These files will be the `--dataset` provided to ddosflowgen.

You can reuse this **noise dataset** multiple times. On future runs, you can
jump ahead to Step 3 if you are satisfied with using your earlier noise.

## Step 3: Run ddosflowgen

Place the `inbound` and `outbound` files created in Step 2 into the same
directory, such as `noise/`. You will also need a topology definition that
describes the attack scenario.

Make sure the program points to the correct attack under the `topologies/` path,
by editing the line: `from topologies import your_specific_attack as topology`

```
python3 ddosflowgen.py --dataset example-noise/ --outdir result
```

Depending on the size of the attack, this can take a long time. There will be
two output files for each node defined in the topology: inbound and outbound.
This output, for all nodes, is the **generated dataset**.

## Importing the Generated Dataset into SiLK

SiLK is normally used to collect live incoming traffic data from routers,
accumulating it into database files. If using
[Analysis Pipeline](https://tools.netsa.cert.org/analysis-pipeline/), you can
also get alerts for certain traffic conditions.

You will probably want to import the **generated dataset** into SiLK and take
a snapshot of the resulting database. This must be done separately for each
node.

*For each node X in the attack topology:*

Start with an empty SiLK database, adjust `sensors.conf` to recognize
the current **own network** and feed the generated dataset into SiLK:

```
reset-silk.sh --no-archive
rwtuc --stop-on-error X-inbound.tuc X-outbound.tuc > synthetic.rw
mv synthetic.rw /opt/dddcop/silk/incoming
```

Wait until SiLK has finished processing the input. Run `top` if unsure, and
examine the `alert.log` to make sure the detector has triggered.
Then store the SiLK capture.

```
cd /opt/dddcop/silk
tar czvf ~/silk-capture.tar.gz silk_repository/
cp /opt/dddcop/silk/pipeline/log/alert.log ~/captured-alert.log
```

## Funding

This project is the result of funding provided by the Science and Technology Directorate
of the United States Department of Homeland Security under contract number D15PC00186.
The views and conclusions contained herein are those of the authors and should not be
interpreted as necessarily representing the official policies or endorsements, either
expressed or implied, of the Department of Homeland Security, or the U.S. Government.
