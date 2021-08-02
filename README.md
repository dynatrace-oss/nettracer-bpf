# NetTracer

NetTracer is a tool for tracing TCP events and collecting network connections metrics on Linux. It consists of two parts - a BPF program used for collecting data and a user space C++ binary that prints the data in structured or semi-structured format.

The BPF program, composed of BPF maps and kprobes, is compiled to an ELF object file. At runtime, that object file is loaded by NetTracer using utilities found in _bpf\_generic_.

NetTracer does not have any runtime dependencies on kernel headers, nor it is tied to any specific kernel version or configuration. To adapt to the currently running kernel at runtime, NetTracer creates a series of TCP connections with known parameters (such as known IP addresses and ports) and discovers where those parameters are stored in the kernel struct sock. This process is often referred to as offset guessing. Since a BPF programs cannot loop, NetTracer does not directly iterate over the possible offsets. It is instead controlled from user space by the binary using a state machine.

Only Linux kernels of version 4.15 or above are supported. NetTracer was inspired by [weaveworks' tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf).

## Features

- Tracing of TCP events: connect, accept and close
- Collecting metrics about each traced connection (see _Metrics_ below)
- High performance - written in C and C++
- Independence from kernel version and configuration

### Metrics

For each IPv4 and IPv6 TCP connection, defined by:

- Source address and port
- Destination address and port
- PID of the communicating process
- Network namespace

the following metrics are collected:

- Bytes sent
- Bytes received
- Packets sent
- Packets received
- Packets retransmitted
- Round-Trip Time (in microseconds)
- Round-Trip Time variance

## Setup

There are two ways of building NetTracer. You can either prepare your environment, installing dependencies on your own, or build it in a Docker container. If you wish to make Docker handle the whole setup, install Docker and run:

```
make
```

The project will be built, tested and the resulting binaries will be placed in _build_ directory.

However, if you prefer to use your own environment for building, run these commands:

```
make build-project
make test-project
```

You may want to see the _Dockerfile_ to check what dependencies need to be installed.

## Usage

To run NetTracer, simply do this:

```
./nettracersrv
```

This way, NetTracer's going to start in logging mode - all the information about traced connections is going to be printed as logs both in console and to a log file, by default saved in _log_ subdirectory. Metrics are printed in customizable time intervals.

Note that you need the following capabilities in order to run NetTracer:

- _CAP\_BPF_
- _CAP\_DAC\_OVERRIDE_
- _CAP\_PERFMON_
- _CAP\_SYS\_ADMIN_
- _CAP\_SYS\_PTRACE_
- _CAP\_SYS\_RESOURCE_

However, to obtain a cleaner output, more appropriate for e.g. collecting metrics from NetTracer by an external tool, you should add _-d_ option:

```
./nettracersrv -d
```

This is going to make NetTracer present metrics about currently active connections in a tabular format. The output is refreshed in customizable time intervals, but you may also manually request a refresh, pressing Enter.

For more information about running options, please refer to NetTracer's help screen:

```
./nettracersrv --help
```

## Help & Support

NetTracer is an open source project. The features are fully supported by Dynatrace.

**Get Help**

- Ask a question in the [product forums](https://community.dynatrace.com/t5/Using-Dynatrace/ct-p/UsingDynatrace)

**Open a [GitHub issue](https://github.com/dynatrace-oss/nettracer-bpf/issues/new) to:**

- Report minor defects, minor items or typos
- Ask for improvements or changes
- Ask any questions related to the community effort

SLAs don't apply for GitHub tickets

**Customers can open a ticket on the [Dynatrace support portal](https://support.dynatrace.com/supportportal/) to:**

- Get support from the Dynatrace technical support engineering team
- Manage and resolve product related technical issues

SLAs apply according to the customer's support level.

## Contributing

See CONTRIBUTING.md for details on submitting changes.

## License

NetTracer is under Apache 2.0 license. See LICENSE for details.

