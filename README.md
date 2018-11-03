# P4-SFC

This is a P4 implementation of service function chaining based on [IETF RFC7665](https://tools.ietf.org/html/rfc7665).
Our implementation includes the following SFC components.
* Service Classifier
* Service Function Forwarder (SFF)
* Service Function Path (SFP)

More details and complete implementations will be added.


## System Requirements
* Ubuntu 14.04+
* [P4 BMv2](https://github.com/p4lang/behavioral-model)
* [p4c](https://github.com/p4lang/p4c)

We recommend to use [a VM of P4 tutorials](https://github.com/p4lang/tutorials/tree/sigcomm18-final-edits) that has all of the required soft ware installed.

## Usage

### 1. Cloning the repository
```bash
$ git clone https://github.com/GyuyeongKim/P4-SFC.git
$ cd P4-SFC
```

### 2. Run

```bash
$ make
```
