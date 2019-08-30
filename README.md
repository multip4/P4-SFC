# High Performance and High available Service Function Chaining in Programmable Data Plane

This is a P4 (P4_16) implementation of service function chaining based on [IETF RFC7665](https://tools.ietf.org/html/rfc7665) and [IETF RFC8300](https://tools.ietf.org/html/rfc8300).
Our implementation includes the following SFC core components and functions.

* Network Service Header (NSH)
* Classifier
  * Service Function Path (SFP) assignment
  * SFC encapsulation
* Service Function Forwarder (SFF)
  * SFP forwarding
  * SFP termination (decapsulation)

## System Requirements
* Ubuntu 14.04+
* [P4 BMv2](https://github.com/p4lang/behavioral-model)
* [p4c](https://github.com/p4lang/p4c)
* [p4Runtime](https://github.com/p4lang/PI)

We highly recommend to use [a VM of P4 tutorials](https://github.com/p4lang/tutorials/tree/sigcomm18-final-edits) that has all of the required software installed.

Note that this implementation has only been tested in BMv2.
Therefore, it may not work as is on production P4-enabled programmable switches.

If you have any questions, please contact gykim08 at korea.ac.kr .