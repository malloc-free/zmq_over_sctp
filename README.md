sctp_over_zmq
=============

sctp_over_zmq is a fork of libzmq and is distributed under the GNU Lesser General Public License as published by the Free Software Foundation; either version 3 of the Licence, or (at your option) any later version.

Information on ØMQ can be obtained from: zeromq.org

This fork adds the transport protocol SCTP to the ØMQ library. The options for SCTP can be configured via zmq_setsockopt - 
please see the acceptance tests in the repository https://github.com/malloc-free/zmq_over_sctp_acceptance_tests for
examples on how to set these options.

Also included is the basic framework for a pluggable protocols interface.

Dependencies:

To build sctp_over_zmq, you will need to have lksctp-tools installed to build. For more information, please see lksctp.sourceforge.net
