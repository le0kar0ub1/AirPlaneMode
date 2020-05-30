# AirPlaneMode

A kernel module for dumb firewalling.

A `sysctl` variable (as iptable) is initialized but unused so far.

All packets are rejected by default.

# Build

`make`

# Run

*WARNING*: the rules need root rights to mount the module.

`make run`

`make stop`

# Epilogue

Just old tests that I share.