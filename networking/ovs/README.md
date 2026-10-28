# Open vSwitch Boundary

Stage 2 uses the system-provided Open vSwitch package; it does not vendor or emulate a switch.

With the Stage 2 topology running, verify the local bridge and controller relationship:

    ovs-vsctl br-exists s1
    ovs-vsctl get bridge s1 protocols
    ovs-vsctl get-controller s1
    ovs-ofctl -O OpenFlow13 dump-flows s1

The expected OpenFlow protocol is OpenFlow13. The controller endpoint is configured through SDN_STAGE2_CONTROLLER_HOST and SDN_STAGE2_CONTROLLER_PORT, defaulting to 127.0.0.1:6653.
