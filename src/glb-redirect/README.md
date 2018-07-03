# glb-redirect iptables module

This module provides the "second chance" packet processing function of GLB by processing inbound [GLB GUE](../../docs/development/gue-header.md) packets before the Linux networking stack processes and decapsulates them, and forwarding packets that would not be valid TCP packets on the local machine (because they are for a non-local connection) to an alternate server.

## License

The `glb-redirect` component contained within this directory is licensed under the [GPL V2](../../LICENSE.md) to make it license compatible with the Linux Kernel.
