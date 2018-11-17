_**netfcts overview**_

Extensions to crate [Netbricks](https://github.com/rstade/NetBricks). This is a crate containing a common library of helper functions and data structures for crate [TrafficEngine](https://github.com/rstade/TrafficEngine) and crate [ProxyEngine](https://github.com/silverengine-de/ProxyEngine).

_**Installation**_

First install NetBricks. _netfcts_ needs the branch e2d2-rstade from the fork at https://github.com/rstade/Netbricks. The required NetBricks version is tagged (starting with v0.2.0). Install NetBricks locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml for the ProxyEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-0-1-1/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

