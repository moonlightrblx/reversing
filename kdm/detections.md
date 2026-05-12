## Detection Insight (Kernel Mapper Behavior)

kdmapper (and similar mappers) map drivers outside of any legitimately loaded kernel module. Many compiled drivers (MSVC-based especially) rely on import wrappers, which becomes a detection surface.

Modern kernel anti-cheats typically:

* Scan kernel memory for **absolute indirect jump instructions** (`FF 25`)
* Verify whether those instructions reside inside a valid loaded module
* If not, they attempt to resolve the referenced import address manually
* Then check whether the resolved import ultimately points back into trusted kernel space (e.g. `ntoskrnl.exe`)

If the chain does not resolve cleanly to a legitimate module, it is treated as suspicious execution flow.

### Common mitigation approach

One approach to reduce this detection surface is to ensure the driver is mapped within a valid module context, similar in concept to how usermode manual mapping tries to preserve module legitimacy.


## References

* [https://www.ired.team/](https://www.ired.team/)
* [https://www.unknowncheats.me/forum/4657320-post25.html](https://www.unknowncheats.me/forum/4657320-post25.html)
* [https://github.com/themetadevv/Kd-Mapper-Clean](https://github.com/themetadevv/Kd-Mapper-Clean)
* [https://vollragm.github.io/posts/abusing-large-page-drivers/](https://vollragm.github.io/posts/abusing-large-page-drivers/)
