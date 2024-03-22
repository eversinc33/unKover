# unKover

A PoC anti-rootkit that can detect drivers mapped to kernel memory. The idea is to have a small & concise anti-rootkit to aid you (the rootkit dev) in honing your rootkits evasion abilities while also showcasing detection vectors with minimal FP rate that can detect many of the openly available driver mapper + rootkit combinations.

While some open source anti-cheats with capabilities far beyond this tool's exist, I wanted something that I can easily tweak according to my needs. Maybe it will be useful for you too.

Techniques implemented:

* NMI Callbacks: Periodically sends Non-Maskable Interrupts (NMIs) to each core and analyzes the currently running thread's call stack for any pointers to unbacked memory.
* APC StackWalks: Same as the NMI check, but with an APC queued to each system thread.
* System thread analysis: Periodically check all system threads for start-addresses pointing to unbacked memory.
* Driver Object analysis: Periodically check all driver objects registered on the system, and check if their DriverEntry points to unbacked memory.

So far its quite trivial to bypass these, especially given the implementations :) Hopefully that will change in the future.