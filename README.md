# InjectDumper

> [!WARNING]
> Only use this in a sandboxed environment, where any uncaught injections cant cause harm!

PoC executable to catch and dump any attempted code injections (locally).

## Features

- Catch remote threads
- Catch thread hijacking
- Dump any recently allocated memory
- Dump memory where thread was started
- Reconstruct some manually mapped PEs
- Supports both 32 and 64 bit

## Usage

> [!NOTE]
> Due to how console apps work (and I'm lazy), closing it normally does not work and it instead needs to be killed via Task Manager or another external tool.

0. (Optional) rename InjectDumper.exe to the name of the process that the injector targets
1. Start InjectDumper (does **NOT** support injections that happen before the programs entry point)
2. Start program that injects code into InjectDumper
3. Start looking at the resulting memory/threads