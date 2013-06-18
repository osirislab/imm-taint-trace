imm-taint-trace
===============

A taint tracer written via Immunity's plugin system. Taint is tracked on registers and memory locations. Currently, ~40 commonly used instructions are implemented.
To track taint, following rules are utilized to determine propagation:
- If data is copied from a tainted source to an untainted destination, taint the destination.
- If data is copied from an untainted source to a tainted destination, clear the destination.
- If data is copied from a memory location through a tainted register, taint the destination.
- If data is copied from a tainted memory location through an untainted register, taint the destination.
- If data is copied from a untainted memory location through an untainted register, clear the destination.
- If the destination is set to a constant value, clear the destination.

Install
-------
Copy `taint.py` and the `taint` directory into Immunity Debugger's `PyCommands` directory.

Help
----
For help, run the command without any arguments.
