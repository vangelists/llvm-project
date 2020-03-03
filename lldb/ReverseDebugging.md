# Reverse Debugging

**[ This project has been created in the context of my master's thesis and absolutely no guarantee is provided regarding stability, feature-completeness and future development, since it will most probably depend solely on my personal free time and future interests. ]**

This is an early-stage proof of concept for live reverse debugging in LLDB, similar to [GDB](https://sourceware.org/gdb/wiki/ReverseDebug), that currently provides initial support for C and C++ on the latest macOS (Darwin on x86-64).

The current implementation takes advantage of existing functionality in LLDB, that forces the target to always be executed in single-step mode. Single-step execution imposes a 1000x or greater slowdown, but proved to be a nice enough starting point for the scope of this project.

As the implementation matures, steps are gradually being taken to alleviate the slowdown (see [Avoiding Unwanted Symbols](#avoiding-unwanted-symbols) and [User Expression Evaluation](#user-expression-evaluation) below), although the current levels of slowdown and memory overhead remain far from ideal for daily use or use with non-trivial programs.

However, there is still lots of room for improvement and I will continue to look for new ways to speed up tracing after completing some of the functionality described in [Future Work](#future-work).


## Command Reference

<details><summary>Recording</summary>

* Start recording and single-stepping:

    `thread tracing start`

* Stop recording and single-stepping, discarding any previously recorded history and all bookmarks:

    `thread tracing stop`

* Temporarily suspend thread tracing and single-stepping while preserving history and associated bookmarks:

    `thread tracing suspend`

* Resume thread tracing and single-stepping, discarding any recorded history collected after the current instruction, along with any associated bookmarks:

    `thread tracing resume`

* Get the ID of the current tracepoint (point in time within recorded history):

    `thread current-tracepoint`

</details>

<details><summary>Stepping Back</summary>

* Step back one or more statements (source lines), stepping into calls:

    `thread step-back [-c <count>]`

* Step back one or more instructions, stepping into calls:

    `thread step-back-inst [-c <count>]`

* Step back until reaching target address:

    `thread step-back-until-address -a <address>`

* Step back until reaching target source line:

    `thread step-back-until-line -l <linenum>`

* Step back until out of current function or beginning of history:

    `thread step-back-until-out`

* Step back until reaching beginning of history:

    `thread step-back-until-start`

* Step back until a breakpoint is hit or beginning of history is reached:

    `thread continue-reverse`

</details>

<details><summary>Replaying</summary>

* Replay the one or more statements, stepping into calls:

    `thread replay [-c <count>]`

* Replay the one or more instructions, stepping into calls:

    `thread replay-inst [-c <count>]`

* Replay until reaching target address:

    `thread replay-until-address -a <address>`

* Replay until reaching target source line:

    `thread replay-until-line -l <linenum>`

* Replay until out of current function or end of history:

    `thread replay-until-out`

* Replay until reaching end of history:

    `thread replay-until-end`

* Replay until a breakpoint is hit or end of history is reached:

    `thread replay-continue`

</details>

<details><summary>Bookmarks</summary>

* Create a bookmark at the current or provided tracepoint, if any, with an optional name:

    `thread tracing bookmark create [-t <tracepoint-id>] [-n <tracepoint-name>]`

* Delete the bookmark marking the provided tracepoint:

    `thread tracing bookmark delete -t <tracepoint-id>`

* Jump to the tracepoint marked by the bookmark:

    `thread tracing bookmark jump -t <tracepoint-id>`

* List either all bookmarks or the bookmark marking the provided tracepoint, if any:

    `thread tracing bookmark list [-t <tracepoint-id>]`

* Rename the bookmark marking the current or the provided tracepoint, if any:

    `thread tracing bookmark rename [-t <tracepoint-id>] -n <tracepoint-name>`

* Move the bookmark marking the provided tracepoint (source) to another location (destination):

    `thread tracing bookmark move -s <tracepoint-id> -d <tracepoint-id>`

</details>

<details><summary>List of Command Aliases</summary><br>

|               Command               |                                       Aliases                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------ |
| `thread tracing start`              | `record-start` <br> `rec-start`                                                      |
| `thread tracing suspend`            | `record-suspend` <br> `rec-suspend`                                                  |
| `thread tracing resume`             | `record-resume` <br> `rec-resume`                                                    |
| `thread tracing stop`               | `record-stop` <br> `rec-stop`                                                        |
| `thread tracing current-tracepoint` | `current-tracepoint` <br> `ct`                                                       |
| `thread tracing bookmark`           | `bookmark` <br> `bm`                                                                 |
| `thread step-back`                  | `step-back` <br> `sb` <br> `previous` <br> `prev` <br> `ps`                          |
| `thread step-back-inst`             | `step-back-inst` <br> `sbi` <br> `previous-instruction` <br> `prev-inst` <br> `pi`   |
| `thread step-back-until-address`    | `step-back-until-address` <br> `previous-address` <br> `pa`                          |
| `thread step-back-until-line`       | `step-back-until-line` <br> `previous-line` <br> `pl`                                |
| `thread step-back-until-out`        | `step-back-until-out` <br> `sbo` <br> `previous-function` <br> `prev-func` <br> `pf` |
| `thread step-back-until-start`      | `step-back-until-start` <br> `sbs`                                                   |
| `thread continue-reverse`           | `continue-reverse` <br> `cr`                                                         |
| `thread replay`                     | `replay` <br> `rs`                                                                   |
| `thread replay-inst`                | `replay-instruction` <br> `replay-inst` <br> `ri`                                    |
| `thread replay-until-address`       | `replay-until-address` <br> `ra`                                                     |
| `thread replay-until-line`          | `replay-until-line` <br> `rl`                                                        |
| `thread replay-until-out`           | `replay-until-out` <br> `replay-function` <br> `rf`                                  |
| `thread replay-until-end`           | `replay-until-end` <br> `rend`                                                       |
| `thread replay-continue`            | `replay-continue` <br> `rc`                                                          |

</details>


## Internals

### Capturing Snapshots

A snapshot of the thread's state and environment (registers, variables, heap) is captured right before each instruction is executed.

- **Stack Frames**

    The LLDB data structures describing all active stack frames are deep-copied along with related metadata, such as the index of the currently selected stack frame and the set of register and variable information per stack frame.

- **Registers & Variables**

    The values of all registers and variables for all active stack frames are currently being backed up, regardless of whether the instruction about to be executed would modify any of those, with the exception of exception state registers, which are always ignored.

- **Heap Modifications**

    If the instruction about to be executed is recognized as one that may store, based on the information provided by the Disassembler plugin, then the destination operand is translated into a (virtual) memory address and the instruction mnemonic is used to extract the number of bytes about to be stored.

    Given that this address corresponds to the heap (that is, does not belong to the stack and does not correspond to any known symbol or code), the contents of that memory location are saved right before and after the aforementioned instruction is executed, in order to backup both the old and the new contents of that location and enable the debugger to undo or redo the write.

- **Thread State**

    Besides the stack frames and associated data, information about the thread state is also captured. In particular, the current stop reason, since it is modified when the user steps backwards, replays one or more recorded instructions or a user expression is evaluated and thus needs to be restored when execution continues normally, and the list of completed thread plans, so that they won't be executed again when the thread resumes.

- **Source Location**

    The original source line is also saved for each instruction in order to enable stepping backwards or replaying one or more statements (source lines).


### Restoring Snapshots

When stepping backwards or replaying for one or more instrucitons, the state and the environment of the thread are restored from the snapshot captured at the point in time, right before the destination instruction was executed.

- **Stack Frames**

    The data stuctures describing all active stack frames and related metadata are restored from the snapshot.

- **Registers & Variables**

    When the user steps backwards or replays, the debugger restores only the register and variable values of the deepest (zeroth) stack frame. However, when another stack frame is selected via the `frame select <frame_index>` command, then the register and variable values of the newly selected stack frame are restored.

- **Heap Modifications**

    Stepping backwards or forward within the recorded execution history means that the state of the heap must also be restored. This is accomplished by undoing or reapplying the modifications made by each store instruction sequentially, up to the point in time where the thread is restored.

    If a heap page has been since unmapped, then the restoration of the old contents fails and the user is warned that all history assosciated with that particular memory page will be discarded, since it is no longer needed.

    On the other side, if the heap region in question is still mapped and thus writable, but its contents have been invalidated and, optionally, reclaimed (e.g. through a call to `free()` and an optional subsequent call to `malloc()`), then that particular heap region ends up in an undefined state, of which the user remains unaware.

    The latter could possibly be resolved by tracking calls to (de)allocations functions in all supported languages or by using a custom allocator, however it was out of the scope of this project and thus a solution was not considered.

- **Thread State**

    Finally, the stop reason and the list of completed thread plans at that point in time are also restored from the snapshot.


### Avoiding Unwanted Symbols

As already discussed, executing the target in single-step mode is extremely slow and imposes a great memory overhead, thus, in order to speed up execution and minimize memory footprint, all symbols that belong either to libraries under `/usr/lib/` or to the `std` C++ namespace are always executed normally and are not traced.

Furthermore, the user has the ability to define a set of additional functions to ignore via the regular expression `target.process.thread.tracing-avoid-regex` in LLDB settings.

In order to avoid a symbol, single-stepping and tracing are suspended before the relevant call instruction is executed and an artificial breakpoint that is deleted on first hit is set at the instruction right after the call. When the call finishes and the breakpoint is reached, then the callback of the breakpoint, which resumes single-stepping and tracing, is executed and the breakpoint is automatically deleted, allowing the thread to continue running.


### Evaluating User Expressions

As for symbols that are ignored, tracing and single-stepping are suspended before a user expression is evaluated and resumed write after the evaluation finishes.

In contrast to the avoided symbols, however, the state of the deepest (zeroth) stack frame, along with its assosciated registers and variables, is also restored after the evaluation finishes, in order to undo any modifications during the evaluation.


### Respecting Breakpoints

When continuing backwards, the thread steps back until either beginning of recorded history is reached or an enabled breakpoint is hit.

Respectively, when replaying forward, the thread replays recorded instructions until either end of recorded history is reached or an enabled breakpoint is hit.


### Bookmarks

The user is also able to mark points of interest within the recorded history and optionally provide a name for them, in order to be able to jump easier from one point in time to another.


### Caching

Results of frequent and expensive computations are cached, aiming to improve tracing performance and consequently reduce the slowdown that is imposed on the target.

For now, this translates to caching whether an address corrseponds to the heap or the stack and whether a symbol belongs to a library installed under `/usr/lib/`.


### Implementation Location

Currently, most of the implementation is provided by the `ThreadPlanInstructionTracer` class in [ThreadPlanTracer.h](https://github.com/vangelists/llvm-project/blob/reverse-debugging/lldb/include/lldb/Target/ThreadPlanTracer.h) and [ThreadPlanTracer.cpp](https://github.com/vangelists/llvm-project/blob/reverse-debugging/lldb/source/Target/ThreadPlanTracer.cpp).

The user-facing commands are implemented in [CommandObjectThread.cpp](https://github.com/vangelists/llvm-project/blob/reverse-debugging/lldb/source/Commands/CommandObjectThread.cpp).

A number of other files have also been modified, albeit to a lesser extent. You may see all the changes by [comparing the `public/reverse-debugging` branch to `master`](https://github.com/vangelists/llvm-project/compare/master...vangelists:public/reverse-debugging).


## Future Work

In no particular order:

- [ ] Track modifications made by system calls and other known functions, e.g. `memcpy()`.
- [ ] Add ability to step back or replay up to the point where a register or variable was last modified.
- [ ] Handle deallocated and reclaimed heap regions.
- [ ] Add support for watchpoints.
- [ ] Create tests.
- [ ] Minimize memory footprint, i.e. back up only what is necessary.
- [ ] Expand functionality to multi-threaded programs.
- [ ] Export reverse debugging API at the SB level.
- [ ] Consider moving the core functionality into a plugin that would use the private or public API.
- [ ] Use the public API to provide a GUI, e.g. for Visual Studio Code.
- [ ] Add support for additional platforms, e.g. Darwin on AArch64.
- [ ] Add support for more languages, e.g. Swift or Rust.


## Contact

Vangelis Tsiatsianas - [contact@vangelists.com](mailto:contact@vangelists.com?subject=[GitHub]%20Live%20Reverse%20Debugging%20for%20LLDB)
