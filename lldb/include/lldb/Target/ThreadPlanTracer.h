//===-- ThreadPlanTracer.h --------------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLDB_TARGET_THREADPLANTRACER_H
#define LLDB_TARGET_THREADPLANTRACER_H

#include <unordered_map>

#include "lldb/Symbol/TaggedASTType.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/lldb-private.h"

namespace lldb_private {

#pragma mark ThreadPlanTracer

class ThreadPlanTracer {
  friend class ThreadPlan;

public:
  enum ThreadPlanTracerStyle {
    eLocation = 0,
    eStateChange,
    eCheckFrames,
    ePython
  };

  enum class Type {
    eBase,
    eAssembly,
    eInstruction
  };

  enum class State {
    eDisabled,
    eEnabled,
    eSuspended
  };

  ThreadPlanTracer(Thread &thread, lldb::StreamSP &stream_sp);
  ThreadPlanTracer(Thread &thread);

  virtual ~ThreadPlanTracer() = default;

  virtual Type GetType() const;

  virtual void TracingStarted() {}
  virtual void TracingEnded() {}
  virtual void TracingSuspendRequested() {}
  virtual void TracingSuspended() {}
  virtual void TracingResumed() {}

  virtual void ExpressionEvaluationStarted() {}
  virtual void ExpressionEvaluationFinished() {}

  void EnableTracing();
  void DisableTracing();
  void SuspendTracing(Thread::TracingToken token);
  void ResumeTracing(Thread::TracingToken token);

  State GetState() const;
  Thread::TracingToken GetTracingToken() const;

  void EnableSingleStepping();
  void DisableSingleStepping();
  bool SingleSteppingEnabled() const;

protected:
  Thread &m_thread;

  void SetToken(Thread::TracingToken token);
  bool GetEvaluatingExpression() const;
  Stream *GetLogStream() const;

  virtual void Log();
  virtual bool ShouldAcceptToken(Thread::TracingToken token) const {}

private:
  bool TracerExplainsStop();

  State m_state;
  Thread::TracingToken m_token;

  bool m_single_step;
  bool m_evaluating_expression; ///< Denotes whether expression evaluation is
                                ///< underway, so as to be able to avoid
                                ///< logging until evaluation is completed.

  lldb::StreamSP m_stream_sp;

  DISALLOW_COPY_AND_ASSIGN(ThreadPlanTracer);
};

#pragma mark ThreadPlanAssemblyTracer

class ThreadPlanAssemblyTracer : public ThreadPlanTracer {
public:
  ThreadPlanAssemblyTracer(Thread &thread, lldb::StreamSP &stream_sp);
  ThreadPlanAssemblyTracer(Thread &thread);
  ~ThreadPlanAssemblyTracer() override;

  Type GetType() const override;
  void TracingEnded() override;
  void Log() override;

private:
  Disassembler *GetDisassembler();

  TypeFromUser GetIntPointerType();

  lldb::DisassemblerSP m_disassembler_sp;
  TypeFromUser m_intptr_type;
  std::vector<RegisterValue> m_register_values;
  lldb::DataBufferSP m_buffer_sp;

  DISALLOW_COPY_AND_ASSIGN(ThreadPlanAssemblyTracer);
};

#pragma mark ThreadPlanInstructionTracer

/// \class ThreadPlanInstructionTracer
///
/// Enables recording & replaying the traced thread by executing the thread in
/// single-step mode and capturing a snapshot of the thread's state before each
/// instruction is executed.
///
class ThreadPlanInstructionTracer : public ThreadPlanTracer {
public:
  /// Constructs this ThreadPlanInstructionTracer object.
  ///
  /// \param[in] thread
  ///     The thread using the thread plan that owns this tracer.
  ///
  explicit ThreadPlanInstructionTracer(Thread &thread);

  /// Constructs this ThreadPlanInstructionTracer object.
  ///
  /// \param[in] thread
  ///     The thread using the thread plan that owns this tracer.
  ///
  /// \param[in] stream_sp
  ///     The stream to be used for logging output.
  ///
  ThreadPlanInstructionTracer(Thread &thread, lldb::StreamSP &stream_sp);

  /// Destructs this ThreadPlanInstructionTracer object.
  ///
  ~ThreadPlanInstructionTracer() override;

  /// Returns the type of this tracer (`eInstruction`).
  ///
  /// \return
  ///     The type of this tracer (`eInstruction`).
  ///
  Type GetType() const override;

  /// Steps back the given number of statements, stepping into calls.
  ///
  /// \param[in] num_statements
  ///     The number of statements to step back.
  ///
  /// \return
  ///     An error value, in case stepping back fails.
  ///
  Status StepBack(std::size_t num_statements = 1);

  /// Steps back the given number of instructions.
  ///
  /// \param[in] num_instructions
  ///     The number of instructions to step back.
  ///
  /// \return
  ///     An error value, in case stepping back fails.
  ///
  Status StepBackInstruction(std::size_t num_instructions = 1);

  /// Steps back until reaching the requested address.
  ///
  /// \param[in] address
  ///     The target PC address.
  ///
  /// \return
  ///     An error value, in case stepping back fails or address is not found.
  ///
  Status StepBackUntilAddress(lldb::addr_t address);

  /// Steps back until reaching the requested line.
  ///
  /// \param[in] line
  ///     The target line.
  ///
  /// \return
  ///     An error value, in case stepping back fails or line is not found.
  ///
  Status StepBackUntilLine(uint32_t line);

  /// Steps back until out of current function or beginning of history.
  ///
  /// \return
  ///     An error value, in case stepping back fails.
  ///
  Status StepBackUntilOutOfFunction();

  /// Steps back until reaching beginning of history.
  ///
  /// \return
  ///     An error value, in case stepping back fails.
  ///
  Status StepBackUntilStart();

  /// Steps back until a breakpoint is hit or beginning of history is reached.
  ///
  /// \param[out] canonical_breakpoint_id
  ///     The canonical ID of the breakpoint responsible for the stop, if any.
  ///
  /// \return
  ///     An error value, in case reverse continuation fails.
  ///
  Status ReverseContinue(Stream &canonical_breakpoint_id);

  /// Replays the given number of statements, stepping into calls.
  ///
  /// \param[in] num_statements
  ///     The number of statements to replay.
  ///
  /// \return
  ///     An error value, in case replay fails.
  ///
  Status Replay(std::size_t num_statements = 1);

  /// Replays the given number of instructions.
  ///
  /// \param[in] num_instructions
  ///     The number of instructions to replay.
  ///
  /// \return
  ///     An error value, in case replay fails.
  ///
  Status ReplayInstruction(std::size_t num_instructions = 1);

  /// Replays until reaching the requested address.
  ///
  /// \param[in] address
  ///     The target PC address.
  ///
  /// \return
  ///     An error value, in case replay fails or address is not found.
  ///
  Status ReplayUntilAddress(lldb::addr_t address);

  /// Replay until reaching the requested line.
  ///
  /// \param[in] line
  ///     The target line.
  ///
  /// \return
  ///     An error value, in case replay fails or line is not found.
  ///
  Status ReplayUntilLine(uint32_t line);

  /// Replays until out of current function or end of history.
  ///
  /// \return
  ///     An error value, in case replay fails.
  ///
  Status ReplayUntilOutOfFunction();

  /// Replays until end of history.
  ///
  /// \return
  ///     An error value, in case replay fails.
  ///
  Status ReplayUntilEnd();

  /// Replays until a breakpoint is hit or end of history is reached.
  ///
  /// \param[out] canonical_breakpoint_id
  ///     The canonical ID of the breakpoint responsible for the stop, if any.
  ///
  /// \return
  ///     An error value, in case replay fails.
  ///
  Status ReplayContinue(Stream &canonical_breakpoint_id);

  /// Restores the register and variable values of the stack frame with the
  /// provided index.
  ///
  /// \param[in] frame_idx
  ///     The stack frame index whose register and variable values to restore.
  ///
  void RestoreStackFrameState(std::size_t frame_idx);

  /// Returns `true` if the state of the active stack frames is currently being
  /// emulated by this tracer in order to mimic a previous point in time.
  ///
  /// \return
  ///     `true` if the state of the active stack frames is currently being
  ///     emulated by this tracer in order to mimic a previous point in time.
  ///
  bool IsStackFrameStateEmulated() const;

  /// Returns the recorded register values for the given stack frame.
  ///
  /// \param[in] frame_idx
  ///     The index of the stack frame whose register values to get.
  ///
  /// \return
  ///     The recorded register values for the given stack frame.
  ///
  const RegisterContext::RegisterValues &
  GetRecordedRegisterValuesForStackFrame(std::size_t frame_idx) const;

  /// Returns the ID of the currently active tracepoint.
  ///
  /// \return
  ///     The ID of the currently active tracepoint or
  ///     `Thread::InvalidTracepointID` on failure.
  ///
  Thread::TracepointID GetCurrentTracepointID() const;

  /// Returns the value of PC at the given location in recorded history.
  ///
  /// \param[in] location
  ///     The location in recorded history whose PC value to return.
  ///
  /// \return
  ///     The value of PC at the given location in recorded history, if any;
  ///     `LLDB_INVALID_ADDRESS` otherwise.
  ///
  lldb::addr_t GetPC(Thread::TracepointID location);

  /// Creates a bookmark at the requested location in recorded history.
  ///
  /// \param[in] location
  ///     The location in recorded history to be marked by the bookmark.
  ///
  /// \param[in] name
  ///     The name of the bookmark.
  ///
  /// \return
  ///     An error value, in case bookmark creation fails.
  ///
  Status CreateBookmark(Thread::TracepointID location,
                        std::string_view name = {});

  /// Deletes the bookmark marking the requested location.
  ///
  /// \param[in] location
  ///     The location marked by the bookmark.
  ///
  /// \return
  ///     An error value, in case bookmark deletion fails.
  ///
  Status DeleteBookmark(Thread::TracepointID location);

  /// Returns the bookmark marking the requested location.
  ///
  /// \param[in] location
  ///     The location in recorded history marked by the bookmark.
  ///
  /// \return
  ///     The bookmark marking the requested location, if any.
  ///
  llvm::Expected<const Thread::TracingBookmark &>
  GetBookmark(Thread::TracepointID location) const;

  /// Returns a collection with references to all bookmarks.
  ///
  /// \return
  ///     A collection with references to all bookmarks.
  ///
  Thread::ΤracingBookmarkList GetAllBookmarks() const;

  /// Restores the thread's state to the point in time marked by the bookmark.
  ///
  /// \param[in] location
  ///     The location within recorded history marked by the bookmark.
  ///
  /// \return
  ///     An error value, in case thread state restoration fails.
  ///
  Status JumpToBookmark(Thread::TracepointID location);

  /// Renames the bookmark marking the given location.
  ///
  /// \param[in] location
  ///     The location in recorded history marked by the bookmark.
  ///
  /// \param[in] name
  ///     The new name of the bookmark.
  ///
  /// \return
  ///     An error value, in case bookmark renaming fails.
  ///
  Status RenameBookmark(Thread::TracepointID location, std::string_view name);

  /// Moves the bookmark from the current location to a new one.
  ///
  /// \param[in] old_location
  ///     The location in recorded history currently marked by the bookmark.
  ///
  /// \param[in] new_location
  ///     The location in recorded history to be marked by the bookmark.
  ///
  /// \return
  ///     An error value, in case bookmark moving fails.
  ///
  Status MoveBookmark(Thread::TracepointID old_location,
                      Thread::TracepointID new_location);

protected:
  /// Initializes this tracer.
  ///
  void TracingStarted() override;

  /// Cleans up this tracer.
  ///
  void TracingEnded() override;

  /// Disables all artificial breakpoints.
  ///
  void TracingSuspendRequested() override;

  /// Checks and updates captured register and frame variable values, in case
  /// they were modified while tracing was suspended, and enables all artificial
  /// breakpoints.
  ///
  void TracingResumed() override;

  /// Restores the current snapshot, because the thread state is modified
  /// during expression evaluation.
  ///
  void ExpressionEvaluationFinished() override;

  /// Saves a snapshot of the thread state, as long as this tracer is enabled.
  ///
  /// \note
  ///     Called before each instruction is executed, if tracing is enabled.
  ///
  void Log() override;

  /// Returns `true` if the given token has higher privilege than the currently
  /// held one, if any (see `Thread::TracingToken` for more details).
  ///
  /// \param[in] token
  ///     The token whose privilege to check against the current one.
  ///
  /// \return
  ///     `true` if the given token has higher privilege than the current one.
  ///
  bool ShouldAcceptToken(Thread::TracingToken token) const override;

private:
  using StackFrameRegisterValues = std::unordered_map<std::size_t,
                                                      RegisterValue>;
  using StackFrameVariableValues = std::unordered_map<std::size_t,
                                                      DataExtractor>;
  using RegisterValues = std::vector<StackFrameRegisterValues>;
  using VariableValues = std::vector<StackFrameVariableValues>;
  using ThreadPlans = std::vector<lldb::ThreadPlanSP>;
  using StackFrames = StackFrameList::StackFrameListCheckpointUP;

  /// \struct HeapData
  ///
  /// Snapshot of a heap region at a certain point in time.
  ///
  struct HeapData {
    /// Constructs this `HeapData` object.
    ///
    /// \param[in] address
    ///     The original address of the saved heap region.
    ///
    /// \param[in] data
    ///     A copy of the data contained in the saved heap region.
    ///
    HeapData(lldb::addr_t address, DataBufferHeap &&data);

    /// Enable move construction and assignment.
    ///
    HeapData(HeapData &&);
    HeapData &operator=(HeapData &&);

    /// Disable copy construction and assignment.
    ///
    DISALLOW_COPY_AND_ASSIGN(HeapData);

    /// Destructs this `HeapData` object.
    ///
    ~HeapData();

    lldb::addr_t address; ///< The original address of the saved heap region.
    DataBufferHeap data; ///< The data contained in the saved heap region.
  };

  /// \struct Tracepoint
  ///
  /// Snapshot of the traced thread's state at a certain point in time.
  ///
  struct Tracepoint {
    /// Constructs this `Tracepoint` object.
    ///
    /// \param[in] registers
    ///     The values of stack frame registers at this point in time.
    ///
    /// \param[in] variables
    ///     The values of stack frame variables at this point in time.
    ///
    /// \param[in] frames
    ///     The stack frames present when the thread stopped.
    ///
    /// \param[in] stop_info
    ///     The stop reason of the thread.
    ///
    /// \param[in] completed_plans
    ///     The thread plans completed by the stop.
    ///
    /// \param[in] line
    ///     The source line at this point in time, if available.
    ///
    Tracepoint(RegisterValues &&registers, VariableValues &&variables,
               StackFrames &&frames, lldb::StopInfoSP &&stop_info,
               ThreadPlans &&completed_plans,
               uint32_t line = LLDB_INVALID_LINE_NUMBER);

    /// Enable move construction and assignment.
    ///
    Tracepoint(Tracepoint &&);
    Tracepoint &operator=(Tracepoint &&);

    /// Disable copy construction and assignment.
    ///
    DISALLOW_COPY_AND_ASSIGN(Tracepoint);

    /// Destructs this `Tracepoint` object.
    ///
    ~Tracepoint();

    RegisterValues registers; ///< The values of stack frame registers.
    VariableValues variables; ///< The values of stack frame variables.
    llvm::Optional<HeapData> heap_data; ///< The contents of a heap region right
                                        ///< before being overwritten by an
                                        ///< instruction that modifies the
                                        ///< region, if applicable.
    uint32_t frame_depth; ///< The depth of the deepest stack frame.
    StackFrames frames; ///< The stack frames present when the thread stoppped.
    lldb::StopInfoSP stop_info; ///< The stop reason of the thread.
    ThreadPlans completed_plans; ///< The thread plans completed by the stop.
    uint32_t line; ///< The source line at this point in time, if available.
  };

  using Timeline = std::vector<Tracepoint>;
  using Bookmarks = std::unordered_map<Thread::TracepointID,
                                       Thread::TracingBookmark>;
  using TracepointCallback = std::function<Status(Tracepoint &)>;

  /// \enum NavigationDirection
  ///
  /// Indicates the direction in which the timeline is traversed in order to
  /// step back or replay.
  ///
  enum NavigationDirection : bool {
    Forward,
    Reverse
  };

  /// Navigates through recorded history for the given number of statements,
  /// stepping into calls.
  ///
  /// \param[in] num_statements
  ///     The number of statements to step back.
  ///
  /// \param[in] direction
  ///     The direction in which to navigate through recorded history.
  ///
  /// \return
  ///     An error value, in case navigation fails.
  ///
  Status Navigate(std::size_t num_statements, NavigationDirection direction);

  /// Navigates through recorded history until reaching the requested address.
  ///
  /// \param[in] address
  ///     The target PC address.
  ///
  /// \param[in] direction
  ///     The direction in which to navigate through recorded history.
  ///
  /// \return
  ///     An error value, in case navigation fails or address is not found.
  ///
  Status NavigateToAddress(lldb::addr_t address, NavigationDirection direction);

  /// Navigates through recorded history until reaching the requested line.
  ///
  /// \param[in] line
  ///     The target line.
  ///
  /// \param[in] direction
  ///     The direction in which to navigate through recorded history.
  ///
  /// \return
  ///     An error value, in case navigation fails or line is not found.
  ///
  Status NavigateToLine(uint32_t line, NavigationDirection direction);

  /// Navigates through recorded history until out of current function or limit
  /// of history.
  ///
  /// \param[in] direction
  ///     The direction in which to navigate through recorded history.
  ///
  /// \return
  ///     An error value, in case navigation fails.
  ///
  Status NavigateUntilOutOfFunction(NavigationDirection direction);

  /// Navigates through recorded history until a breakpoint is hit or limit of
  /// history is reached.
  ///
  /// \param[in] direction
  ///     The direction in which to navigate through recorded history.
  ///
  /// \param[out] canonical_breakpoint_id
  ///     The canonical ID of the breakpoint responsible for the stop, if any.
  ///
  /// \return
  ///     An error value, in case navigation fails.
  ///
  Status ContinueInTimeline(NavigationDirection direction,
                            Stream &canonical_breakpoint_id);

  /// Saves a snapshot of the thread.
  ///
  void CaptureSnapshot();

  /// Restores the snapshot with the supplied ID.
  ///
  /// \param[in] tracepoint_id
  ///     The ID of the snapshot to restore.
  ///
  void RestoreSnapshot(Thread::TracepointID tracepoint_id);

  /// Clears all recorded history following the current instruction, if the user
  /// stepped or continued forward while the thread state was being emulated by
  /// this tracer.
  ///
  void ClearSubsequentRecordingHistoryIfNeeded();

  /// Returns the values of registers that belong to the given stack frame.
  ///
  /// \param[in] frame
  ///     The stack frame whose register values to save.
  ///
  /// \return
  ///     A list containing the values of the stack frame registers.
  ///
  StackFrameRegisterValues GetStackFrameRegisterValues(StackFrame &frame);

  /// Returns the values of variables that belong to the given stack frame.
  ///
  /// \param[in] frame
  ///     The stack frame whose variable values to save.
  ///
  /// \return
  ///     A list containing the values of the stack frame variables.
  ///
  StackFrameVariableValues GetStackFrameVariableValues(StackFrame &frame);

  /// Returns a copy of the data located at the given heap region.
  ///
  /// \param[in] address
  ///     The address of the heap region to save.
  ///
  /// \param[in] size
  ///     The size of the heap region to save.
  ///
  /// \return
  ///     A copy of the data located at the given heap region, on success.
  ///
  llvm::Optional<HeapData> GetHeapData(lldb::addr_t address,
                                       lldb::offset_t size);

  /// Writes the given saved data back to the heap.
  ///
  /// \param[in] heap_data
  ///     The saved heap data to restore.
  ///
  void RestoreHeapData(const HeapData &heap_data);

  /// Saves the new contents of the heap region written by the previous store
  /// instruction, if any.
  ///
  void SaveRecentlyStoredHeapDataIfNeeded();

  /// Restores the given values of registers in the given stack frame.
  ///
  /// \param[in] frame
  ///     The stack frame whose register values to restore.
  ///
  /// \param[in] registers
  ///     The stack frame register values to restore.
  ///
  void RestoreStackFrameRegisters(StackFrame &frame,
                                  StackFrameRegisterValues &registers);

  /// Restores the given values of variables in the given stack frame.
  ///
  /// \param[in] frame
  ///     The stack frame whose variable values to restore.
  ///
  /// \param[in] variables
  ///     The stack frame variable values to restore.
  ///
  void RestoreStackFrameVariables(StackFrame &frame,
                                  StackFrameVariableValues &variables);

  /// Sequentially applies all heap modifications recorded in the snapshot
  /// before the current one and up to the provided destination.
  ///
  /// \pre
  ///     The destination snapshot must be older than the current one.
  ///
  /// \param[in] destination
  ///     The ID of the destination snapshot.
  ///
  void UndoHeapWritesUpTo(Thread::TracepointID destination);

  /// Sequentially applies all heap modifications recorded in the current
  /// snapshot and up to the one before the provided destination.
  ///
  /// \pre
  ///     The destination snapshot must be newer than the current one.
  ///
  /// \param[in] destination
  ///     The ID of the destination snapshot.
  ///
  void RedoHeapWritesUpTo(Thread::TracepointID destination);

  /// Saves the contents of the heap region about to be overwritten by the given
  /// instruction, if any.
  ///
  /// \param[in] store_instruction
  ///     The instruction that may store.
  ///
  /// \note
  ///     Currently, only basic x86 instructions are supported.
  ///
  void HandleInstructionThatMayStore(Instruction &store_instruction);

  /// Handles calls to functions that should be executed, but not traced, and
  /// calls to deallocation functions that should not be executed at all.
  ///
  /// \param[in] call_instruction
  ///     The call instruction.
  ///
  /// \param[in] instruction_after_call
  ///     The instruction after the call.
  ///
  void HandleCallInstruction(Instruction &call_instruction,
                             Instruction &instruction_after_call);

  /// Suspends thread tracing and single stepping to prevent tracing unwanted
  /// symbols and speed up execution.
  ///
  /// Also, sets an artificial breakpoint at the instruction after the call in
  /// order to continue tracing after the call has finished.
  ///
  /// \param[in] instruction_after_call_address
  ///     The address of the instruction right after the call.
  ///
  /// \note
  ///     The `target.process.thread.tracing-avoid-symbols-regex` and
  ///     `target.process.thread.tracing-avoid-libraries` settings allow the
  ///     user to define additional functions to avoid.
  ///
  void HandleCallTargetToAvoid(lldb::addr_t instruction_after_call_address);

  /// Returns `true` if the given call target is a symbol to avoid.
  ///
  /// \param[in] call_target
  ///     The demangled name of the called function.
  ///
  /// \return
  ///     `true` if the given call target is a symbol to avoid.
  ///
  bool ShouldAvoidCallTarget(llvm::StringRef call_target) const;

  /// Resumes tracing and single stepping, if suspended by the tracer itself
  /// before calling a symbol to avoid.
  ///
  /// \param[in] baton
  ///     A generic pointer that will be passed to the callback when invoked.
  ///
  /// \param[in] context
  ///     The execution context of the callback.
  ///
  /// \param[in] breakpoint_id
  ///     The breakpoint ID.
  ///
  /// \param[in] breakpoint_location_id
  ///     The breakpoint location ID.
  ///
  /// \return
  ///     `true` if the target should stop.
  ///
  static bool AvoidedSymbolBreakpointHitCallback(
      void *baton, StoppointCallbackContext *context,
      lldb::user_id_t breakpoint_id, lldb::user_id_t breakpoint_location_id);

  /// Disassembles and returns the requested number of instructions starting
  /// from the current one.
  ///
  /// \param[in] num_instructions
  ///     The number of instructions to disassemble.
  ///
  /// \return
  ///     The disassembled instructions, if successful.
  ///
  llvm::Expected<InstructionList &>
  DisassembleInstructions(std::size_t num_instructions) const;

  /// Returns the breakpoint that resolves to the given address, if any.
  ///
  /// \param[in] address
  ///     The address of the breakpoint to look for.
  ///
  /// \return
  ///     The breakpoint that resolves to the given address, if found.
  ///
  llvm::Expected<Breakpoint &> GetBreakpointAtAddress(lldb::addr_t address);

  /// Returns the recorded PC value for the stack frame with the given ID from
  /// the provided snapshot.
  ///
  /// \param[in] snapshot
  ///     The snapshot holding the recorded state of the stack frame at a
  ///     certain point in time.
  ///
  /// \param[in] frame_idx
  ///     The index of the stack frame whose PC value to get.
  ///
  /// \return
  ///     The recorded PC value for the stack frame with the given ID from
  ///     the provided snapshot.
  ///
  lldb::addr_t GetRecordedPCForStackFrame(Tracepoint &snapshot,
                                          std::size_t frame_idx = 0);

  /// Calculates the address described by the provided instruction operand.
  ///
  /// \param[in] operand
  ///     The instruction operand describing the address.
  ///
  /// \return
  ///     The address described by the provided instruction operand, if valid;
  ///     `LLDB_INVALID_ADDRESS` otherwise.
  ///
  lldb::addr_t
  CalculateAddressFromOperand(const Instruction::Operand &operand) const;

  /// Returns `true` if this tracer has been suspended for internal reasons,
  /// such as to avoid tracing a symbol.
  ///
  /// \return
  ///     `true` if this tracer has been suspended for internal reasons.
  ///
  bool HasBeenSuspendedInternally() const;

  /// Steps back until `predicate` returns a success status or beginning of
  /// history is reached.
  ///
  /// \param[in] predicate
  ///     Executed on each iteration. A successful return status ends stepping.
  ///
  /// \param[in] initializer
  ///     Called before stepping with the current tracepoint as argument.
  ///     A failed return status makes the function return immediately.
  ///
  /// \param[in] past_begin
  ///     Called in case the stepping loop reaches past beginning of history.
  ///
  /// \return
  ///     An error value, in case stepping back fails.
  ///
  Status StepBackInternal(
      TracepointCallback &&predicate,
      TracepointCallback &&initializer = GetDefaultTracepointCallback(),
      TracepointCallback &&past_begin = GetDefaultTracepointCallback());

  /// Replays until `predicate` returns a success status or end of history is
  /// reached.
  ///
  /// \param[in] predicate
  ///     Executed on each iteration. A successful return status ends replay.
  ///
  /// \param[in] initializer
  ///     Called before replaying with the current tracepoint as argument.
  ///     A failed return status makes the function return immediately.
  ///
  /// \param[in] past_end
  ///     Called in case the replay loop reaches past end of history.
  ///
  /// \return
  ///     An error value, in case replay fails.
  ///
  Status ReplayInternal(
      TracepointCallback &&predicate,
      TracepointCallback &&initializer = GetDefaultTracepointCallback(),
      TracepointCallback &&past_end = GetDefaultTracepointCallback());

  /// Traverses the recorded history.
  ///
  /// \param[in] predicate
  ///     Executed on each iteration. A successful return status ends the loop.
  ///
  /// \param[in] initializer
  ///     Called before the loop with the current tracepoint as argument.
  ///     A failed return status makes the function return immediately.
  ///
  /// \param[in] past_limit
  ///     Called in case the loop reaches past the limits of history.
  ///
  /// \return
  ///     The number of instructions to step back or replay.
  ///
  /// \note
  ///     Helper function for `StepBackInternal()` and `ReplayInternal()`.
  ///
  template<typename TimelineIteratorType>
  llvm::Expected<std::size_t> TraverseTimeline(
      const TimelineIteratorType &current_tracepoint,
      const TimelineIteratorType &timeline_limit,
      TracepointCallback &&predicate,
      TracepointCallback &&initializer,
      TracepointCallback &&past_limit);

  /// Returns a callback with an empty body, accepted by `StepBackInternal()`
  /// and `ReplayInternal().
  ///
  /// \return
  ///     A callback that always returns a successful status.
  ///
  static inline TracepointCallback GetDefaultTracepointCallback();

  /// Prints the given formatted message to the default logging stream using
  /// the prefix "error: " and a newline in the end.
  ///
  /// \param[in] format
  ///     The error message format.
  ///
  /// \param[in] args
  ///     The replacement parameters.
  ///
  template <typename... Args>
  void FormatError(llvm::StringRef format, Args &&... args) const;

  Target *m_target; ///< The target that owns the thread being traced.

  lldb::DisassemblerSP m_disassembler_sp; ///< The disassembler used to decode
                                          ///< the instructions of the current
                                          ///< target.

  Timeline m_timeline; ///< Holds the per-instruction snapshots that make up the
                       ///< thread's recorded history.

  Thread::TracepointID m_current_tracepoint; ///< The current point in time in
                                             ///< the thread's recorded history.

  Bookmarks m_bookmarks; ///< Holds the bookmarks to points of interest in the
                         ///< thread's recorded history.

  std::vector<lldb::user_id_t> m_artificial_breakpoint_ids; ///< Breakpoints set
                                                            ///< after calls to
                                                            ///< avoided symbols
                                                            ///< in order to
                                                            ///< resume tracing.

  bool m_stepped_while_suspended; ///< Used to avoid capturing program state at
                                  ///< a particular point in time more than once
                                  ///< in case the user suspends and resumes
                                  ///< tracing while the thread is stopped at
                                  ///< the same instruction.

  bool m_artificial_step; ///< Set if stepping back while tracing is suspended
                          ///< by the tracer itself in order to avoid tracing an
                          ///< unwanted symbol. It is used to prevent capturing
                          ///< a duplicate snapshot when tracing is resumed.

  bool m_stepped_back; ///< This flag is set when stepping backwards, so that
                       ///< the tracer can discard recorded history following
                       ///< the current instruction when the thread continues
                       ///< or steps forward.

  bool m_modified_heap; ///< Set when an instruction that writes to the heap is
                        ///< detected, in order to denote that the newly written
                        ///< data need to be backed up right after the store,
                        ///< so as to be able to restore them when replaying.

  bool m_emulating_stack_frames; ///< Denotes whether the state of the active
                                 ///< stack frames is currently being emulated
                                 ///< by this tracer in order to mimic a
                                 ///< previous point in time.

  static inline ThreadPlanInstructionTracer *m_this; ///< Pointer to self, to
                                                     ///< enable calling
                                                     ///< non-static methods
                                                     ///< from static ones.

  DISALLOW_COPY_AND_ASSIGN(ThreadPlanInstructionTracer);
};

} // namespace lldb_private

#endif // LLDB_TARGET_THREADPLANTRACER_H
