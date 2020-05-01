//===-- ThreadPlanTracer.cpp ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Breakpoint/BreakpointLocation.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Disassembler.h"
#include "lldb/Core/DumpDataExtractor.h"
#include "lldb/Core/DumpRegisterValue.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Core/Value.h"
#include "lldb/Core/ValueObject.h"
#include "lldb/Symbol/TypeList.h"
#include "lldb/Symbol/TypeSystem.h"
#include "lldb/Symbol/VariableList.h"
#include "lldb/Target/ABI.h"
#include "lldb/Target/MemoryRegionInfo.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/SectionLoadList.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/ThreadPlan.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/State.h"

using namespace lldb;
using namespace lldb_private;

#pragma mark ThreadPlanTracer

ThreadPlanTracer::ThreadPlanTracer(Thread &thread, StreamSP &stream_sp)
    : m_process(*thread.GetProcess().get()), m_tid(thread.GetID()),
      m_single_step(true), m_state(State::eDisabled),
      m_token(TracingToken::Invalid), m_evaluating_expression(false),
      m_stream_sp(stream_sp), m_thread(nullptr) {}

ThreadPlanTracer::ThreadPlanTracer(Thread &thread)
    : m_process(*thread.GetProcess().get()), m_tid(thread.GetID()),
      m_single_step(true), m_state(State::eDisabled),
      m_token(TracingToken::Invalid), m_evaluating_expression(false),
      m_stream_sp(), m_thread(nullptr) {}

ThreadPlanTracer::Type ThreadPlanTracer::GetType() const {
  return Type::eBase;
}

ThreadPlanTracer::State ThreadPlanTracer::GetState() const {
  return m_state;
}

bool ThreadPlanTracer::GetEvaluatingExpression() const {
  return m_evaluating_expression;
}

TracingToken ThreadPlanTracer::GetTracingToken() const {
  return m_token;
}

void ThreadPlanTracer::SetToken(TracingToken token) {
  m_token = token;
}

void ThreadPlanTracer::EnableTracing() {
  if (m_state == State::eDisabled) {
    m_state = State::eEnabled;
    SetToken(TracingToken::Invalid);
    TracingStarted();
  }
}

void ThreadPlanTracer::DisableTracing() {
  if (m_state != State::eDisabled) {
    m_state = State::eDisabled;
    SetToken(TracingToken::Invalid);
    TracingEnded();
  }
}

void ThreadPlanTracer::SuspendTracing(TracingToken token) {
  if (m_state == State::eDisabled) {
    return;
  }
  if (token == TracingToken::ExpressionEvaluation) {
    if (!m_evaluating_expression) {
      m_evaluating_expression = true;
      ExpressionEvaluationStarted();
    }
  }
  if (!ShouldAcceptToken(token)) {
    return;
  }
  TracingSuspendRequested();
  if (m_state == State::eEnabled) {
    m_state = State::eSuspended;
    SetToken(token);
    DisableSingleStepping();
    TracingSuspended();
  }
}

void ThreadPlanTracer::ResumeTracing(TracingToken token) {
  if (m_state == State::eDisabled) {
    return;
  }
  if (token == TracingToken::ExpressionEvaluation) {
    if (m_evaluating_expression) {
      m_evaluating_expression = false;
      ExpressionEvaluationFinished();
    }
  }
  if (!ShouldAcceptToken(token)) {
    return;
  }
  if (m_state == State::eSuspended) {
    m_state = State::eEnabled;
    SetToken(TracingToken::Invalid);
    EnableSingleStepping();
    TracingResumed();
  }
}

void ThreadPlanTracer::EnableSingleStepping() {
  m_single_step = true;
}

void ThreadPlanTracer::DisableSingleStepping() {
  assert("Disabling single-stepping while tracing is enabled will lead to "
         "unwanted consequences! Suspend or disable tracing first." &&
         GetState() != State::eEnabled);
  m_single_step = false;
}

bool ThreadPlanTracer::SingleSteppingEnabled() const {
  return m_single_step;
}

Stream *ThreadPlanTracer::GetLogStream() const {
  if (m_stream_sp)
    return m_stream_sp.get();
  else {
    TargetSP target_sp(m_thread->CalculateTarget());
    if (target_sp)
      return &(target_sp->GetDebugger().GetOutputStream());
  }
  return nullptr;
}

Thread &ThreadPlanTracer::GetThread() {
  if (m_thread)
    return *m_thread;
    
  ThreadSP thread_sp = m_process.GetThreadList().FindThreadByID(m_tid);
  m_thread = thread_sp.get();
  return *m_thread;
}

void ThreadPlanTracer::Log() {
  SymbolContext sc;
  bool show_frame_index = false;
  bool show_fullpaths = false;

  Stream *stream = GetLogStream();
  if (stream) {
    GetThread().GetStackFrameAtIndex(0)->Dump(stream, show_frame_index,
                                              show_fullpaths);
    stream->Printf("\n");
    stream->Flush();
  }
}

bool ThreadPlanTracer::TracerExplainsStop() {
  if (m_state == State::eEnabled && m_single_step) {
    lldb::StopInfoSP stop_info = GetThread().GetStopInfo();
    return (stop_info->GetStopReason() == eStopReasonTrace);
  } else
    return false;
}

#pragma mark ThreadPlanAssemblyTracer

ThreadPlanAssemblyTracer::ThreadPlanAssemblyTracer(Thread &thread,
                                                   StreamSP &stream_sp)
    : ThreadPlanTracer(thread, stream_sp), m_disassembler_sp(), m_intptr_type(),
      m_register_values() {}

ThreadPlanAssemblyTracer::ThreadPlanAssemblyTracer(Thread &thread)
    : ThreadPlanTracer(thread), m_disassembler_sp(), m_intptr_type(),
      m_register_values() {}

Disassembler *ThreadPlanAssemblyTracer::GetDisassembler() {
  if (!m_disassembler_sp)
    m_disassembler_sp = Disassembler::FindPlugin(
        m_process.GetTarget().GetArchitecture(), nullptr, nullptr);
  return m_disassembler_sp.get();
}

TypeFromUser ThreadPlanAssemblyTracer::GetIntPointerType() {
  if (!m_intptr_type.IsValid()) {
    if (auto target_sp = m_process.CalculateTarget()) {
      auto type_system_or_err =
          target_sp->GetScratchTypeSystemForLanguage(eLanguageTypeC);
      if (auto err = type_system_or_err.takeError()) {
        LLDB_LOG_ERROR(
            lldb_private::GetLogIfAnyCategoriesSet(LIBLLDB_LOG_TYPES),
            std::move(err),
            "Unable to get integer pointer type from TypeSystem");
      } else {
        m_intptr_type = TypeFromUser(
            type_system_or_err->GetBuiltinTypeForEncodingAndBitSize(
                eEncodingUint,
                target_sp->GetArchitecture().GetAddressByteSize() * 8));
      }
    }
  }
  return m_intptr_type;
}

ThreadPlanAssemblyTracer::~ThreadPlanAssemblyTracer() = default;

ThreadPlanTracer::Type ThreadPlanAssemblyTracer::GetType() const {
  return Type::eAssembly;
}

void ThreadPlanAssemblyTracer::TracingEnded() {
  m_register_values.clear();
}

void ThreadPlanAssemblyTracer::Log() {
  if (GetState() == State::eSuspended)
    return;

  Stream *stream = GetLogStream();

  if (!stream)
    return;

  RegisterContext *reg_ctx = GetThread().GetRegisterContext().get();

  lldb::addr_t pc = reg_ctx->GetPC();
  Address pc_addr;
  bool addr_valid = false;
  uint8_t buffer[16] = {0}; // Must be big enough for any single instruction
  addr_valid = m_process.GetTarget().GetSectionLoadList().ResolveLoadAddress(
      pc, pc_addr);

  pc_addr.Dump(stream, &GetThread(), Address::DumpStyleResolvedDescription,
               Address::DumpStyleModuleWithFileAddress);
  stream->PutCString(" ");

  Disassembler *disassembler = GetDisassembler();
  if (disassembler) {
    Status err;
    m_process.ReadMemory(pc, buffer, sizeof(buffer), err);

    if (err.Success()) {
      DataExtractor extractor(buffer, sizeof(buffer), m_process.GetByteOrder(),
                              m_process.GetAddressByteSize());

      bool data_from_file = false;
      if (addr_valid)
        disassembler->DecodeInstructions(pc_addr, extractor, 0, 1, false,
                                         data_from_file);
      else
        disassembler->DecodeInstructions(Address(pc), extractor, 0, 1, false,
                                         data_from_file);

      InstructionList &instruction_list = disassembler->GetInstructionList();
      const uint32_t max_opcode_byte_size =
          instruction_list.GetMaxOpcocdeByteSize();

      if (instruction_list.GetSize()) {
        const bool show_bytes = true;
        const bool show_address = true;
        Instruction *instruction =
            instruction_list.GetInstructionAtIndex(0).get();
        const FormatEntity::Entry *disassemble_format =
            m_process.GetTarget().GetDebugger().GetDisassemblyFormat();
        instruction->Dump(stream, max_opcode_byte_size, show_address,
                          show_bytes, nullptr, nullptr, nullptr,
                          disassemble_format, 0);
      }
    }
  }

  const ABI *abi = m_process.GetABI().get();
  TypeFromUser intptr_type = GetIntPointerType();

  if (abi && intptr_type.IsValid()) {
    ValueList value_list;
    const int num_args = 1;

    for (int arg_index = 0; arg_index < num_args; ++arg_index) {
      Value value;
      value.SetValueType(Value::eValueTypeScalar);
      value.SetCompilerType(intptr_type);
      value_list.PushValue(value);
    }

    if (abi->GetArgumentValues(GetThread(), value_list)) {
      for (int arg_index = 0; arg_index < num_args; ++arg_index) {
        stream->Printf(
            "\n\targ[%d]=%llx", arg_index,
            value_list.GetValueAtIndex(arg_index)->GetScalar().ULongLong());

        if (arg_index + 1 < num_args)
          stream->PutCString(", ");
      }
    }
  }

  if (m_register_values.empty()) {
    RegisterContext *reg_ctx = GetThread().GetRegisterContext().get();
    m_register_values.resize(reg_ctx->GetRegisterCount());
  }

  RegisterValue reg_value;
  for (size_t reg_num = 0, num_registers = reg_ctx->GetRegisterCount();
       reg_num < num_registers; ++reg_num) {
    const RegisterInfo *reg_info = reg_ctx->GetRegisterInfoAtIndex(reg_num);
    if (reg_ctx->ReadRegister(reg_info, reg_value)) {
      assert(reg_num < m_register_values.size());
      if (m_register_values[reg_num].GetType() == RegisterValue::eTypeInvalid ||
          reg_value != m_register_values[reg_num]) {
        if (reg_value.GetType() != RegisterValue::eTypeInvalid) {
          stream->PutCString("\n\t");
          DumpRegisterValue(reg_value, stream, reg_info, true, false,
                            eFormatDefault);
        }
      }
      m_register_values[reg_num] = reg_value;
    }
  }
  stream->EOL();
  stream->Flush();
}

#pragma mark Static Functions & Constants

using RegisterCallback = std::function<void(const RegisterInfo *, std::size_t)>;
using StackFrameCallback = std::function<void(StackFrame &)>;
using ValueObjectCallback = std::function<void(ValueObject *, std::size_t)>;

constexpr auto max_register_set_id = std::numeric_limits<std::size_t>::max();

// Currently, the tracer recognizes exception state registers only on Darwin.
#if defined(__APPLE__)
constexpr auto exc_register_set_id = 2;
#else
constexpr auto exc_register_set_id = max_register_set_id;
#endif

/// Maximum size in bytes of x86 `NOP` instruction opcode.
constexpr auto max_i386_nop_opcode_size = 9;

/// Opcodes of x86 `NOP` instruction.
constexpr uint8_t i386_nop_opcodes[][max_i386_nop_opcode_size] {
  {0x90},
  {0x66, 0x90},
  {0x0f, 0x1f, 0x00},
  {0x0f, 0x1f, 0x40, 0x00},
  {0x0f, 0x1f, 0x44, 0x00, 0x00},
  {0x66, 0x0f, 0x1f, 0x40, 0x00, 0x00},
  {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
  {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
  {0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}
};

/// Holds a backup of an instruction opcode that was replaced with `NOP` and is
/// pending restoration.
///
static struct {
  /// Sets the original location of the saved opcode.
  ///
  void SetLocation(addr_t address, std::size_t opcode_size) {
    this->address = address;
    this->opcode_size = opcode_size;
  }

  /// Clears the saved opcode.
  ///
  void Clear() {
    ::memset(opcode, 0, opcode_size);
    SetLocation(LLDB_INVALID_ADDRESS, 0);
  }

  /// Returns `true` if there is a saved opcode pending restoration.
  ///
  /// \return
  ///     `true` if there is a saved opcode pending restoration.
  ///
  bool IsPendingRestoration() {
    return address != LLDB_INVALID_ADDRESS;
  }

  addr_t address = LLDB_INVALID_ADDRESS; ///< The address of the saved opcode.
  uint8_t opcode[max_i386_nop_opcode_size]; ///< The opcode replaced with `NOP`.
  std::size_t opcode_size = 0; ///< The size of the opcode in bytes.
} opcode_backup;

/// Returns `true` if the register with the provided ID is characterized as an
/// exception state register in the given register context.
///
/// \param[in] register_context
///     The register context containing the register.
///
/// \param[in] register_id
///     The ID of the register to check.
///
/// \return
///     `true` if the register with the provided ID is characterized as an
///     exception state register in the given register context.
///
constexpr bool IsExceptionStateRegister(RegisterContext &register_context,
                                        std::size_t register_id) {
  if constexpr (exc_register_set_id == max_register_set_id) {
    return false;
  }

  const RegisterSet *exc_register_set =
      register_context.GetRegisterSet(exc_register_set_id);
  const std::size_t num_registers = exc_register_set->num_registers;

  for (std::size_t exc_reg_id = 0; exc_reg_id < num_registers; ++exc_reg_id) {
    if (exc_register_set->registers[exc_reg_id] == register_id) {
      return true;
    }
  }
  return false;
}

/// Returns `true` if the given function is a known deallocation function.
///
/// \param[in] function_name
///     The name of the function.
///
/// \return
///     `true` if the given function is a known deallocation function.
///
static bool IsDeallocationFunction(llvm::StringRef function_name) {
  static const std::set<llvm::StringRef> dealloc_funcs = {"free", "munmap"};
  return dealloc_funcs.find(function_name) != dealloc_funcs.end();
}

/// Returns `true` if the given function belongs to a library whose symbols
/// shall not be traced.
///
/// \param[in] target
///     The current target.
///
/// \param[in] thread
///     The thread being traced.
///
/// \param[in] function_name
///     The name of the function to search for.
///
/// \return
///     `true` if the given function belongs to a library whose symbols shall
///     not be traced.
///
static bool IsLibraryFunctionToAvoid(Target &target, Thread &thread,
                                     ConstString function_name) {
  static std::map<std::size_t, bool> lib_funcs;

  // Hash the function name and check whether the result is already cached.
  const std::size_t name_hash = llvm::hash_value(function_name.GetStringRef());
  if (auto iter = lib_funcs.find(name_hash); iter != lib_funcs.end()) {
    return std::get<bool>(*iter);
  }

  // Look up the function in all loaded modules.
  SymbolContextList sc_list;
  constexpr bool include_symbols = true;
  constexpr bool include_inlines = true;
  target.GetImages().FindFunctions(function_name, eFunctionNameTypeAuto,
                                   include_symbols, include_inlines, sc_list);

  // If the function is not found in any loaded module, make the assumption that
  // it belongs to a system library and thus ignore it.
  const std::size_t sc_list_size = sc_list.GetSize();
  if (sc_list_size == 0) {
    lib_funcs.emplace(name_hash, true);
    return true;
  }

  // Get the list of libraries whose symbols the user has opted not to trace.
  const FileSpecList libraries_to_avoid = thread.GetLibrariesToAvoidTracing();

  // Check whether the function belongs in a module that shall be ignored.
  for (std::size_t sc_idx = 0; sc_idx < sc_list_size; ++sc_idx) {
    SymbolContext sc;
    sc_list.GetContextAtIndex(sc_idx, sc);
    if (sc.module_sp) {
      const FileSpec module_spec = sc.module_sp->GetFileSpec();

      // In case the function in question belongs to a system library, avoid it.
      if (module_spec.GetDirectory().GetStringRef().startswith("/usr/lib")) {
        lib_funcs.emplace(name_hash, true);
        return true;
      }

      // Finally, avoid tracing the function if it belongs to a library that the
      // user has indicated not to trace.
      for (const FileSpec &library_to_avoid : libraries_to_avoid) {
        if (FileSpec::Match(module_spec, library_to_avoid)) {
          lib_funcs.emplace(name_hash, true);
          return true;
        }
      }
    }
  }

  lib_funcs.emplace(name_hash, false);
  return false;
}

/// Returns `true` if the address exists in the provided target or module.
///
/// \param[in] target
///     The target that provides the section load list to search.
///
/// \param[in] module
///     The module to find the address in.
///
/// \param[in] address
///     The address to search for.
///
/// \return
///     `true` if the address exists in the provided target or module.
///
static bool
LookupAddressInTargetModule(Target &target, Module *module, addr_t address) {
  const SectionLoadList &section_load_list = target.GetSectionLoadList();
  Address section_offset_address;

  if (!section_load_list.IsEmpty()) {
    if (!section_load_list.ResolveLoadAddress(address, section_offset_address)) {
      return false;
    } else if (section_offset_address.GetModule().get() != module) {
      return false;
    }
  } else {
    if (!module->ResolveFileAddress(address, section_offset_address)) {
      return false;
    }
  }

  return true;
}

/// Returns `true` if the address exists in a module of the provided target.
///
/// \param[in] target
///     The target providing the modules to search.
///
/// \param[in] address
///     The address to search for.
///
/// \return
///     `true` if the address exists in a module of the provided target.
///
static bool LookupAddressInTargetModules(Target &target, addr_t address) {
  const ModuleList &target_modules = target.GetImages();
  std::lock_guard<std::recursive_mutex> guard(target_modules.GetMutex());

  const std::size_t num_modules = target_modules.GetSize();

  for (std::size_t module_idx = 0; module_idx < num_modules; ++module_idx) {
    Module *module = target_modules.GetModulePointerAtIndexUnlocked(module_idx);
    if (LookupAddressInTargetModule(target, module, address)) {
      return true;
    }
  }

  return false;
}

/// Returns `true` if the address corresponds to the stack of the given thread.
///
/// \param[in] thread
///     The thread whose stack to check.
///
/// \param[in] address
///     The address to look up.
///
/// \return
///     `true` if the address corresponds to the stack of the given thread.
///
static bool IsStackAddress(Thread &thread, addr_t address) {
  static MemoryRegionInfo::RangeType stack_range;

  // Look up the stack range only if it hasn't already been cached.
  if (!stack_range.IsValid()) {
    MemoryRegionInfo stack_info;
    const addr_t sp = thread.GetRegisterContext()->GetSP();

    if (thread.GetProcess()->GetMemoryRegionInfo(sp, stack_info).Fail()) {
      llvm_unreachable("Unsupported process type!");
    }
    stack_range = stack_info.GetRange();
  }

  return address >= stack_range.GetRangeBase() &&
         address <= stack_range.GetRangeEnd();
}

/// Returns `true` if the address corresponds to the heap of the process owning
/// the provided thread.
///
/// \param[in] thread
///     The thread whose stack to check, in order to verify that the address
///     does not belong there.
///
/// \param[in] address
///     The address to look up.
///
/// \return
///     `true` if the address corresponds to the heap of the process owning
///     the provided thread.
///
static bool IsHeapAddress(Thread &thread, addr_t address) {
  static std::map<addr_t, bool> heap_addresses;

  // Check whether the result has already been cached.
  if (auto iter = heap_addresses.find(address); iter != heap_addresses.end()) {
    return std::get<bool>(*iter);
  }

  Target &target = *thread.CalculateTarget();
  const bool is_stack_address = IsStackAddress(thread, address);
  const bool exists_in_module = LookupAddressInTargetModules(target, address);
  const bool is_heap_address = !is_stack_address && !exists_in_module;

  heap_addresses.emplace(address, is_heap_address);
  return is_heap_address;
}

/// Constructs an `llvm::Error` using the provided error message.
///
/// \param[in] error_message
///     The error message to be packed into the error.
///
/// \return
///     An `llvm::Error` carrying the provided error message.
///
static inline llvm::Error MakeError(llvm::StringRef error_message) {
  return llvm::make_error<llvm::StringError>(error_message,
                                             llvm::inconvertibleErrorCode());
}

/// Constructs an `llvm::Error` using the provided format.
///
/// \param[in] format
///     The error message format.
///
/// \param[in] args
///     The replacement parameters.
///
/// \return
///     An `llvm::Error` carrying the provided error message.
///
template <typename... Args>
static inline llvm::Error MakeErrorWithFormat(llvm::StringRef format,
                                              Args &&... args) {
  std::string error_message = llvm::formatv(format.data(),
                                            std::forward<Args>(args)...).str();
  return MakeError(error_message);
}

/// Invokes the provided callback for each register in the register context.
///
/// \param[in] register_context
///     The register context whose registers to use as arguments.
///
/// \param[in] callback
///     The callback to invoke for each register.
///
static void
DoForEachRegister(RegisterContext &register_context,
                  RegisterCallback &&callback) {
  const std::size_t num_registers = register_context.GetRegisterCount();
  for (std::size_t reg_id = 0; reg_id < num_registers; ++reg_id) {
    callback(register_context.GetRegisterInfoAtIndex(reg_id), reg_id);
  }
}

/// Invokes the provided callback for each stack frame in the frame list.
///
/// \param[in] frames
///     The list that contains the stack frames to use as arguments.
///
/// \param[in] callback
///     The callback to invoke for each frame.
///
static void DoForEachStackFrame(StackFrameList &frames,
                                StackFrameCallback &&callback) {
  const std::size_t num_frames = frames.GetNumFrames();
  for (std::size_t frame_idx = 0; frame_idx < num_frames; ++frame_idx) {
    callback(*frames.GetFrameAtIndex(frame_idx));
  }
}

/// Invokes the provided callback for each value object in the stack frame.
///
/// \param[in] frame
///     The frame that contains the value objects to use as arguments.
///
/// \param[in] callback
///     The callback to invoke for each value object.
///
static void DoForEachValueObjectInStackFrame(StackFrame &frame,
                                             ValueObjectCallback &&callback) {
  VariableList *variable_list = frame.GetVariableList(true);
  if (!variable_list) {
    return;
  }
  const std::size_t num_variables = variable_list->GetSize();
  for (std::size_t var_id = 0; var_id < num_variables; ++var_id) {
    VariableSP variable = variable_list->GetVariableAtIndex(var_id);
    // FIXME: Ignore static members until the following issue is resolved:
    //        https://github.com/llvm/llvm-project/issues/146
    if (variable->IsStaticMember()) {
      continue;
    }
    ValueObjectSP value_object = frame.GetValueObjectForFrameVariable(
        variable, DynamicValueType::eNoDynamicValues);
    if (value_object && value_object->IsInScope()) {
      callback(value_object.get(), var_id);
    }
  }
}

/// Returns the demangled name of the function called by the given instruction.
///
/// \param[in] call_instruction
///     The call instruction.
///
/// \return
///     The demangled name of the function called by the given instruction, if
///     available; an empty string, otherwise.
///
static std::string GetDemangledCallTarget(Thread &thread,
                                          Instruction &call_instruction) {
  assert("Instruction must be a call!" && call_instruction.IsCall());
  ExecutionContext exe_ctx;
  thread.CalculateExecutionContext(exe_ctx);

  // Isolate the name of the called function.
  llvm::StringRef call_target(call_instruction.GetComment(&exe_ctx));
  if (!call_target.empty()) {
    call_target.consume_front("symbol stub for: ");
    call_target = call_target.split(' ').first;
  }

  return call_target.str();
}

/// Returns the number of bytes stored by an instruction, based on the mnemonic.
///
/// \param[in] instruction_mnemonic
///     The mnemonic of an instruction that may store.
///
/// \return
///     The number of bytes stored by an instruction, based on the mnemonic.
///
/// \note
///     Currently, only basic x86 instructions are supported.
///
static offset_t GetBytesStored(llvm::StringRef instruction_mnemonic) {
  switch (instruction_mnemonic.back()) {
  case 'b':
    return 1;
  case 'w':
    return 2;
  case 'l':
  case 's':
    return 4;
  case 'q':
  case 'd':
    return 8;
  default:
    llvm_unreachable("Unknown byte size!");
  }
}

/// Replaces the opcode at the given address with `NOP`.
///
/// \param[in] thread
///     The thread being traced.
///
/// \param[in] opcode_address
///     The address of the opcode to replace.
///
/// \param[in] opcode_size
///     The size of the opcode to replace.
///
/// \return
///     An error value, in case replacement failed.
///
static Status BackUpAndReplaceOpcodeWithNOP(Thread &thread,
                                            addr_t opcode_address,
                                            std::size_t opcode_size) {
  assert("There is already an opcode pending restoration!" &&
         !opcode_backup.IsPendingRestoration());

  // Save current opcode.
  Status error;
  thread.GetProcess()->ReadMemory(opcode_address, opcode_backup.opcode,
                                  opcode_size, error);
  if (error.Fail()) {
    return Status("Failed to read process memory: %s", error.AsCString());
  }
  opcode_backup.SetLocation(opcode_address, opcode_size);

  // Replace opcode with the appropriate NOP instruction, based on its size.
  thread.GetProcess()->WriteMemory(opcode_address,
                                   i386_nop_opcodes[opcode_size],
                                   opcode_size, error);
  if (error.Fail()) {
    return Status("Failed to write process memory: %s", error.AsCString());
  }

  return Status();
}

/// Restores the opcode that has been previously replaced with `NOP`.
///
/// \param[in] thread
///     The thread being traced.
///
/// \return
///     An error value, in case restoration failed.
///
static Status RestoreOpcodeBackup(Thread &thread) {
  assert("There is no opcode pending restoration!" &&
         opcode_backup.IsPendingRestoration());

  Status error;
  thread.GetProcess()->WriteMemory(opcode_backup.address, opcode_backup.opcode,
                                   opcode_backup.opcode_size, error);
  opcode_backup.Clear();

  return error.Fail()
             ? Status("Failed to write process memory: %s", error.AsCString())
             : Status();
}

#pragma mark HeapData

ThreadPlanInstructionTracer::HeapData::HeapData(addr_t base,
                                                DataBufferHeap &&data)
    : base(base), data(data), modified(false) {}

ThreadPlanInstructionTracer::HeapData::HeapData(HeapData &&) = default;

ThreadPlanInstructionTracer::HeapData::~HeapData() = default;

ThreadPlanInstructionTracer::HeapData &
ThreadPlanInstructionTracer::HeapData::operator=(HeapData &&) = default;

bool ThreadPlanInstructionTracer::HeapData::Contains(addr_t address) const {
  return address >= base && address <= (base + data.GetByteSize() - 1);
}

void ThreadPlanInstructionTracer::HeapData::Dump(Stream &stream) const {
  DumpHexBytes(&stream, data.GetBytes(), data.GetByteSize(), data.GetByteSize(),
               LLDB_INVALID_ADDRESS);
}

#pragma mark Tracepoint

ThreadPlanInstructionTracer::Tracepoint::Tracepoint(
  Thread::TracepointID id, RegisterValues &&registers,
  VariableValues &&variables, StackFrames &&frame_list, StopInfoSP &&stop_info,
  std::size_t completed_plan_checkpoint, uint32_t line)
    : id(id), registers(std::move(registers)), variables(std::move(variables)),
      frame_depth(frame_list->frames.size() - 1), frames(std::move(frame_list)),
      stop_info(std::move(stop_info)),
      completed_plan_checkpoint(completed_plan_checkpoint), line(line) {}

ThreadPlanInstructionTracer::Tracepoint::Tracepoint(Tracepoint &&) = default;

ThreadPlanInstructionTracer::Tracepoint::~Tracepoint() = default;

ThreadPlanInstructionTracer::Tracepoint &
ThreadPlanInstructionTracer::Tracepoint::operator=(Tracepoint &&) = default;

#pragma mark ThreadPlanInstructionTracer

ThreadPlanInstructionTracer::ThreadPlanInstructionTracer(Thread &thread)
  : ThreadPlanTracer(thread), m_thread(thread),
    m_current_tracepoint(Thread::InvalidTracepointID), m_bookmarks(),
    m_artificial_breakpoint_ids(), m_stepped_while_suspended(false),
    m_artificial_step(false), m_modified_heap(false),
    m_emulating_stack_frames(false) {
  InitializeSpecialFunctionHandlers();
}

ThreadPlanInstructionTracer::ThreadPlanInstructionTracer(Thread &thread,
                                                         StreamSP &stream_sp)
  : ThreadPlanTracer(thread, stream_sp), m_thread(thread),
    m_current_tracepoint(Thread::InvalidTracepointID), m_bookmarks(),
    m_artificial_breakpoint_ids(), m_stepped_while_suspended(false),
    m_artificial_step(false), m_emulating_stack_frames(false) {
  InitializeSpecialFunctionHandlers();
}

ThreadPlanInstructionTracer::~ThreadPlanInstructionTracer() {
  DisableTracing();
  m_tracers.erase(m_thread.GetID());
}

#pragma mark Base Class Methods

ThreadPlanTracer::Type ThreadPlanInstructionTracer::GetType() const {
  return Type::eInstruction;
}

void ThreadPlanInstructionTracer::TracingStarted() {
  InitializeStaticMembersIfNeeded();
  assert("Recording history not empty!" && m_timeline.empty());
  m_timeline.reserve(1000);

  // Capture the state of the thread at the current PC.
  Log();
}

void ThreadPlanInstructionTracer::TracingEnded() {
  for (break_id_t breakpoint_id : m_artificial_breakpoint_ids) {
    m_target->RemoveBreakpointByID(breakpoint_id);
  }
  m_artificial_breakpoint_ids.clear();
  m_timeline.clear();
  m_current_tracepoint = Thread::InvalidTracepointID;
  m_bookmarks.clear();
  m_stepped_while_suspended = false;
  m_artificial_step = false;
  m_modified_heap = false;
  m_emulating_stack_frames = false;
}

void ThreadPlanInstructionTracer::TracingSuspendRequested() {
  if (HasBeenSuspendedInternally()) {
    for (break_id_t breakpoint_id : m_artificial_breakpoint_ids) {
      m_target->DisableBreakpointByID(breakpoint_id);
    }
  }
}

void ThreadPlanInstructionTracer::TracingResumed() {
  if (m_stepped_while_suspended && !m_artificial_step) {
    Log();
    m_stepped_while_suspended = false;
  }
  for (break_id_t breakpoint_id : m_artificial_breakpoint_ids) {
    m_target->EnableBreakpointByID(breakpoint_id);
  }
}

void ThreadPlanInstructionTracer::ExpressionEvaluationFinished() {
  if (GetTracingToken() == TracingToken::ExpressionEvaluation &&
      m_emulating_stack_frames) {
    const uint32_t selected_frame_index = m_thread.GetSelectedFrameIndex();
    RestoreSnapshot(m_current_tracepoint);
    m_thread.SetSelectedFrameByIndex(selected_frame_index);
  }
}

bool ThreadPlanInstructionTracer::ShouldAcceptToken(TracingToken token) const {
  // Fetch the current token.
  const TracingToken current_token = GetTracingToken();

  // An invalid token means that nobody needs to preserve the tracing state
  // currently and thus anyone can override it.
  if (current_token == TracingToken::Invalid) {
    return true;
  }

  // An invalid token is only accepted when the current one is also invalid.
  if (token == TracingToken::Invalid) {
    return false;
  }

  // A token of the same kind with the current already has control.
  if (current_token == token) {
    return true;
  }

  // Expression evaluation attempts to affect tracing while the user or the
  // tracer is currently in control.
  if (token == TracingToken::ExpressionEvaluation) {
    return false;
  }

  // The user is able to override internal tracer choices, e.g. resume tracing
  // in case it has been suspended to avoid tracing calls to avoided symbols.
  if (token == TracingToken::UserCommand) {
    assert("The user should not be able to affect tracing while an "
           "expression is being evaluated!" &&
           current_token != TracingToken::ExpressionEvaluation);
    return true;
  }

  // Sanity checks.
  switch (current_token) {
  case TracingToken::UserCommand:
    llvm_unreachable("The tracer should not attempt to override user choice!");
  case TracingToken::ExpressionEvaluation:
    llvm_unreachable("The tracer should not affect expression evaluation!");
  default:
    llvm_unreachable("Unhandled incoming or current token type!");
  }
}

#pragma mark Helper Methods

void ThreadPlanInstructionTracer::InitializeStaticMembersIfNeeded() {
  if (!m_target) {
    m_target = &m_thread.GetProcess()->GetTarget();
    m_disassembler_sp = Disassembler::FindPlugin(m_target->GetArchitecture(),
                                                 nullptr, nullptr);
  }
  m_tracers.try_emplace(m_thread.GetID(), this);
}

void ThreadPlanInstructionTracer::InitializeSpecialFunctionHandlers() {
  const auto handle_cstring_mem_funcs = [&]() {
    const uint64_t destination = GetRegisterValueAsUInt64(ConstString("rdi"));
    const uint64_t count = GetRegisterValueAsUInt64(ConstString("rdx"));
    if (destination == UINT64_MAX || count == UINT64_MAX) {
      return;
    }
    if (!IsHeapAddress(m_thread, destination)) {
      return;
    }
    if (llvm::Optional<HeapData> heap_data = GetHeapData(destination, count);
        heap_data) {
      m_timeline[m_current_tracepoint].heap_data = std::move(heap_data);
      m_modified_heap = true;
    }
  };
  m_special_function_handlers.insert({"memcpy", handle_cstring_mem_funcs});
  m_special_function_handlers.insert({"memmove", handle_cstring_mem_funcs});
  m_special_function_handlers.insert({"memset", handle_cstring_mem_funcs});
}

bool ThreadPlanInstructionTracer::HasBeenSuspendedInternally() const {
  return GetState() == State::eSuspended &&
         GetTracingToken() == TracingToken::Internal;
}

template <typename... Args>
void ThreadPlanInstructionTracer::FormatError(llvm::StringRef format,
                                              Args &&... args) const {
  if (Stream *stream = GetLogStream(); stream) {
    stream->Format("error: {0}\n", llvm::formatv(format.data(),
                                                 std::forward<Args>(args)...));
    stream->Flush();
  }
}

template <typename T>
std::string ThreadPlanInstructionTracer::TakeErrorString(
    llvm::Expected<T> &unexpected) const {
  return llvm::toString(std::move(unexpected.takeError()));
}

ThreadPlanInstructionTracer *
ThreadPlanInstructionTracer::GetTracerPtrForThread(tid_t tid) {
  if (const auto tracer = m_tracers.find(tid); tracer != m_tracers.end()) {
    return std::get<ThreadPlanInstructionTracer *>(*tracer);
  }
  return nullptr;
}

#pragma mark Managing Bookmarks

llvm::Expected<Thread::TracingBookmarkID>
ThreadPlanInstructionTracer::CreateBookmark(Thread::TracepointID tracepoint_id,
                                            llvm::StringRef name) {
  constexpr auto getUniqueBookmarkID = []() {
    static Thread::TracingBookmarkID unique_bookmark_id = 0;
    return unique_bookmark_id++;
  };

  if (tracepoint_id >= m_timeline.size()) {
    return MakeError("Invalid tracepoint ID.");
  }

  llvm::Expected<const Thread::TracingBookmark &> bookmark =
      GetBookmarkAtTracepoint(tracepoint_id);
  if (bookmark) {
    return MakeError("A bookmark already exists at this tracepoint.");
  }
  llvm::consumeError(std::move(bookmark.takeError()));

  const addr_t pc = GetRecordedPCForStackFrame(m_timeline[tracepoint_id]);
  const Thread::TracingBookmarkID bm_id = getUniqueBookmarkID();
  m_bookmarks.emplace(bm_id, Thread::TracingBookmark(m_thread, bm_id,
                                                     tracepoint_id, name, pc));
  return bm_id;
}

Status ThreadPlanInstructionTracer::DeleteBookmark(
    Thread::TracingBookmarkID bookmark_id) {
  return (m_bookmarks.erase(bookmark_id) == 0) ? Status("Invalid bookmark ID.")
                                               : Status();
}

llvm::Expected<const Thread::TracingBookmark &>
ThreadPlanInstructionTracer::GetBookmark(
    Thread::TracingBookmarkID boookmark_id) const {
  if (auto iter = m_bookmarks.find(boookmark_id); iter != m_bookmarks.end()) {
    return std::get<Thread::TracingBookmark>(*iter);
  }
  return MakeError("Invalid bookmark ID.");
}

llvm::Expected<const Thread::TracingBookmark &>
ThreadPlanInstructionTracer::GetBookmarkAtTracepoint(
    Thread::TracepointID tracepoint_id) const {
  const auto bookmark = std::find_if(m_bookmarks.cbegin(), m_bookmarks.cend(),
                                     [&](const auto &bookmark_pair) {
    const auto &bookmark = std::get<Thread::TracingBookmark>(bookmark_pair);
    return bookmark.GetMarkedTracepointID() == tracepoint_id;
  });
  if (bookmark == m_bookmarks.end()) {
    return MakeError("There is no bookmark at this tracepoint.");
  }
  return std::get<Thread::TracingBookmark>(*bookmark);
}

Thread::ΤracingBookmarkList
ThreadPlanInstructionTracer::GetAllBookmarks() const {
  Thread::ΤracingBookmarkList bookmarks;
  bookmarks.reserve(m_bookmarks.size());
  for (const auto &[_, bookmark] : m_bookmarks) {
    bookmarks.push_back(bookmark);
  }
  std::sort(bookmarks.begin(), bookmarks.end(),
            [](const Thread::TracingBookmark &first,
               const Thread::TracingBookmark &second) {
    return first.GetMarkedTracepointID() < second.GetMarkedTracepointID();
  });
  return bookmarks;
}

Status ThreadPlanInstructionTracer::JumpToBookmark(
    Thread::TracingBookmarkID boookmark_id) {
  llvm::Expected<const Thread::TracingBookmark &> bookmark =
      GetBookmark(boookmark_id);
  if (!bookmark) {
    return Status("Invalid bookmark ID.");
  }
  return JumpToTracepoint(bookmark->GetMarkedTracepointID());
}

Status ThreadPlanInstructionTracer::RenameBookmark(
    Thread::TracingBookmarkID boookmark_id, llvm::StringRef name) {
  if (auto iter = m_bookmarks.find(boookmark_id); iter != m_bookmarks.end()) {
    std::get<Thread::TracingBookmark>(*iter).SetName(name);
    return Status();
  }
  return Status("Invalid bookmark ID.");
}

Status ThreadPlanInstructionTracer::MoveBookmark(
    Thread::TracingBookmarkID boookmark_id,
    Thread::TracepointID new_tracepoint_id) {
  if (new_tracepoint_id >= m_timeline.size()) {
    return Status("Invalid tracepoint ID.");
  }
  if (m_bookmarks.find(new_tracepoint_id) != m_bookmarks.end()) {
    return Status("A bookmark already exists at the destination tracepoint.");
  }
  if (auto iter = m_bookmarks.find(boookmark_id); iter != m_bookmarks.end()) {
    const addr_t pc = GetRecordedPCForStackFrame(m_timeline[new_tracepoint_id]);
    std::get<Thread::TracingBookmark>(*iter).
        SetMarkedTracepointID(new_tracepoint_id, pc);
    return Status();
  }
  return Status("Invalid bookmark ID.");
}

#pragma mark Examining Recorded History

bool ThreadPlanInstructionTracer::IsStackFrameStateEmulated() const {
  return m_emulating_stack_frames;
}

const RegisterContext::SavedRegisterValues &
ThreadPlanInstructionTracer::GetRecordedRegisterValuesForStackFrame(
    std::size_t frame_idx) const {
  assert("Stack frame state is not restored!" && IsStackFrameStateEmulated());
  return m_timeline[m_current_tracepoint].registers[frame_idx];
}

Thread::TracepointID
ThreadPlanInstructionTracer::GetCurrentTracepointID() const {
  return m_current_tracepoint;
}

Status ThreadPlanInstructionTracer::JumpToTracepoint(
    Thread::TracepointID destination) {
  if (destination >= m_timeline.size()) {
    return Status("The latest tracepoint is %zu.", m_timeline.size() - 1);
  }
  if (destination == m_current_tracepoint) {
    return Status("Already at requested tracepoint.");
  }
  RestoreSnapshot(destination);
  return Status();
}

void ThreadPlanInstructionTracer::DumpSourceLocationInfo(Tracepoint &tracepoint,
                                                         Stream &stream) {
  if (tracepoint.id == m_current_tracepoint) {
    stream.PutCString("* ");
  } else {
    stream.PutCString("  ");
  }

  const addr_t saved_pc = GetRecordedPCForStackFrame(tracepoint);
  stream.Format("{0} ({1:x}): ", tracepoint.id, saved_pc);

  Address pc;
  pc.SetOpcodeLoadAddress(saved_pc, m_target);

  SymbolContext sc;
  pc.CalculateSymbolContext(&sc);
  sc.DumpStopContext(&stream, m_thread.CalculateProcess().get(), pc, false,
                     true, false, true, true);
}

Status ThreadPlanInstructionTracer::CollectPastWriteLocations(
    TracepointCallback collector) {
  if (GetState() == State::eDisabled) {
    return Status("Tracing is disabled.");
  }

  const auto timeline_begin = m_timeline.rend();
  const auto current_tracepoint = timeline_begin - m_current_tracepoint - 1;

  auto result = TraverseTimeline<Timeline::reverse_iterator>(
      current_tracepoint, timeline_begin, std::move(collector));

  return !result ? Status(std::move(result.takeError()))
                 : Status();
}

Status ThreadPlanInstructionTracer::CollectFutureWriteLocations(
    TracepointCallback collector) {
  if (GetState() == State::eDisabled) {
    return Status("Tracing is disabled.");
  }

  const auto current_tracepoint = m_timeline.begin() + m_current_tracepoint;

  auto result = TraverseTimeline<Timeline::iterator>(
      current_tracepoint, m_timeline.end(), std::move(collector));

  return !result ? Status(std::move(result.takeError()))
                 : Status();
}

Status ThreadPlanInstructionTracer::ListWriteLocations(
    Stream &stream, const llvm::Twine &value_string, std::size_t num_locations,
    TracedWriteTiming write_timing, WriteLocationCollector &&collector,
    WriteLocationFinalizer &&finalizer) {
  if (num_locations == 0) {
    return Status("Invalid number of source locations.");
  }

  Status error;
  StreamString header;
  WriteLocations locations;
  std::size_t max_locations = num_locations;

  // Wrap callback to capture local state.
  const auto collector_wrapper = [&](Tracepoint &tracepoint) {
    return collector(tracepoint, locations, max_locations);
  };

  // Call collection callback for current tracepoint.
  collector_wrapper(m_timeline[m_current_tracepoint]);

  // Call collection callback for the rest tracepoints.
  switch (write_timing) {
  case TracedWriteTiming::Past:
    header.PutCString("\nPast tracepoints ");
    error = CollectPastWriteLocations(collector_wrapper);
    break;
  case TracedWriteTiming::Future:
    header.PutCString("\nFuture tracepoints ");
    error = CollectFutureWriteLocations(collector_wrapper);
    break;
  case TracedWriteTiming::Any:
    header.PutCString("\nTracepoints ");
    max_locations = (num_locations / 2) + 1;
    error = CollectPastWriteLocations(collector_wrapper);
    if (error.Success()) {
      max_locations = num_locations;
      error = CollectFutureWriteLocations(collector_wrapper);
    }
    break;
  }

  // Call finalization callback before checking results, if any.
  if (finalizer) {
    finalizer();
  }

  // Print list header.
  if (error.Fail()) {
    return error;
  } else if (locations.empty()) {
    return Status("Not enough information in history.");
  }
  header.Format("where {0} was modified:\n\n", value_string);
  stream.PutCString(header.GetString());

  // Print the modification instructions.
  for (const auto &location : locations) {
    stream.PutCString(location.second);
  }

  return Status();
}

Status ThreadPlanInstructionTracer::ListRegisterWriteLocations(
    Stream &stream, llvm::StringRef register_name, std::size_t num_locations,
    TracedWriteTiming write_timing) {
  std::size_t register_id = LLDB_INVALID_REGNUM;

  // The recorded register values are saved and indexed using the ID of their
  // register, thus look for the ID of the register with the provided name.
  DoForEachRegister(*m_thread.GetRegisterContext(),
                    [&](const RegisterInfo *reg_info, std::size_t reg_id) {
    if (llvm::StringRef(reg_info->name).equals(register_name)) {
      register_id = reg_id;
    }
  });
  if (register_id == LLDB_INVALID_REGNUM) {
    return Status("Unknown register.");
  }

  std::size_t found_locations = 0;

  const auto collector = [&](Tracepoint &tracepoint, WriteLocations &locations,
                             std::size_t max_locations) {
    const StackID &frame_id = m_thread.GetSelectedFrame()->GetStackID();

    RegisterContext::SavedRegisterValue *old_value =
        GetRecordedStackFrameRegisterValue(tracepoint, frame_id, register_id);
    if (tracepoint.id + 1 >= m_timeline.size() || !old_value ||
        !old_value->modified) {
      return Status(LLDB_GENERIC_ERROR);
    }

    RegisterContext::SavedRegisterValue *new_value =
        GetRecordedStackFrameRegisterValue(m_timeline[tracepoint.id + 1],
                                           frame_id, register_id);
    if (!new_value) {
      return Status(LLDB_GENERIC_ERROR);
    }

    StreamString location_string;
    DumpSourceLocationInfo(tracepoint, location_string);
    location_string.Format("\n  ├─ Old value: {0:x}",
                           old_value->value.GetAsUInt64());
    location_string.Format("\n  └─ New value: {0:x}\n\n",
                           new_value->value.GetAsUInt64());

    locations[tracepoint.id] = std::move(location_string.GetString().str());

    return (++found_locations == max_locations) ? Status()
                                                : Status(LLDB_GENERIC_ERROR);
  };

  return ListWriteLocations(stream, "$" + register_name, num_locations,
                            write_timing, std::move(collector));
}

Status ThreadPlanInstructionTracer::ListVariableWriteLocations(
    Stream &stream, llvm::StringRef variable_name, std::size_t num_locations,
    TracedWriteTiming write_timing) {
  Status error;
  StackFrame &frame = *m_thread.GetSelectedFrame();

  // The recorded variable values are saved and indexed using the ID of their
  // variable, thus look for the ID of the variable with the provided name.
  VariableList *variable_list = frame.GetVariableList(true);
  VariableSP variable = variable_list->FindVariable(ConstString(variable_name));
  if (!variable) {
    return Status("Unknown variable.");
  }
  const uint32_t variable_id = variable_list->FindVariableIndex(variable);
  if (variable_id == UINT32_MAX) {
    return Status("Unknown variable.");
  }

  // Variable values are saved in a plain buffer, without any type information,
  // however the tracer is going to need information about the type and format
  // of the variable in order to print its value correctly.
  //
  // Thus, create a value object for the variable, that will be used to print
  // the previously recorded values.
  ValueObjectSP value_object =
      frame.GetValueObjectForFrameVariable(variable,
                                           DynamicValueType::eNoDynamicValues);

  // The value object created above holds the current value of the variable, so
  // back it up before modifying it for printing.
  DataExtractor variable_value_backup;
  if (value_object->GetData(variable_value_backup, error); error.Fail()) {
    FormatError("Error backing up value of variable \"{0}\": {1}",
                value_object->GetName().AsCString(), error.AsCString());
  }

  std::size_t found_locations = 0;

  const auto collector = [&](Tracepoint &tracepoint, WriteLocations &locations,
                             std::size_t max_locations) {
    const StackID &frame_id = frame.GetStackID();

    SavedVariableValue *old_value =
        GetRecordedStackFrameVariableValue(tracepoint, frame_id, variable_id);
    if (tracepoint.id + 1 >= m_timeline.size() || !old_value ||
        !old_value->modified) {
      return Status(LLDB_GENERIC_ERROR);
    }

    SavedVariableValue *new_value =
        GetRecordedStackFrameVariableValue(m_timeline[tracepoint.id + 1],
                                           frame_id, variable_id);
    if (!new_value) {
      return Status(LLDB_GENERIC_ERROR);
    }

    DataExtractor &old_data = old_value->data;
    DataExtractor &new_data = new_value->data;

    StreamString location_string;
    DumpSourceLocationInfo(tracepoint, location_string);

    // Temporarily replace the current variable value with the recorded ones.
    if (value_object->SetData(old_data, error); error.Success()) {
      if (value_object->CanProvideValue()) {
        location_string.Format("\n  ├─ Old value: {0}",
                               value_object->GetValueAsCString());
      } else {
        location_string.PutCString("\n  ├─ Old value: ");
        DumpHexBytes(&location_string, old_data.GetDataStart(),
                     old_data.GetByteSize(), old_data.GetByteSize(),
                     LLDB_INVALID_ADDRESS);
      }
    }
    if (value_object->SetData(new_data, error); error.Success()) {
      if (value_object->CanProvideValue()) {
        location_string.Format("\n  └─ New value: {0}\n\n",
                               value_object->GetValueAsCString());
      } else {
        location_string.PutCString("\n  └─ New value: ");
        DumpHexBytes(&location_string, new_data.GetDataStart(),
                     new_data.GetByteSize(), new_data.GetByteSize(),
                     LLDB_INVALID_ADDRESS);
        location_string.PutCString("\n\n");
      }
    }

    locations[tracepoint.id] = std::move(location_string.GetString().str());

    return (++found_locations == max_locations) ? Status()
                                                : Status(LLDB_GENERIC_ERROR);
  };

  const auto finalizer = [&]() {
    // Restore the current value of the variable from the backup before the
    // command finishes, in order not to inadvertently alter the program state.
    if (value_object->SetData(variable_value_backup, error); error.Fail()) {
      FormatError("Error restoring value of variable \"{0}\": {1}",
                  value_object->GetName().AsCString(), error.AsCString());
    }
  };

  return ListWriteLocations(stream, "\"" + variable_name + "\"", num_locations,
                            write_timing, std::move(collector),
                            std::move(finalizer));
}

Status ThreadPlanInstructionTracer::ListHeapAddressWriteLocations(
    Stream &stream, addr_t heap_address, std::size_t num_locations,
    TracedWriteTiming write_timing) {
  if (!IsHeapAddress(m_thread, heap_address)) {
    return Status("The given address does not belong to the heap.");
  }
  std::size_t found_locations = 0;

  const auto collector = [&](Tracepoint &tracepoint, WriteLocations &locations,
                             std::size_t max_locations) {
    if (tracepoint.id + 1 >= m_timeline.size() || !tracepoint.heap_data ||
        !tracepoint.heap_data->modified ||
        !tracepoint.heap_data->Contains(heap_address)) {
      return Status(LLDB_GENERIC_ERROR);
    }

    StreamString location_string;
    DumpSourceLocationInfo(tracepoint, location_string);

    location_string.Format("\n  ├─ Old contents: ");
    tracepoint.heap_data->Dump(location_string);

    location_string.Format("\n  └─ New contents: ");
    const Tracepoint &next_tracepoint = m_timeline[tracepoint.id + 1];
    next_tracepoint.heap_data->Dump(location_string);

    location_string.PutCString("\n\n");
    locations[tracepoint.id] = std::move(location_string.GetString().str());

    return (++found_locations == max_locations) ? Status()
                                                : Status(LLDB_GENERIC_ERROR);
  };

  StreamString value_string_stream;
  value_string_stream.Format("{0:x}", heap_address);
  return ListWriteLocations(stream, value_string_stream.GetString(),
                            num_locations, write_timing, std::move(collector));
}

#pragma mark Navigating Recorded History

template<typename TimelineIteratorType>
llvm::Expected<std::size_t> ThreadPlanInstructionTracer::TraverseTimeline(
    const TimelineIteratorType &current_tracepoint,
    const TimelineIteratorType &timeline_limit, TracepointCallback &&predicate,
    TracepointCallback &&initializer, TracepointCallback &&past_limit) {
  if (initializer) {
    if (Status error = initializer(*current_tracepoint); error.Fail()) {
      return MakeError(error.AsCString());
    }
  }

  auto tracepoint = current_tracepoint;

  while (++tracepoint != timeline_limit) {
    if (predicate(*tracepoint).Success()) {
      break;
    }
  }
  if (tracepoint == timeline_limit) {
    --tracepoint;
    if (past_limit) {
      if (Status error = past_limit(*tracepoint); error.Fail()) {
        return MakeError(error.AsCString());
      }
    }
  }

  return std::distance(current_tracepoint, tracepoint);
}

Status
ThreadPlanInstructionTracer::StepBackInternal(TracepointCallback &&predicate,
                                              TracepointCallback &&initializer,
                                              TracepointCallback &&past_begin) {
  if (GetState() == State::eDisabled) {
    return Status("Tracing is disabled.");
  }

  const auto timeline_begin = m_timeline.rend();
  const auto current_tracepoint = timeline_begin - m_current_tracepoint - 1;

  auto num_instructions = TraverseTimeline<Timeline::reverse_iterator>(
      current_tracepoint, timeline_begin, std::move(predicate),
      std::move(initializer), std::move(past_begin));

  return !num_instructions ? Status(std::move(num_instructions.takeError()))
                           : StepBackInstruction(*num_instructions);
}

Status
ThreadPlanInstructionTracer::ReplayInternal(TracepointCallback &&predicate,
                                            TracepointCallback &&initializer,
                                            TracepointCallback &&past_end) {
  if (GetState() == State::eDisabled) {
    return Status("Tracing is disabled.");
  }

  const auto current_tracepoint = m_timeline.begin() + m_current_tracepoint;

  auto num_instructions = TraverseTimeline<Timeline::iterator>(
      current_tracepoint, m_timeline.end(), std::move(predicate),
      std::move(initializer), std::move(past_end));

  return !num_instructions ? Status(std::move(num_instructions.takeError()))
                           : ReplayInstruction(*num_instructions);
}

Status ThreadPlanInstructionTracer::Navigate(std::size_t num_statements,
                                             NavigationDirection direction) {
  std::size_t found_statements = 0;
  uint32_t current_line;

  const auto predicate = [&](Tracepoint &tracepoint) {
    if (tracepoint.line != current_line) {
      if (++found_statements == num_statements) {
        return Status();
      }
      current_line = tracepoint.line;
    }
    return Status(LLDB_GENERIC_ERROR);
  };

  const auto initializer = [&](Tracepoint &current_tracepoint) {
    current_line = current_tracepoint.line;
    return Status();
  };

  const auto past_limit = [&](Tracepoint &) {
    if (found_statements < num_statements) {
      switch (found_statements) {
      case 0:
        return Status("Not enough statements exist in history.");
      case 1:
        return Status("There is only 1 recorded statement in this direction.");
      default:
        return Status("There are only %" PRIu64 " recorded statements in this "
                      "direction.", found_statements);
      }
    }
    return Status();
  };

  switch (direction) {
  case NavigationDirection::Forward:
    return ReplayInternal(std::move(predicate), std::move(initializer),
                          std::move(past_limit));
  case NavigationDirection::Reverse:
    return StepBackInternal(std::move(predicate), std::move(initializer),
                            std::move(past_limit));
  }
}

Status
ThreadPlanInstructionTracer::NavigateToAddress(addr_t address,
                                               NavigationDirection direction) {
  const auto predicate = [&](Tracepoint &tracepoint) {
    return (GetRecordedPCForStackFrame(tracepoint) == address)
               ? Status()
               : Status(LLDB_GENERIC_ERROR);
  };

  const auto initializer = [&](Tracepoint &current_tracepoint) {
    if (address == LLDB_INVALID_ADDRESS) {
      return Status("Invalid address.");
    } else if (GetRecordedPCForStackFrame(current_tracepoint) == address) {
      return Status("Already at requested address.");
    } else {
      return Status();
    }
  };

  const auto past_limit = [&](Tracepoint &) {
    return Status("Requested address was not found in history.");
  };

  switch (direction) {
  case NavigationDirection::Forward:
    return ReplayInternal(std::move(predicate), std::move(initializer),
                          std::move(past_limit));
  case NavigationDirection::Reverse:
    return StepBackInternal(std::move(predicate), std::move(initializer),
                            std::move(past_limit));
  }
}

Status
ThreadPlanInstructionTracer::NavigateToLine(uint32_t line,
                                            NavigationDirection direction) {
  const auto predicate = [&](Tracepoint &tracepoint) {
    return (tracepoint.line == line) ? Status() : Status(LLDB_GENERIC_ERROR);
  };

  const auto initializer = [&](Tracepoint &current_tracepoint) {
    if (line == LLDB_INVALID_LINE_NUMBER) {
      return Status("Invalid line number.");
    } else if (current_tracepoint.line == line) {
      return Status("Already at requested address.");
    } else {
      return Status();
    }
  };

  const auto past_limit = [](Tracepoint &) {
    return Status("Requested source line was not found in history.");
  };

  switch (direction) {
  case NavigationDirection::Forward:
    return ReplayInternal(std::move(predicate), std::move(initializer),
                          std::move(past_limit));
  case NavigationDirection::Reverse:
    return StepBackInternal(std::move(predicate), std::move(initializer),
                            std::move(past_limit));
  }
}

Status ThreadPlanInstructionTracer::NavigateUntilOutOfFunction(
    NavigationDirection direction) {
  uint32_t current_frame_depth;

  const auto predicate = [&](Tracepoint &tracepoint) {
    StackFrame::Kind frame_kind = tracepoint.frames->frames[0]->frame_kind;
    const bool is_regular = (frame_kind == StackFrame::Kind::Regular);
    const bool is_outer = tracepoint.frame_depth < current_frame_depth;
    return (is_regular && is_outer) ? Status() : Status(LLDB_GENERIC_ERROR);
  };

  const auto initializer = [&](Tracepoint &current_tracepoint) {
    current_frame_depth = current_tracepoint.frame_depth;
    return Status();
  };

  switch (direction) {
  case NavigationDirection::Forward:
    return ReplayInternal(std::move(predicate), std::move(initializer));
  case NavigationDirection::Reverse:
    return StepBackInternal(std::move(predicate), std::move(initializer));
  }
}

llvm::Expected<Breakpoint &>
ThreadPlanInstructionTracer::GetBreakpointAtAddress(addr_t address) {
  const BreakpointList &breakpoint_list = m_target->GetBreakpointList();
  const std::size_t num_breakpoints = breakpoint_list.GetSize();

  for (std::size_t bp_id = 0; bp_id < num_breakpoints; ++bp_id) {
    Breakpoint &bp = *breakpoint_list.GetBreakpointAtIndex(bp_id);
    if (bp.IsEnabled() && bp.FindLocationByAddress(address)) {
      return bp;
    }
  }
  return MakeError("No breakpoints resolve to this address.");
}

addr_t ThreadPlanInstructionTracer::GetRecordedPCForStackFrame(
    Tracepoint &tracepoint, std::size_t frame_idx) {
  StackFrameList::StackFrameListCheckpoint &frame_list = *tracepoint.frames;
  StackFrame::StackFrameCheckpoint &frame = *frame_list.frames[frame_idx];
  RegisterContextSP &reg_context_sp = frame.reg_context_sp;
  StackFrameRegisterValues &registers = tracepoint.registers[frame_idx];

  const uint32_t pc_num = reg_context_sp->ConvertRegisterKindToRegisterNumber(
      eRegisterKindGeneric, LLDB_REGNUM_GENERIC_PC);

  return registers[pc_num].value.GetAsUInt64();
}

std::size_t ThreadPlanInstructionTracer::GetRecordedStackFrameIndex(
    Tracepoint &tracepoint, const StackID &frame_id) {
  const StackFrameList::StackFrameCheckpointList &saved_frames =
      tracepoint.frames->frames;

  const auto latest_frame_snapshot = std::find_if(saved_frames.begin(),
                                                  saved_frames.end(),
                                                  [&](const auto &saved_frame) {
      return saved_frame->id == frame_id;
  });

  return (latest_frame_snapshot != saved_frames.end())
             ? (*latest_frame_snapshot)->frame_index
             : LLDB_INVALID_FRAME_ID;
}

RegisterContext::SavedRegisterValue *
ThreadPlanInstructionTracer::GetRecordedStackFrameRegisterValue(
    Tracepoint &tracepoint, const StackID &frame_id, std::size_t register_id) {
  if (m_current_tracepoint != Thread::InvalidTracepointID &&
      m_current_tracepoint > 0) {
    const std::size_t frame_idx = GetRecordedStackFrameIndex(tracepoint,
                                                             frame_id);
    if (frame_idx != LLDB_INVALID_FRAME_ID) {
      return &tracepoint.registers[frame_idx][register_id];
    }
  }
  return nullptr;
}

ThreadPlanInstructionTracer::SavedVariableValue *
ThreadPlanInstructionTracer::GetRecordedStackFrameVariableValue(
    Tracepoint &tracepoint, const StackID &frame_id, std::size_t variable_id) {
  if (m_current_tracepoint != Thread::InvalidTracepointID &&
      m_current_tracepoint > 0) {
    const std::size_t frame_idx = GetRecordedStackFrameIndex(tracepoint,
                                                             frame_id);
    if (frame_idx != LLDB_INVALID_FRAME_ID) {
      return &tracepoint.variables[frame_idx][variable_id];
    }
  }
  return nullptr;
}

Status ThreadPlanInstructionTracer::ContinueInTimeline(
    NavigationDirection direction, Stream &canonical_breakpoint_id) {
  const auto predicate = [&](Tracepoint &tracepoint) {
    // Get recorded PC value for deepest stack frame.
    constexpr std::size_t zeroth_frame_idx = 0;
    const addr_t pc = GetRecordedPCForStackFrame(tracepoint, zeroth_frame_idx);

    // Check if there is a breakpoint that resolves to the saved PC.
    llvm::Expected<Breakpoint &> breakpoint = GetBreakpointAtAddress(pc);
    if (breakpoint) {
      const break_id_t breakpoint_location_id =
          breakpoint->HasResolvedLocations()
              ? breakpoint->GetLocationAtIndex(0)->GetID()
              : LLDB_INVALID_BREAK_ID;
      BreakpointID::GetCanonicalReference(&canonical_breakpoint_id,
                                          breakpoint->GetID(),
                                          breakpoint_location_id);
      return Status();
    }
    llvm::consumeError(std::move(breakpoint.takeError()));
    return Status(LLDB_GENERIC_ERROR);
  };

  switch (direction) {
  case NavigationDirection::Forward:
    return ReplayInternal(std::move(predicate));
  case NavigationDirection::Reverse:
    return StepBackInternal(std::move(predicate));
  }
}

#pragma mark Stepping Back

Status ThreadPlanInstructionTracer::StepBack(std::size_t num_statements) {
  return Navigate(num_statements, NavigationDirection::Reverse);
}

Status ThreadPlanInstructionTracer::StepBackUntilAddress(addr_t address) {
  return NavigateToAddress(address, NavigationDirection::Reverse);
}

Status ThreadPlanInstructionTracer::StepBackUntilLine(uint32_t line) {
  return NavigateToLine(line, NavigationDirection::Reverse);
}

Status ThreadPlanInstructionTracer::StepBackUntilOutOfFunction() {
  return NavigateUntilOutOfFunction(NavigationDirection::Reverse);
}

Status ThreadPlanInstructionTracer::StepBackUntilStart() {
  return StepBackInstruction(m_current_tracepoint);
}

Status
ThreadPlanInstructionTracer::ReverseContinue(Stream &canonical_breakpoint_id) {
  return ContinueInTimeline(NavigationDirection::Reverse,
                            canonical_breakpoint_id);
}

Status
ThreadPlanInstructionTracer::StepBackInstruction(std::size_t num_instructions) {
  // Check if the thread can step back.
  if (GetState() == State::eDisabled) {
    return Status("Tracing is disabled.");
  } else if (m_timeline.empty()) {
    return Status("Must record at least one instruction to step back.");
  } else if (m_current_tracepoint == 0) {
    return Status("Already at oldest point in time.");
  } else if (num_instructions == 0) {
    return Status("Number of instructions to step must be at least 1.");
  } else if (num_instructions > m_current_tracepoint) {
    return Status("There are only %" PRIu64 " older instructions in history.",
                  m_current_tracepoint);
  }

  // Even if tracing has been suspended to avoid tracing an unwanted symbol,
  // the user should still be able to step back.
  if (HasBeenSuspendedInternally()) {
    EnableSingleStepping();

    // Mark this step as artificial to prevent capturing a duplicate snapshot
    // when tracing is resumed.
    m_artificial_step = true;
    ResumeTracing(TracingToken::UserCommand);
    m_artificial_step = false;
  }

  // Restore the state at the requested point in time.
  RestoreSnapshot(m_current_tracepoint - num_instructions);

  return Status();
}

#pragma mark Replaying

Status ThreadPlanInstructionTracer::Replay(std::size_t num_statements) {
  return Navigate(num_statements, NavigationDirection::Forward);
}

Status ThreadPlanInstructionTracer::ReplayUntilAddress(addr_t address) {
  return NavigateToAddress(address, NavigationDirection::Forward);
}

Status ThreadPlanInstructionTracer::ReplayUntilLine(uint32_t line) {
  return NavigateToLine(line, NavigationDirection::Forward);
}

Status ThreadPlanInstructionTracer::ReplayUntilOutOfFunction() {
  return NavigateUntilOutOfFunction(NavigationDirection::Forward);
}

Status ThreadPlanInstructionTracer::ReplayUntilEnd() {
  return ReplayInstruction(m_timeline.size() - m_current_tracepoint - 1);
}

Status
ThreadPlanInstructionTracer::ReplayContinue(Stream &canonical_breakpoint_id) {
  return ContinueInTimeline(NavigationDirection::Forward,
                            canonical_breakpoint_id);
}

Status
ThreadPlanInstructionTracer::ReplayInstruction(std::size_t num_instructions) {
  // Check if the thread can replay.
  if (GetState() == State::eDisabled) {
    return Status("Tracing is disabled.");
  } else if (m_timeline.empty()) {
    return Status("Must record at least one instruction to replay.");
  } else if (m_current_tracepoint == m_timeline.size() - 1) {
    return Status("Already at latest point in time.");
  } else if (num_instructions < 1) {
    return Status("Number of instructions to replay be at least 1.");
  }
  std::size_t newer_instructions = m_timeline.size() - m_current_tracepoint - 1;
  if (num_instructions > m_timeline.size() - m_current_tracepoint - 1) {
    return Status("There are only %" PRIu64 " newer instructions in history.",
                  newer_instructions);
  }

  // Restore the state at the requested point in time.
  RestoreSnapshot(m_current_tracepoint + num_instructions);
  return Status();
}

#pragma mark Capturing Snapshots

ThreadPlanInstructionTracer::StackFrameRegisterValues
ThreadPlanInstructionTracer::GetStackFrameRegisterValues(StackFrame &frame) {
  RegisterContext &register_context = *frame.GetRegisterContext();
  StackFrameRegisterValues registers;
  DoForEachRegister(register_context, [&](const RegisterInfo *register_info,
                                          std::size_t register_id) {
    RegisterValue reg_value;
    register_context.ReadRegister(register_info, reg_value);
    if (m_current_tracepoint != Thread::InvalidTracepointID &&
        m_current_tracepoint != 0) {
      Tracepoint &previous_tracepoint = m_timeline[m_current_tracepoint - 1];
      RegisterContext::SavedRegisterValue *saved_value =
          GetRecordedStackFrameRegisterValue(previous_tracepoint,
                                             frame.GetStackID(), register_id);
      if (saved_value && saved_value->value != reg_value) {
        saved_value->modified = true;
      }
    }
    registers[register_id] = {std::move(reg_value), false};
  });
  return registers;
}

ThreadPlanInstructionTracer::StackFrameVariableValues
ThreadPlanInstructionTracer::GetStackFrameVariableValues(StackFrame &frame) {
  StackFrameVariableValues variables;
  DoForEachValueObjectInStackFrame(frame, [&](ValueObject *value_object,
                                              std::size_t variable_id) {
    Status error;
    DataExtractor data;
    if (value_object->GetData(data, error); error.Success()) {
      if (m_current_tracepoint != Thread::InvalidTracepointID &&
          m_current_tracepoint != 0) {
        Tracepoint &previous_tracepoint = m_timeline[m_current_tracepoint - 1];
        SavedVariableValue *saved_variable =
          GetRecordedStackFrameVariableValue(previous_tracepoint,
                                             frame.GetStackID(), variable_id);
        if (saved_variable) {
          const DataExtractor &saved_data = saved_variable->data;
          if (saved_data.GetByteSize() > 0) {
            if (::memcmp(data.GetDataStart(), saved_data.GetDataStart(),
                         data.GetByteSize()) != 0) {
              saved_variable->modified = true;
            }
          }
        }
      }
      variables[variable_id] = {std::move(data), false};
    } else {
      FormatError("Error saving value of variable \"{0}\": {1}",
                  value_object->GetName().AsCString(), error.AsCString());
    }
  });
  return variables;
}

llvm::Optional<ThreadPlanInstructionTracer::HeapData>
ThreadPlanInstructionTracer::GetHeapData(addr_t address, offset_t size) {
  assert("The given address does not correspond to the heap!" &&
         IsHeapAddress(m_thread, address));
  Status error;
  DataBufferHeap heap_data(size, 0);
  m_thread.GetProcess()->ReadMemory(address, heap_data.GetBytes(),
                                    heap_data.GetByteSize(), error);
  if (error.Fail()) {
    FormatError("Failed to read process memory: {0}", error.AsCString());
    return {};
  }
  return HeapData(address, std::move(heap_data));
}

void ThreadPlanInstructionTracer::SaveRecentlyStoredHeapDataIfNeeded() {
  if (!m_modified_heap) {
    return;
  }

  assert("There must always be at least one previous snapshot, i.e. the one "
         "captured right before the store!" && m_current_tracepoint > 0);
  Tracepoint &previous_tracepoint = m_timeline[m_current_tracepoint - 1];
  if (!previous_tracepoint.heap_data) {
    return;
  }
  HeapData &old_heap_data = *previous_tracepoint.heap_data;
  const addr_t address = old_heap_data.base;
  const offset_t size = old_heap_data.data.GetByteSize();

  llvm::Optional<HeapData> heap_data = GetHeapData(address, size);
  if (!heap_data) {
    llvm_unreachable("The tracer managed to read the memory right before the "
                     "store, but failed to do so again right after the store!");
  }
  old_heap_data.modified = true;
  m_timeline[m_current_tracepoint].heap_data = std::move(heap_data);
  m_modified_heap = false;
}

void ThreadPlanInstructionTracer::CaptureSnapshot() {
  StackFrameList &frame_list = *m_thread.GetStackFrameList();

  // Save register values.
  RegisterValues registers;
  DoForEachStackFrame(frame_list, [&](StackFrame &frame) {
    registers.push_back(std::move(GetStackFrameRegisterValues(frame)));
  });

  // Save current stack frames.
  StackFrames frames = frame_list.CheckpointStackFrameList();

  // Save values of stack frame variables.
  VariableValues variables;
  DoForEachStackFrame(frame_list, [&](StackFrame &frame) {
    variables.push_back(std::move(GetStackFrameVariableValues(frame)));
  });

  // Save thread state.
  StopInfoSP stop_info = m_thread.GetStopInfo();
  const std::size_t completed_plan_checkpoint =
      m_thread.GetPlans().CheckpointCompletedPlans();

  // Save current source line, if available.
  const SymbolContext &symbol_context = m_thread.GetStackFrameAtIndex(0)->
      GetSymbolContext(eSymbolContextLineEntry);
  const uint32_t current_source_line = symbol_context.line_entry.line;

  // Append snapshot to history and update current tracepoint index.
  m_timeline.emplace_back(++m_current_tracepoint, std::move(registers),
                          std::move(variables), std::move(frames),
                          std::move(stop_info), completed_plan_checkpoint,
                          current_source_line);

  // Save any heap data stored by the directly previous instruction.
  SaveRecentlyStoredHeapDataIfNeeded();
}

#pragma mark Restoring Snapshots

void ThreadPlanInstructionTracer::RestoreStackFrameRegisters(
    StackFrame &frame, StackFrameRegisterValues &registers) {
  RegisterContext &register_ctx = *frame.GetRegisterContextSP();
  DoForEachRegister(register_ctx, [&](const RegisterInfo *reg_info,
                                      std::size_t reg_id) {
    if (IsExceptionStateRegister(register_ctx, reg_id)) {
      return;
    }
    if (!register_ctx.WriteRegister(reg_info, registers[reg_id].value)) {
      if (reg_info->alt_name) {
        FormatError("Frame {0}: Failed to write register \"{1}\" ({2}).",
                    frame.GetFrameIndex(), reg_info->name,
                    reg_info->alt_name);
      } else {
        FormatError("Frame {0}: Failed to write register \"{1}\".",
                    frame.GetFrameIndex(), reg_info->name);
      }
    }
  });
}

void ThreadPlanInstructionTracer::RestoreStackFrameVariables(
    StackFrame &frame, StackFrameVariableValues &variables) {
  DoForEachValueObjectInStackFrame(frame, [&](ValueObject *value_object,
                                              std::size_t var_id) {
    Status error;
    if (value_object->SetData(variables[var_id].data, error); error.Fail()) {
      FormatError("Error restoring value of variable \"{0}\": {1}",
                  value_object->GetName().AsCString(), error.AsCString());
    }
  });
}

void ThreadPlanInstructionTracer::RestoreHeapData(const HeapData &heap_data) {
  // Try to restore the supplied data to the heap.
  Status error;
  const addr_t base = heap_data.base;
  const uint8_t *data = heap_data.data.GetBytes();
  const offset_t size = heap_data.data.GetByteSize();
  m_thread.GetProcess()->WriteMemory(base, data, size, error);
  if (error.Success()) {
    return;
  }

  // The heap region is no longer accessible, so discard all recorded
  // modifications of this area, since they aren't needed anymore.
  const addr_t end = base + size - 1;
  for (Tracepoint &tracepoint : m_timeline) {
    if (tracepoint.heap_data) {
      const addr_t tracepoint_base = tracepoint.heap_data->base;
      if (tracepoint_base >= base && tracepoint_base <= end ||
          tracepoint_base >= end && tracepoint_base <= base) {
        tracepoint.heap_data.reset();
      }
    }
  }

  // Inform the user that this particular heap region won't be restored anymore.
  FormatError("Failed to write process memory: {0}", error.AsCString());
  FormatError("The heap region {0:x} - {1:x} is no longer accessible, thus all "
              "recorded history for this area will be discarded.", base, end);
}

void ThreadPlanInstructionTracer::UndoHeapWritesUpTo(
    Thread::TracepointID destination) {
  auto tracepoint = m_timeline.cbegin() + m_current_tracepoint;
  const auto destination_tracepoint = m_timeline.cbegin() + destination;
  while (--tracepoint >= destination_tracepoint) {
    if (tracepoint->heap_data) {
      RestoreHeapData(*tracepoint->heap_data);
    }
  }
}

void ThreadPlanInstructionTracer::RedoHeapWritesUpTo(
    Thread::TracepointID destination) {
  auto tracepoint = m_timeline.cbegin() + m_current_tracepoint;
  const auto destination_tracepoint = m_timeline.cbegin() + destination;
  while (tracepoint++ < destination_tracepoint) {
    if (tracepoint->heap_data) {
      RestoreHeapData(*tracepoint->heap_data);
    }
  }
}

void
ThreadPlanInstructionTracer::RestoreStackFrameState(std::size_t frame_idx) {
  if (GetState() != State::eEnabled) {
    return;
  }
  Tracepoint &current_tracepoint = m_timeline[m_current_tracepoint];
  StackFrame &frame = *m_thread.GetStackFrameAtIndex(frame_idx);
  RestoreStackFrameRegisters(frame, current_tracepoint.registers[frame_idx]);
  RestoreStackFrameVariables(frame, current_tracepoint.variables[frame_idx]);
  m_emulating_stack_frames = true;
}

void ThreadPlanInstructionTracer::RestoreSnapshot(
    Thread::TracepointID tracepoint_id) {
  assert("Invalid tracepoint ID!" && tracepoint_id < m_timeline.size());

  // Restore heap data.
  if (tracepoint_id < m_current_tracepoint) {
    UndoHeapWritesUpTo(tracepoint_id);
  } else {
    RedoHeapWritesUpTo(tracepoint_id);
  }

  // Update current tracepoint index.
  m_current_tracepoint = tracepoint_id;

  // Restore stack frames.
  Tracepoint &current_tracepoint = m_timeline[m_current_tracepoint];
  m_thread.SetStackFrameList(
      std::make_shared<StackFrameList>(*current_tracepoint.frames));

  // Restore register and variable values for current (zeroth) stack frame.
  RestoreStackFrameState(0);

  // Restore thread state.
  StopInfoSP stop_info = current_tracepoint.stop_info;
  if (stop_info) {
    stop_info->MakeStopInfoValid();
  }
  m_thread.SetStopInfo(stop_info);
  m_thread.GetPlans().RestoreCompletedPlanCheckpoint(
      current_tracepoint.completed_plan_checkpoint);
}

#pragma mark Logging

uint64_t ThreadPlanInstructionTracer::GetRegisterValueAsUInt64(
    ConstString register_name, uint64_t fail_value) const {
  RegisterContext &register_context = *m_thread.GetRegisterContext();
  const RegisterInfo *register_info = register_context.GetRegisterInfoByName(
      register_name.GetStringRef());
  if (register_info) {
    RegisterValue register_value;
    if (register_context.ReadRegister(register_info, register_value)) {
      return register_value.GetAsUInt64(fail_value);
    }
  }
  return fail_value;
}

addr_t ThreadPlanInstructionTracer::CalculateAddressFromOperand(
    const Instruction::Operand &operand) const {
  if (operand.m_type != Instruction::Operand::Type::Dereference) {
    return LLDB_INVALID_ADDRESS;
  }

  const Instruction::Operand &address_operand = operand.m_children[0];

  switch (address_operand.m_type) {
  case Instruction::Operand::Type::Dereference:
  case Instruction::Operand::Type::Invalid:
  case Instruction::Operand::Type::Product:
    return LLDB_INVALID_ADDRESS;
  case Instruction::Operand::Type::Immediate:
    return address_operand.m_immediate;
  case Instruction::Operand::Type::Register:
    return GetRegisterValueAsUInt64(address_operand.m_register);
  case Instruction::Operand::Type::Sum: {
    const Instruction::Operand &offset_operand = address_operand.m_children[0];
    const Instruction::Operand &base_operand = address_operand.m_children[1];
    const addr_t base = GetRegisterValueAsUInt64(base_operand.m_register);
    if (base == LLDB_INVALID_ADDRESS) {
      return LLDB_INVALID_ADDRESS;
    }
    return offset_operand.m_negative ? base - offset_operand.m_immediate
                                     : base + offset_operand.m_immediate;
  }
  default:
    llvm_unreachable("Unknown instruction operand type!");
  }
}

llvm::Expected<InstructionList &>
ThreadPlanInstructionTracer::DisassembleInstructions(
    std::size_t num_instructions) const {
  // Verify the requested number of instructions.
  if (num_instructions < 1) {
    return MakeError("Invalid number of instructions to disassemble.");
  }

  // Make sure a disassembler is available.
  if (!m_disassembler_sp) {
    return MakeErrorWithFormat(
        "Unable to find disassembler plugin for {0} architecture.",
        m_target->GetArchitecture().GetArchitectureName());
  }

  // Allocate a buffer large enough to hold the requested instructions.
  constexpr std::size_t max_instruction_size = 16;
  DataBufferHeap buffer(num_instructions * max_instruction_size, 0);

  const addr_t pc = m_thread.GetRegisterContext()->GetPC();
  ProcessSP process = m_thread.GetProcess();

  // Read instructions from memory.
  Status error;
  process->ReadMemory(pc, buffer.GetBytes(), buffer.GetByteSize(), error);
  if (error.Fail()) {
    return MakeErrorWithFormat("Failed to read process memory: {0}",
                               error.AsCString());
  }

  // Disassemble instructions.
  DataExtractor extractor(buffer.GetBytes(), buffer.GetByteSize(),
                          process->GetByteOrder(),
                          process->GetAddressByteSize());
  m_disassembler_sp->DecodeInstructions(Address(pc), extractor, 0,
                                        num_instructions, false, false);

  // Return instructions, if decoded successfully.
  InstructionList &instruction_list = m_disassembler_sp->GetInstructionList();
  if (instruction_list.GetSize()) {
    return instruction_list;
  } else {
    return MakeErrorWithFormat("Could not disassemble {0} instructions "
                               "(starting at {1:x}).", num_instructions, pc);
  }
}

bool ThreadPlanInstructionTracer::ShouldAvoidCallTarget(
    llvm::StringRef call_target) const {
  // An unidentified call target often indicates a lack of debug information,
  // thus this is probably a call to an external or system library function.
  if (call_target.empty()) {
    return true;
  }

  // There is no need to trace C++ STL functions.
  if (call_target.startswith("std::")) {
    return true;
  }

  // Check whether the user has opted not to trace the called function.
  const RegularExpression *symbols_to_avoid_regex =
      m_thread.GetSymbolsToAvoidTracingRegex();
  if (symbols_to_avoid_regex) {
    if (!symbols_to_avoid_regex->IsValid()) {
      FormatError("Invalid regular expression for symbols to avoid.");
      return false;
    }
    if (symbols_to_avoid_regex->Execute(call_target)) {
      return true;
    }
  }

  // Finally, check whether this function belongs to a library whose symbols
  // shall not be traced.
  if (IsLibraryFunctionToAvoid(*m_target, m_thread, ConstString(call_target))) {
    return true;
  }

  return false;
}

bool ThreadPlanInstructionTracer::AvoidedSymbolBreakpointHitCallback(
    void *tid_baton, StoppointCallbackContext *context, user_id_t breakpoint_id,
    user_id_t breakpoint_location_id) {
  const auto forget_artificial_breakpoint =
      [&](ArtificialBreakpointIDs &artificial_breakpoint_ids,
          break_id_t breakpoint_id) {
    auto bp_id_iter = std::find(artificial_breakpoint_ids.begin(),
                                artificial_breakpoint_ids.end(),
                                breakpoint_id);
    assert("Artificial breakpoint not found!" &&
           bp_id_iter != artificial_breakpoint_ids.end());
    std::swap(*bp_id_iter, artificial_breakpoint_ids.back());
    artificial_breakpoint_ids.pop_back();
  };

  // Clear artificial breakpoint and resume tracing, if needed.
  const tid_t tid = reinterpret_cast<tid_t>(tid_baton);
  if (ThreadPlanInstructionTracer *tracer = GetTracerPtrForThread(tid);
      tracer) {
    forget_artificial_breakpoint(tracer->m_artificial_breakpoint_ids,
                                 breakpoint_id);
    if (tracer->HasBeenSuspendedInternally()) {
      tracer->EnableSingleStepping();
      tracer->ResumeTracing(TracingToken::Internal);
    }
  }
  m_target->RemoveBreakpointByID(breakpoint_id);

  // Allow target to run.
  return false;
}

void ThreadPlanInstructionTracer::HandleCallTargetToAvoid(addr_t bp_addr) {
  // Suspend tracing and single stepping.
  SuspendTracing(TracingToken::Internal);
  DisableSingleStepping();

  // Set an artificial breakpoint at the instruction after the call.
  if (BreakpointSP bp = m_target->CreateBreakpoint(bp_addr, true, false); bp) {
    m_artificial_breakpoint_ids.push_back(bp->GetID());
    void *tid_baton = reinterpret_cast<void *>(m_thread.GetID());
    bp->SetCallback(AvoidedSymbolBreakpointHitCallback, tid_baton, true);
    bp->SetBreakpointKind("call-to-avoided-symbol-finished");
    bp->SetOneShot(true);
    bp->SetAutoContinue(true);
  }
}

void ThreadPlanInstructionTracer::HandleSpecialFunctionIfNeeded(
    llvm::StringRef function_name) {
  if (auto iter = m_special_function_handlers.find(function_name);
      iter != m_special_function_handlers.end()) {
    const SpecialFunctionHandler &handler = iter->getValue();
    handler();
  }
}

void ThreadPlanInstructionTracer::HandleCallInstruction(
    Instruction &call_inst, Instruction &inst_after_call) {
  const auto get_opcode_address = [&](const Instruction &instruction) {
    return instruction.GetAddress().GetOpcodeLoadAddress(m_target);
  };

  const std::string call_target = GetDemangledCallTarget(m_thread, call_inst);

  // Handle calls to known deallocation functions that should not be executed.
  if (m_thread.GetTracingJumpOverDeallocationFunctions() &&
      IsDeallocationFunction(call_target)) {
    const std::size_t call_opcode_size = call_inst.GetOpcode().GetByteSize();
    Status error = BackUpAndReplaceOpcodeWithNOP(m_thread,
                                                 get_opcode_address(call_inst),
                                                 call_opcode_size);
    if (error.Fail()) {
      FormatError("Failed to replace call to deallocation function: {0}",
                  error.AsCString());
    }
    return;
  }

  // Check if this a call to a function that needs special handling, e.g. a
  // system call or a call to a known memory manipulation function.
  //
  // These functions can't or shall not be traced, but their side effects, such
  // as modifications to the heap, must be tracked.
  HandleSpecialFunctionIfNeeded(call_target);

  // Finally, avoid tracing the called function, if applicable.
  if (ShouldAvoidCallTarget(call_target)) {
    HandleCallTargetToAvoid(get_opcode_address(inst_after_call));
  }
}

void ThreadPlanInstructionTracer::HandleInstructionThatMayStore(
    Instruction &store_instruction) {
  ExecutionContext exe_ctx;
  m_thread.CalculateExecutionContext(exe_ctx);
  const llvm::StringRef mnemonic = store_instruction.GetMnemonic(&exe_ctx);

  // Ignore "push" instructions, since they have no destination operand and
  // always write to the stack.
  if (mnemonic.startswith("push")) {
    return;
  }

  llvm::SmallVector<Instruction::Operand, 2> operands;
  if (!store_instruction.ParseOperands(operands) || operands.size() == 0) {
    return;
  }

  const addr_t address = CalculateAddressFromOperand(operands.back());
  if (address != LLDB_INVALID_ADDRESS && IsHeapAddress(m_thread, address)) {
    offset_t size = GetBytesStored(mnemonic);
    if (m_current_tracepoint > 0) {
      const Tracepoint &previous_tracepoint =
          m_timeline[m_current_tracepoint - 1];
      if (previous_tracepoint.heap_data) {
        const HeapData &saved_data = *previous_tracepoint.heap_data;
        const offset_t saved_data_size = saved_data.data.GetByteSize();
        if (saved_data_size > size) {
          size = saved_data_size;
        }
      }
    }
    if (llvm::Optional<HeapData> heap_data = GetHeapData(address, size);
        heap_data) {
      m_timeline[m_current_tracepoint].heap_data = std::move(heap_data);
      m_modified_heap = true;
    }
  }
}

void ThreadPlanInstructionTracer::ClearSubsequentRecordingHistoryIfNeeded() {
  // The recording history needs to be cleared only in case the thread has
  // stepped or continued forward while the thread state was being emulated.
  if (!m_emulating_stack_frames) {
    return;
  }

  // Clear any bookmarks referring to snapshots that are about to be discarded.
  for (auto iter = m_bookmarks.begin(); iter != m_bookmarks.end(); ) {
    if (std::get<const Thread::TracepointID>(*iter) > m_current_tracepoint) {
      iter = m_bookmarks.erase(iter);
    } else {
      ++iter;
    }
  }

  // Calcualate limits of discarded timeline area.
  assert("Recorded history must always shrink in case the thread stepped or "
         "continued forward after having stepped back!" &&
         m_current_tracepoint + 1 <= m_timeline.size());
  const auto discard_start = m_timeline.begin() + m_current_tracepoint + 1;
  const auto discard_end = m_timeline.end();
  ThreadPlanStack &plan_stack = m_thread.GetPlans();

  // Discard associated completed plan checkpoints.
  for (auto iter = discard_start; iter != discard_end; ++iter) {
    plan_stack.DiscardCompletedPlanCheckpoint(iter->completed_plan_checkpoint);
  }

  // Discard recorded history following the current instruction.
  m_timeline.erase(discard_start, discard_end);

  // Cancel any pending heap region backup.
  m_modified_heap = false;
}

void ThreadPlanInstructionTracer::Log() {
  // Avoid logging when tracing is disabled or an expression is being evaluated.
  if (GetState() == State::eDisabled || GetEvaluatingExpression()) {
    return;
  }

  // Don't log when tracing is suspended, but keep track of stepping to avoid
  // capturing a duplicate snapshot when resuming immediately after suspending.
  if (GetState() == State::eSuspended) {
    m_stepped_while_suspended = true;
    return;
  }

  // Make sure that the recorded history following the current instruction is
  // discarded, if the user has stepped or continued forward while the thread
  // state was being emulated by this tracer.
  ClearSubsequentRecordingHistoryIfNeeded();

  // The thread resumed forward, so any previously restored state has been
  // replaced by the real one.
  m_emulating_stack_frames = false;

  // Restore any instruction opcode that was replaced with `NOP` in order to
  // jump over a call to a deallocation function.
  if (opcode_backup.IsPendingRestoration()) {
    RestoreOpcodeBackup(m_thread);
  }

  // Save the state of the thread at this point in time.
  CaptureSnapshot();

  // The user has opted to trace calls to any symbol.
  if (m_thread.GetIgnoreTracingAvoidSettings()) {
    return;
  }

  // The tracer disassembles two instructions at a time, since the instruction
  // directly after the current one will be needed in case the thread is
  // currently stopped at a call that needs additional handling (see below).
  llvm::Expected<InstructionList &> inst_list = DisassembleInstructions(2);
  if (!inst_list) {
    FormatError(TakeErrorString(inst_list));
    return;
  }

  // Check if the current instruction needs special handling, that is:
  //   - Calls a deallocation function that should not be executed.
  //   - Calls a function that should be executed, but not be traced.
  //   - May store.
  Instruction &current_instruction = *inst_list->GetInstructionAtIndex(0);
  if (current_instruction.IsCall()) {
    Instruction &next_instruction = *inst_list->GetInstructionAtIndex(1);
    HandleCallInstruction(current_instruction, next_instruction);
  } else if (current_instruction.MayStore()) {
    HandleInstructionThatMayStore(current_instruction);
  }
}
