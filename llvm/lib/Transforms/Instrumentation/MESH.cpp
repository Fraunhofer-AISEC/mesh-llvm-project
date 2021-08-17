//===-- MESH.cpp ----------------------------------------------------===//
//
// This file is distributed under the Apache License v2.0
// License with LLVM Exceptions. See LICENSE.TXT for details.
//
// Author: Emanuel Vintila, Fraunhofer AISEC
//
//===----------------------------------------------------------------------===//


/* includes */
#include <stdlib.h> // getenv
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"


using namespace llvm;


#define DEBUG_TYPE "mesh"


/* options */
//#define PRINT_INSTR // print instruction before and after the MESH instrumentation
#define INSTR_STATS // print statistics about the number of instrumentation points

#ifdef INSTR_STATS
#include <iostream> // std::cerr
#endif


/* globals */
static const char *const kMESHCtorPrefix = "mesh.";
static const char *const kMESHFnPrefix = "__mesh_";
static const char *const kMESHModuleCtorName = "mesh.module_ctor";
static const char *const kMESHInitRtName = "__mesh_init_rt";
static const char *const kMESHInitGlobalsPrefix = "__mesh_init_globals_";


namespace {

class MESH : public ModulePass {
public:
  static char ID;
  MESH() : ModulePass(ID) { }

  StringRef getPassName() const override {
    return "MESHPass";
  }

  bool doInitialization(Module &M) override;
  bool runOnModule(Module &M) override;

  void initializeFunctionDefinitionList(Module &M);
  void initializeCtor(Module &M);
  void initializeInlineAsms();
  void initializeCallbacks(Module &M);
  Function* createInitGlobalsFunction(Module &M);

private:
  enum arch_t {
    X86_64 = 0,
    AARCH64 = 1
  };
  arch_t arch;
  size_t addr_mask;
  size_t NR_ADDR_BITS;
  size_t POINTER_SIZE;
  size_t NR_TAG_BITS;

  LLVMContext *C;

  const DataLayout *dataLayout_p;
  Triple TargetTriple;

  std::vector<Value *> instrumentedInstructions;

  Type *Int32Ty;
  Type *Int64Ty;
  Type *IntptrTy;
  Type *PtrTy;
  Type *VoidTy;
  StructType *LineTy;
  ArrayType *TableTy;
  PointerType *TablePtrTy;

  Constant *TableAddrLong;
  Constant *TableAddr;
  Constant *HeapUpperLimitLong;

  Function *MESHCtorFunction;
  FunctionCallee MESHDerefFn;
  FunctionCallee MESHFail;
  FunctionCallee MESHFailNonHeap;
  FunctionCallee MESHStripFn;
  FunctionCallee MESHCheckFn;
  FunctionCallee MESHTimestampFn;
  FunctionCallee MESHDetimestampFn;
  FunctionCallee MESHMallocFn;
  FunctionCallee MESHFreeFn;
  FunctionCallee MESHCallocFn;
  FunctionCallee MESHReallocFn;

  std::set< const Value * > SkippablePointers = {};
  std::set< const Value * > NotSkippablePointers = {};

  std::set<llvm::GlobalValue::GUID> FunctionDefintionSet = {};

#ifdef INSTR_STATS
  uint64_t instr_load = 0;
  uint64_t instr_store = 0;

  uint64_t skipped_load = 0;
  uint64_t skipped_store = 0;

  uint64_t unintr_load = 0;
  uint64_t unintr_store = 0;

  uint64_t total_mem_intr = 0;
  uint64_t instr_mem_intr = 0;
#endif
  
  bool canSkipPointer(const Value *PointerOperand, std::vector<const Value *> AlreadyProcessed);
  bool canSkipLoad(const LoadInst *LI);
  bool canSkipStore(const StoreInst *SI);
  bool canSkipGEP(const GEPOperator *GEP);
  bool canSkipFunctionOperand(const Value *Op);

  bool instrumentMemAccesses(
    SmallVectorImpl<LoadInst *> &Loads,
    SmallVectorImpl<StoreInst *> &Stores,
    SmallVectorImpl<Instruction *> &MemInstrinsics
    );

  // interest checkers
  bool isInterestingFunction(const Function *F);
  bool isInterestingAlloca(const AllocaInst *Inst);
  bool isInterestingArgument(const Argument *Arg);
  bool isInterestingGlobal(const GlobalVariable *GV);
  bool isInterestingLoad(const LoadInst *LI);
  bool isInterestingStore(const StoreInst *SI);
  bool isInterestingGEP(const GEPOperator *GEP);
  
  // visitors
  bool visitLoad(LoadInst *Inst);
  bool visitAlloca(AllocaInst *Inst);


  Value *checkPtr(Value *Ptr, Instruction *InsertBefore, size_t size);
  Value *checkPtrVarSize(Value *Ptr, Instruction *InsertBefore, Value *size);
  Value *stripPtr(Value *Ptr, Instruction *InsertBefore);

  // instrumentors
  void instrumentLoad(LoadInst *LI);
  void instrumentStore(StoreInst *SI);
  void instrumentGEP(GEPOperator *GEP, IRBuilder<> &IRB);
  void instrumentMemIntrinsic(Instruction *I, IRBuilder<> &IRB);
  bool instrumentFunctionCall(CallInst *CI, const Module &M);
  void instrumentReturn(SmallVectorImpl<Value *> &TimestampedPointers, Instruction *RI);


  bool instrumentArgUsages(Argument *Arg);
  void instrumentAlloca(Instruction *I, Value *AIPtr, Value *Replacement);
  void instrumentGlobal(Module &M, Function *F, GlobalVariable *GV, unsigned N);

  bool instrumentFunction(
    SmallVectorImpl<AllocaInst *> &Allocas,
    SmallVectorImpl<LoadInst *> &Loads,
    SmallVectorImpl<StoreInst *> &Stores,
    SmallVectorImpl<GEPOperator *> &GEPs,
    SmallVectorImpl<Instruction *> &Returns,
    SmallVectorImpl<Instruction *> &MemInstrinsics);
};

} // end anonymous namespace


char MESH::ID = 0;


bool MESH::doInitialization(Module &M) {
  LLVM_DEBUG(dbgs() << "Initialize MESH for module " << M.getName() << "\n");

  dataLayout_p = &M.getDataLayout();

  C = &(M.getContext());
  TargetTriple = Triple(M.getTargetTriple());

  IRBuilder<> IRB(*C);

  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  IntptrTy = IRB.getIntPtrTy(*dataLayout_p);
  PtrTy = IRB.getInt8PtrTy();
  VoidTy = IRB.getVoidTy();

  std::vector<Type*> members;
  members.push_back( Int64Ty );
  members.push_back( Int64Ty );

  LineTy = StructType::create(members, "LineTy");
  TableTy = ArrayType::get(LineTy, UINT16_MAX + 1);
  TablePtrTy = PointerType::get(TableTy, dyn_cast<PointerType>(PtrTy)->getAddressSpace());

  uint64_t MESHHeapAddress;
  const char *MESHHeapAddressStrPtr = getenv("MESH_HEAP_ADDRESS");
  if (MESHHeapAddressStrPtr)
  {    
    char *end_ptr;
    MESHHeapAddress = std::strtoull(MESHHeapAddressStrPtr, &end_ptr, 16);
    if ( (*end_ptr != '\0') || 
         ( MESHHeapAddress == UINT64_MAX && errno == ERANGE ) ) {
      report_fatal_error("MESH pass: Failed to parse MESH_HEAP_ADDRESS \"" + std::string(MESHHeapAddressStrPtr) + "\" as a hex");      
    }
  }
  else {
    // use default
    MESHHeapAddress = 4096;
  }
  std::cerr << "Using MESH Heap address: " << MESHHeapAddress << "\n";

  TableAddrLong = ConstantInt::get(Int64Ty, MESHHeapAddress);
  HeapUpperLimitLong = ConstantInt::get( Int64Ty, MESHHeapAddress + 0x0000001F0010ULL); // size hardcored in the Mesh Heap
  
  TableAddr = ConstantExpr::getIntToPtr(TableAddrLong, TablePtrTy);

  return true;
}


void MESH::initializeCtor(Module &M) {
  MESHCtorFunction = nullptr;
  std::tie(MESHCtorFunction, std::ignore) =
      createSanitizerCtorAndInitFunctions(M, kMESHModuleCtorName, kMESHInitRtName,
                                          /*InitArgTypes=*/{}, /*InitArgs=*/{});
  appendToGlobalCtors(M, MESHCtorFunction, 0);
}


void MESH::initializeFunctionDefinitionList(Module &M) {
  for (auto &F: M) {
    if (!F.isDeclaration()) FunctionDefintionSet.insert(F.getGUID());
  }
}



void MESH::initializeInlineAsms() {
  switch (TargetTriple.getArch()) {
    case Triple::x86_64:
      arch = X86_64;
      NR_ADDR_BITS = 48; // @todo
      POINTER_SIZE = 64;
      NR_TAG_BITS = POINTER_SIZE - NR_ADDR_BITS;
      addr_mask = UINT64_MAX >> NR_TAG_BITS;
      break;
    case Triple::aarch64:
      arch = AARCH64;
      NR_ADDR_BITS = 48;
      POINTER_SIZE = 64;
      NR_TAG_BITS = POINTER_SIZE - NR_ADDR_BITS;
      addr_mask = UINT64_MAX >> NR_TAG_BITS;
      break;
    default:
      report_fatal_error("MESH pass: Unsupported architecture");
  }
}


void MESH::initializeCallbacks(Module &M) {

  LLVMContext *Ctx = &M.getContext();

  MESHFail = M.getOrInsertFunction("__mesh_fail",
          FunctionType::get(VoidTy, {Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int64Ty}, false));
  MESHFailNonHeap = M.getOrInsertFunction("__mesh_fail_non_heap",
          FunctionType::get(VoidTy, {Int64Ty}, false));
  MESHDerefFn = M.getOrInsertFunction("__mesh_metadata_deref",
          FunctionType::get(PtrTy, {PtrTy, Int64Ty}, false));
  MESHStripFn = M.getOrInsertFunction("__mesh_metadata_strip",
          FunctionType::get(PtrTy, {PtrTy}, false));
  MESHCheckFn = M.getOrInsertFunction("__mesh_metadata_check",
          FunctionType::get(Type::getVoidTy(*Ctx), {PtrTy, Int64Ty}, false));
  MESHTimestampFn = M.getOrInsertFunction("__mesh_metadata_timestamp",
          FunctionType::get(PtrTy, {Int64Ty, Int64Ty}, false));
  MESHDetimestampFn = M.getOrInsertFunction("__mesh_metadata_detimestamp",
          FunctionType::get(VoidTy, {Int64Ty}, false));

  MESHMallocFn = M.getOrInsertFunction("__mesh_malloc",
          FunctionType::get(PtrTy, {Int64Ty}, false));
  FunctionCallee DefaultMallocFn = M.getOrInsertFunction("malloc",
          FunctionType::get(PtrTy, {Int64Ty}, false));
  DefaultMallocFn.getCallee()->replaceAllUsesWith(MESHMallocFn.getCallee());

  MESHFreeFn = M.getOrInsertFunction("__mesh_free",
          FunctionType::get(VoidTy, {PtrTy}, false));
  FunctionCallee DefaultFreeFn = M.getOrInsertFunction("free",
          FunctionType::get(VoidTy, {PtrTy}, false));
  DefaultFreeFn.getCallee()->replaceAllUsesWith(MESHFreeFn.getCallee());

  MESHCallocFn = M.getOrInsertFunction("__mesh_calloc",
          FunctionType::get(PtrTy, {Int64Ty, Int64Ty}, false));
  FunctionCallee DefaultCallocFn = M.getOrInsertFunction("calloc",
          FunctionType::get(PtrTy, {Int64Ty, Int64Ty}, false));
  DefaultCallocFn.getCallee()->replaceAllUsesWith(MESHCallocFn.getCallee());

  MESHReallocFn = M.getOrInsertFunction("__mesh_realloc",
          FunctionType::get(PtrTy, {PtrTy, Int64Ty}, false));
  FunctionCallee DefaultReallocFn = M.getOrInsertFunction("realloc",
          FunctionType::get(PtrTy, {PtrTy, Int64Ty}, false));
  DefaultReallocFn.getCallee()->replaceAllUsesWith(MESHReallocFn.getCallee());
}


Function* MESH::createInitGlobalsFunction(Module &M) {
  const std::string Name = kMESHInitGlobalsPrefix + M.getName().str();
  Function *F = Function::Create(FunctionType::get(VoidTy, false), GlobalValue::InternalLinkage, Name, M);

  BasicBlock *BB = BasicBlock::Create(M.getContext(), "", F);
  IRBuilder<> IRB(ReturnInst::Create(M.getContext(), BB));
  return F;
}


Value *MESH::stripPtr(Value *Ptr, Instruction *InsertBefore) {
  if (!dyn_cast<PointerType>(Ptr->getType()))
    return Ptr; // not a pointer

  IRBuilder<> IRB(InsertBefore);
  Value *PtrLong = IRB.CreatePointerCast(Ptr, IntptrTy);
  Value *Mask;
  Mask = ConstantInt::get(IntptrTy, addr_mask);
  
  Value *StrippedPtr = IRB.CreateAnd(PtrLong, Mask);
  
  return IRB.CreateIntToPtr(StrippedPtr, Ptr->getType());
}


Value *MESH::checkPtrVarSize(Value *Ptr, Instruction *InsertBefore, Value *Size) {
  // head
  // InsertBefore
  // tail

  // transforms to:

  // head
  // 1. if tagged
  //   2. get tag
  //   3. get lower bound
  //   4. if less than lower bound 
  //   5.   abort
  //   6. get upper bound
  //   7. if greater than upper bound
  //   8.   abort
  // 9. else
  //  10. if not null 
  //  11.   if addr < Mesh Heap upper bound
  //  12.     abort
  // 
  // InsertBefore
  // tail
  
  Function *Function = InsertBefore->getParent()->getParent();

  BasicBlock *Head_bb = InsertBefore->getParent();
  BasicBlock *Tail_bb = Head_bb->splitBasicBlock(InsertBefore, "tail_bb");
  BasicBlock *IsTagged_bb = BasicBlock::Create(InsertBefore->getContext(), "is_tagged", Function);
  BasicBlock *IsNotTagged_bb = BasicBlock::Create(InsertBefore->getContext(), "is_not_tagged", Function);

  IRBuilder<> IRB(Head_bb->getTerminator());


  // 1. if tagged
  Value *PtrLong = IRB.CreatePointerCast(Ptr, IntptrTy);
  Value *IsTaggedCond = IRB.CreateICmpUGE(PtrLong, ConstantInt::get(Int64Ty, (0x1ull << NR_ADDR_BITS)));

  BranchInst *IsTaggedCondBr = BranchInst::Create(IsTagged_bb, IsNotTagged_bb, IsTaggedCond);
  ReplaceInstWithInst(Head_bb->getTerminator(), IsTaggedCondBr);
  // 2. get tag

  IRB.SetInsertPoint(IsTagged_bb);

  Value *TagLong;
  TagLong = IRB.CreateLShr(PtrLong, POINTER_SIZE - NR_TAG_BITS);
  Value *MetadataTableOffsetLong = IRB.CreateShl(TagLong, 4); // * 16
  Value *LBAddrLong = IRB.CreateAdd(MetadataTableOffsetLong, TableAddrLong);

  // 3. get lower bound
  Value *LowerBound = IRB.CreateLoad(Int64Ty, IRB.CreateIntToPtr(LBAddrLong, PointerType::getUnqual(Int64Ty)), "lower_bound_load");
  
  // 4. if less than lower bound
  BasicBlock* Fail_bb = BasicBlock::Create(InsertBefore->getContext(), "fail", Function);
 
  Value *LowerBoundCmp = IRB.CreateICmpULT(PtrLong, LowerBound, "illegal_lower_bound_cmp");
 
  Value *DerefAddrEnd = IRB.CreateAdd(PtrLong, Size, "deref_addr_end");
  
  // 6. get upper bound
  // compute upper bound location
  Value *UpperBoundAddrLong = IRB.CreateAdd(LBAddrLong, ConstantInt::get(Int64Ty, 8) );

  Value *StrippedPtrLong;
  StrippedPtrLong = IRB.CreateAnd(PtrLong, ConstantInt::get(PtrLong->getType(), addr_mask));
  Value *StrippedPtr = IRB.CreateIntToPtr(StrippedPtrLong, Ptr->getType());


  // load upper bound
  Value *UpperBound = IRB.CreateLoad(Int64Ty, IRB.CreateIntToPtr(UpperBoundAddrLong, PointerType::getUnqual(Int64Ty)), "upper_bound_load");

  //   7. if greater than upper bound
  Value *UpperBoundCmp = IRB.CreateICmpUGT(DerefAddrEnd, UpperBound);
 

  Value *IllegalAccessCmp = IRB.CreateOr(LowerBoundCmp, UpperBoundCmp, "illegal_access_cond");
 
  // replace terminator
  if (IsTagged_bb->getTerminator()) {
    // the original terminator is no longer needed
    IsTagged_bb->getTerminator()->eraseFromParent();
  }
  IRB.CreateCondBr(IllegalAccessCmp, Fail_bb, Tail_bb, MDBuilder(*C).createBranchWeights(1, 100000));

  // 9. check that untagged pointers do not access our heap
  IRB.SetInsertPoint(IsNotTagged_bb);
  
  // 10. if not null
  Value *NonZeroCond = IRB.CreateIsNotNull(PtrLong);
  Value *IllegalHeapAccessCond = IRB.CreateICmpULT(PtrLong, HeapUpperLimitLong, "illegal_heap_access_from_outside");
  if (IsNotTagged_bb->getTerminator()) {
    // the original terminator is no longer needed
    IsNotTagged_bb->getTerminator()->eraseFromParent();
  }
  BasicBlock* NonHeapFail_bb = BasicBlock::Create(InsertBefore->getContext(), "fail_non_heap", Function);
  Value *NonZeroAndIllegalCond = IRB.CreateAnd(IllegalHeapAccessCond, NonZeroCond, "illegal_access_cond");
  IRB.CreateCondBr(NonZeroAndIllegalCond, NonHeapFail_bb, Tail_bb, MDBuilder(*C).createBranchWeights(1, 100000));


  //   8.   abort
  IRB.SetInsertPoint(Fail_bb);
  IRB.CreateCall(MESHFail, {PtrLong, TagLong, DerefAddrEnd, LowerBound, LBAddrLong});
  IRB.CreateUnreachable();

  // 9. abort (non heap)
  IRB.SetInsertPoint(NonHeapFail_bb);
  IRB.CreateCall(MESHFailNonHeap, {PtrLong});
  IRB.CreateUnreachable();
  
  IRB.SetInsertPoint( Tail_bb->getFirstNonPHI() );
  PHINode *phi = IRB.CreatePHI(Ptr->getType(), 2, "stripped_ptr");
  phi->addIncoming(Ptr, IsNotTagged_bb);
  phi->addIncoming(StrippedPtr, IsTagged_bb);
  return phi;
}


Value *MESH::checkPtr(Value *Ptr, Instruction *InsertBefore, size_t size) {
  return checkPtrVarSize( Ptr, InsertBefore, ConstantInt::get(Int64Ty, size) );
}


void MESH::instrumentLoad(LoadInst *LI) {
  LLVM_DEBUG(dbgs() << "Instrumenting LOAD " << *LI << " of type " << *LI->getPointerOperandType() << " with value of type " << *LI->getType() << '\n');
  Value *StrippedPtr = checkPtr(LI->getPointerOperand(), LI, dataLayout_p->getTypeStoreSize(LI->getType()) );
  LI->setOperand(LI->getPointerOperandIndex(), StrippedPtr);
}


void MESH::instrumentStore(StoreInst *SI) {
  LLVM_DEBUG(dbgs() << "Instrumenting STORE " << *SI << '\n');

  Value *StrippedPtr = checkPtr(SI->getPointerOperand(), SI, dataLayout_p->getTypeStoreSize(SI->getValueOperand()->getType()) );
  SI->setOperand(SI->getPointerOperandIndex(), StrippedPtr);
}


bool MESH::instrumentFunctionCall(CallInst *CI, const Module &M) {
  if (!CI) return false;
  if (!CI->getCalledFunction()) return false;

  const Function *F = dyn_cast<Function>(CI->getCalledFunction());

  if (!F) {
    LLVM_DEBUG(dbgs() << "Cannot instrument call " << *CI << '\n');
    return false;
  }

  bool changed = false;

  LLVM_DEBUG(dbgs() << "Looking for " << F->getName() << " in the module\n");
    
  if (F->getName().str().rfind("llvm.experimental.vector.reduce.add", 0) == 0) return false; // skip this for now
  if (F->getName().startswith("__mesh_")) {
    return false; // one of our functions
  }

#ifdef PRINT_INSTR
    std::cerr << "CallInst name " << F->getName().str() << '\n';      
#endif

  bool foundFunction = std::find(FunctionDefintionSet.begin(), FunctionDefintionSet.end(), F->getGUID()) != FunctionDefintionSet.end();

  if ( !foundFunction ) {
    for (unsigned i = 0; i < CI->getNumOperands() - 1; i++) {
      Value *Operand = CI->getOperand(i);
      Type *Type_p = Operand->getType();
      LLVM_DEBUG(dbgs() << "Operand " << *Operand << " of type " << *Type_p << '\n');
      if ( Type_p->isMetadataTy() ) {
        // nothing to do
      }
      else if ( Type_p->isPointerTy() ) {
        IRBuilder<> IRB(CI);
        if (!canSkipPointer(Operand, {}) ) {
          Value *StrippedPtr = stripPtr(Operand, CI);
          //Value *StrippedPtr = checkPtr(Operand, CI, dataLayout_p->getTypeStoreSize(Operand->getType()));
          CI->setOperand(i, StrippedPtr); 
          changed = true;
        }
      }
    }
  }
  else {
    LLVM_DEBUG(dbgs() << "Skipped because it is internal and so it will be instrumented\n");
  }
  return changed;
}


void MESH::instrumentMemIntrinsic(Instruction *I, IRBuilder<> &IRB) {
  LLVM_DEBUG(dbgs() << "Instrumenting MemInstrinsic " << *I << '\n');

  if (CallInst *InstAsCall = dyn_cast<CallInst>(I)) {
    const Function *F = dyn_cast<Function>(
                                     InstAsCall->getCalledFunction()->stripPointerCasts());
    if (!F) return;    
  
    StringRef Name = F->getName();
    if (Name.startswith("llvm.memcpy") ||
        Name.startswith("llvm.memmove")) {

#ifdef INSTR_STATS
      total_mem_intr += 2;
#endif
      if ( !canSkipPointer( I->getOperand(0), {} ) ) {
        Value *StrippedPtr0 = checkPtrVarSize(I->getOperand(0), I, I->getOperand(2) );
        I->setOperand(0, StrippedPtr0);
#ifdef INSTR_STATS
        instr_mem_intr++;
#endif
      }
      if ( !canSkipPointer( I->getOperand(1), {} ) ) {
        Value *StrippedPtr1 = checkPtrVarSize(I->getOperand(1), I, I->getOperand(2));
        I->setOperand(1, StrippedPtr1);
#ifdef INSTR_STATS
        instr_mem_intr++;
#endif
      }
    }
    else if (Name.startswith("llvm.memset")) {
#ifdef INSTR_STATS
      total_mem_intr++;
#endif
      if ( !canSkipPointer( I->getOperand(0), {} ) ) {
        Value *StrippedPtr0 = checkPtrVarSize(I->getOperand(0), I, I->getOperand(2) );
        I->setOperand(0, StrippedPtr0);
#ifdef INSTR_STATS
        instr_mem_intr++;
#endif
      }
    }
    else {
      LLVM_DEBUG(dbgs() << "MemIntrisic " << *I << "(" + Name + ") not recognized!!!\n");
    }    
  }
  else {
    LLVM_DEBUG(dbgs() << "MemIntrisic " << *I << " not a CallInst!!!\n");
  }
  
}



bool MESH::canSkipPointer(const Value *PointerOperand, std::vector<const Value *> AlreadyProcessed) {
  auto it = SkippablePointers.find(PointerOperand);
  if ( it != SkippablePointers.end() ) {
    return true;
  }
  it = NotSkippablePointers.find(PointerOperand);
  if ( it != NotSkippablePointers.end() ) {
    return false;
  }


  auto it2 = std::find(AlreadyProcessed.begin(), AlreadyProcessed.end(), PointerOperand);
  if (it2 != AlreadyProcessed.end()) {
    // cycle detected
    NotSkippablePointers.insert(PointerOperand);
    return false;
  }
  AlreadyProcessed.push_back(PointerOperand); // avoid infinite cycles

  if (isa<AllocaInst>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    return true;
  }
  else if (isa<Constant>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    return true;
  }
  else if (isa<GlobalVariable>(PointerOperand)) {
    std::cerr << "Skipping global\n";
    SkippablePointers.insert(PointerOperand);
    return true;
  }
  else if (isa<MetadataAsValue>(PointerOperand)) {
    SkippablePointers.insert(PointerOperand);
    std::cerr << "Skipping metadata\n";
    return true;
  }
  else if  (const GEPOperator *GEP = dyn_cast<GEPOperator>(PointerOperand)) {
    return canSkipPointer(GEP->getPointerOperand(), AlreadyProcessed);
  }
  else if (const PHINode *phi = dyn_cast<PHINode>(PointerOperand)) {
    unsigned N = phi->getNumIncomingValues();
    for (unsigned i = 0; i < N; i++) {
      if ( !canSkipPointer(phi->getIncomingValue(i) , AlreadyProcessed) ) {
        NotSkippablePointers.insert(PointerOperand);
        return false;
      }
    }
    SkippablePointers.insert(PointerOperand);
    return true;
  }
  else if (const SelectInst *sel = dyn_cast<SelectInst>(PointerOperand)) {
    return canSkipPointer(sel->getTrueValue(), AlreadyProcessed) && canSkipPointer(sel->getFalseValue(), AlreadyProcessed);
  }

  NotSkippablePointers.insert(PointerOperand);
  return false;
}

bool MESH::canSkipLoad(const LoadInst *LI) {
  return canSkipPointer(LI->getPointerOperand(), std::vector<const Value *>{});
}

bool MESH::canSkipFunctionOperand(const Value *Op) {
  bool canSkip = false;
  // skip only if all generators are allocas
  if (isa<AllocaInst>(Op)) canSkip = true;
  else if (isa<Constant>(Op)) canSkip = true;

  return canSkip;
}

bool MESH::canSkipStore(const StoreInst *SI) {
  return canSkipPointer(SI->getPointerOperand(), std::vector<const Value *>{});
}

bool MESH::instrumentMemAccesses(
    SmallVectorImpl<LoadInst *> &Loads,
    SmallVectorImpl<StoreInst *> &Stores,
    SmallVectorImpl<Instruction *> &MemInstrinsics
    ) {
    bool changed = false;

    for (LoadInst *I: Loads) {
      if ( isInterestingLoad(I) ) {
        if ( !canSkipLoad(I) ) {
          instrumentLoad(I);
          changed = true;
#ifdef INSTR_STATS
          instr_load++;
#endif
        } else {
#ifdef INSTR_STATS
          skipped_load++;
#endif
        }
      }
      else {
#ifdef INSTR_STATS
          unintr_load++;
#endif
      }
    }
    for (StoreInst *I: Stores) {
      if ( isInterestingStore(I) ) {
        if ( !canSkipStore(I) ) {
          instrumentStore(I);
          changed = true;
#ifdef INSTR_STATS
          instr_store++;
#endif
        }
        else {
#ifdef INSTR_STATS
          skipped_store++;
#endif
        }
      }
      else {
#ifdef INSTR_STATS
          unintr_store++;
#endif
      }
    }
    for (Instruction *I: MemInstrinsics) {
      IRBuilder<> IRB{I};
      instrumentMemIntrinsic(I, IRB);
      changed = true;
    }
    return changed;
}


bool MESH::isInterestingLoad(const LoadInst *LI) {
  Type *type_p = LI->getPointerOperandType();
    
  if ( !(type_p->isStructTy() || type_p->isArrayTy() || type_p->isVectorTy() ||
           type_p->isPointerTy()) ) {
      LLVM_DEBUG(dbgs() << "Type " << *type_p << " is not interesting.\n");
      return false;
  }
  return true;
}

bool MESH::isInterestingStore(const StoreInst *SI) {
  const Value *PtrOperand = SI->getPointerOperand();
  // different address spaces
  Type *Ty = cast<PointerType>(PtrOperand->getType()->getScalarType());
  if (Ty->getPointerAddressSpace() != 0)
    return false;

  // swifterror addresses
  if (PtrOperand->isSwiftError())
    return false;

  if ( !(Ty->isStructTy() || Ty->isArrayTy() || Ty->isVectorTy() || Ty->isPointerTy()) ) {
    return false;
  }
  return true;
}


bool MESH::isInterestingArgument(const Argument *Arg) {
  LLVM_DEBUG(dbgs() << "Arg " << *Arg << '\n');
  Type *TypePtr = Arg->getType(); // expected type
  if ( !(TypePtr->isStructTy() || TypePtr->isArrayTy() || TypePtr->isVectorTy() ||
         TypePtr->isPointerTy()) ) {
    LLVM_DEBUG(dbgs() << "Argument type " << *TypePtr << " is not interesting.\n");

    return false;
  }

  LLVM_DEBUG(dbgs() << "Argument type " << *TypePtr << " IS interesting.\n");
  return true;  
}

bool MESH::isInterestingFunction(const Function *F) {
  // don't instrument functions without body.
  if (F->isDeclaration())
    return false;
  //don't instrument functions inserted by the compiler.
  if (F->getName().startswith("llvm."))
    return false;
  // don't instrument functions inserted by this pass.
  if (F->getName().startswith(kMESHCtorPrefix) ||
      F->getName().startswith(kMESHFnPrefix))
    return false;
  // don't instrument when explicitly turned off.
  if (!F->hasFnAttribute(Attribute::MESH))
    return false;
  return true;
}



/* ------------------- */

bool MESH::runOnModule(Module &M) {
  LLVM_DEBUG(dbgs() << "Entering MESH pass for module " << M.getName() << '\n');
  
  bool Changed = false;

  initializeCtor(M);
  initializeInlineAsms();
  initializeCallbacks(M);
  initializeFunctionDefinitionList(M);

#ifdef ONLY_LOG
  return Changed;
#endif

  for (auto &F : M) { // for each function in module
    SkippablePointers = {}; // per function
    NotSkippablePointers = {};

    if (!isInterestingFunction(&F)) continue;

#ifdef PRINT_INSTR
    std::cerr << "Before instrumenting:\n";      
    F.dump();
#endif

    SmallVector<LoadInst *, 32> Loads;
    SmallVector<StoreInst *, 32> Stores;
    SmallVector<Instruction *, 2> MemInstrinsics;


    LLVM_DEBUG(dbgs() << "==================================================\n");
    LLVM_DEBUG(dbgs() << "Processing function " << F.getName() << "...\n");
    LLVM_DEBUG(dbgs() << "==================================================\n");

    /* collect the instructions that we need to instrument */
    for (auto &BB : F) { // for each basic block in function
      for (auto &I : BB) { // for each instruction in basic block
#ifdef PRINT_INSTR
        std::cerr << "Instruction:\n";
        I.dump();
#endif
        if (isa<MemIntrinsic>(I)) {
          MemInstrinsics.push_back(&I);
        }
        else if (CallInst *CI = dyn_cast<CallInst>(&I)) {
          // strip pointers given to external functions
          Changed |= instrumentFunctionCall(CI, M);
        }
        else if (LoadInst *LI = dyn_cast<LoadInst>(&I)) {
          // collect load for possible instrumentation
          Loads.push_back(LI);
        }
        else if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
          // collect store for possible instrumentation
          Stores.push_back(SI);
        }
      } // for (auto &I : BB)
    } // for (auto &BB : F)

    Changed |= instrumentMemAccesses(Loads, Stores, MemInstrinsics);

#ifdef PRINT_INSTR
    std::cerr << "After instrumenting:\n";    
    F.dump();
#endif
  } // for (auto &F : M)

#ifdef INSTR_STATS
  std::cerr << "Instrumented loads: " << instr_load << '\n';
  std::cerr << "Instrumented stores: " << instr_store << '\n';
  std::cerr << "Skipped loads: " << skipped_load << '\n';
  std::cerr << "Skipped stores: " << skipped_store << '\n';
#endif

  return Changed;
}

ModulePass *llvm::createMESHPass() {
  return new MESH();
}

