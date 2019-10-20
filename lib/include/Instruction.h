#pragma once

#include "List.h"
#include "Operand.h"
#include "Flag.h"

namespace spvgentwo
{
	// forward delcs
	class Type;
	class Function;
	class Module;

	class Instruction : public List<Operand>
	{
	public:
		using Iterator = EntryIterator<Operand>;

		template <class ...Args>
		Instruction(Module* _pModule, const spv::Op _op = spv::Op::OpNop, Args&& ... _args);
		template <class ...Args>
		Instruction(Function* _pFunction, const spv::Op _op = spv::Op::OpNop, Args&& ... _args);
		template <class ...Args>
		Instruction(BasicBlock* _pBasicBlock, const spv::Op _op = spv::Op::OpNop, Args&& ... _args);

		~Instruction();

		Module* getModule();
		const Module* getModule() const;

		Function* getFunction();
		const Function* getFunction() const;

		BasicBlock* getBasicBlock();
		const BasicBlock* getBasicBlock() const;

		// manual instruction construction:
		void setOperation(const spv::Op _op) { m_Operation = _op; };
		spv::Op getOperation() const { return m_Operation; }
		template<class ...Args>
		Operand& addOperand(Args&& ... _operand) { return emplace_back(stdrep::forward<Args>(_operand)...); }

		spv::Id getResultId() const;
		Instruction* getTypeInst() const;
		const Type* getType() const;

		// get StorageClass of OpVariable instructions
		spv::StorageClass getStorageClass() const;
	
		bool isType() const;
		bool isTerminator() const;

		bool hasResult() const { return hasResultId(m_Operation); }
		bool hasResultType() const { return hasResultTypeId(m_Operation); }
		bool hasResultAndType() const { return hasResultAndTypeId(m_Operation); }

		// reset Operation and clear Operands
		void reset();

		// get number of 32 bit words used by this instruction
		unsigned int getWordCount() const;

		// get opcode encoded with instruction word count [16 bit op code, 16 bit number of operand words] 
		unsigned int getOpCode() const;

		// serialize instructions of this basic block to the IWriter
		void write(IWriter* _pWriter, spv::Id& _resultId);

		// make operation from up to 3 intermediate results, resulting instruction has result and result type
		Instruction* makeOp(const spv::Op _instOp, Instruction* _pOp1, Instruction* _pOp2 = nullptr, Instruction* _pOp3 = nullptr, Instruction* _pResultType = nullptr);
		
		// direclty translate arguments to spirv operands
		template <class ...Args>
		Instruction* makeOpEx(const spv::Op _op, Args ... _args);

		// convert and add the raw data passed via _args as literal_t operands
		template <class ...Args>
		void appendLiterals(Args ... _args);

		void opNop();

		Instruction* opUndef(Instruction* _pResultType);

		Instruction* opSizeOf(Instruction* _pPointerToVar);

		// instruction generators:
		// all instructions generating a result id return a pointer to this instruction for reference (passing to other instruction operand)
		void opCapability(const spv::Capability _capability);

		void opMemoryModel(const spv::AddressingModel _addressModel, const spv::MemoryModel _memoryModel);

		void opExtension(const char* _pExtName);

		// generates extension id
		Instruction* opExtInstImport(const char* _pExtName);

		template <class ...Operands>
		Instruction* opExtInst(Instruction* _pResultType, Instruction* _pExtensionId, unsigned int _instOpCode, Operands ... _operands);

		Instruction* opLabel();

		Instruction* opFunction(const Flag<spv::FunctionControlMask> _functionControl, Instruction* _pResultType, Instruction* _pFuncType);

		Instruction* opFunctionParameter(Instruction* _pType);

		void opReturn();

		void opReturnValue(Instruction* _pValue);

		void opFunctionEnd();

		template <class ... ArgInstr>
		Instruction* opFunctionCall(Instruction* _pResultType, Instruction* _pFunction, ArgInstr ... _args);

		template <class ... ArgInstr>
		Instruction* call(Function* _pFunction, ArgInstr ... _args);

		//  _pFunction is result of opFunction
		template <class ... Instr>
		void opEntryPoint(const spv::ExecutionModel _model, Instruction* _pFunction, const char* _pName, Instr ... _instr);

		// _pResultType must be of OpTypePointer
		Instruction* opVariable(Instruction* _pResultType, const spv::StorageClass _storageClass, Instruction* _pInitializer = nullptr);

		void opName(Instruction* _pTarget, const char* _pName);

		void opMemberName(Instruction* _pTargetStructType, unsigned int _memberIndex, const char* _pName);

		template <class ... Decorations>
		void opDecorate(Instruction* _pTarget, spv::Decoration _decoration, Decorations ... _decorations);

		template <class ... Decorations>
		void opMemberDecorate(Instruction* _pTargetStructType, unsigned int _memberIndex, spv::Decoration _decoration, Decorations ... _decorations);

		template <class ... Instr>
		void opMemberId(Instruction* _pTarget, spv::Decoration _decoration, Instruction* _pId, Instr*..._ids);

		// deduce parent form input variables
		template <class ... VarInst>
		Instruction* opPhi(Instruction* _pVar, VarInst* ... _variables);	

		template <class ...LoopControlParams>
		void opLoopMerge(BasicBlock* _pMergeBlock, BasicBlock* _pContinueBlock, const Flag<spv::LoopControlMask> _loopControl, LoopControlParams ... _params);

		void opSelectionMerge(BasicBlock* _pMergeBlock, const spv::SelectionControlMask _control);

		// label is infered from the basic block on serialization
		void opBranch(BasicBlock* _pTargetBlock);

		// label is infered from the basic block on serialization
		void opBranchConditional(Instruction* _pCondition, BasicBlock* _pTrueBlock, BasicBlock* _pFalseBlock);
		void opBranchConditional(Instruction* _pCondition, BasicBlock* _pTrueBlock, BasicBlock* _pFalseBlock, const unsigned int _trueWeight, const unsigned int _falseWeight);

		template <class ... Instr>
		Instruction* opAccessChain(Instruction* _pResultType, Instruction* _pBase, Instruction* _pConstIndex, Instr* ... _pIndices);

		template <class ... IntIndices>
		Instruction* opAccessChain(Instruction* _pBase, const unsigned int _firstIndex, IntIndices... _indices);

		template <class ... Instr>
		Instruction* opInBoundsAccessChain(Instruction* _pResultType, Instruction* _pBase, Instruction* _pConstIndex, Instr* ... _pIndices);

		template <class ... Operands>
		Instruction* opLoad(Instruction* _pPointerToVar, const Flag<MemoryOperands> _memOperands = MemoryOperands::None, Operands ... _operands);

		template <class ... Operands>
		void opStore(Instruction* _pPointerToVar, Instruction* _valueToStore, const Flag<MemoryOperands> _memOperands = MemoryOperands::None, Operands ... _operands);

	private:
		void resolveId(spv::Id& _resultId);

		// creates literals
		template <class T, class ...Args>
		void makeOpInternal(T first, Args ... _args);

		template <class ... VarInst>
		Instruction* opPhiInternal(Instruction* _pVar, VarInst* ... _variables);

	private:
		spv::Op m_Operation = spv::Op::OpNop;

		enum class ParentType 
		{
			BasicBlock,
			Function,
			Module
		} m_parentType = ParentType::BasicBlock;

		union
		{
			BasicBlock* pBasicBlock = nullptr; // parent
			Function* pFunction;
			Module* pModule;
		} m_parent;

	};

	// free helper function
	void writeInstructions(IWriter* _pWriter, const List<Instruction>& _instructions, spv::Id& _resultId);

	template<class ...Args>
	inline Instruction::Instruction(Module* _pModule, const spv::Op _op, Args&& ..._args) :
		m_parentType(ParentType::Module), List(_pModule->getAllocator())
	{
		m_parent.pModule = _pModule;
		makeOpEx(_op, stdrep::forward<Args>(_args)...);
	}

	template<class ...Args>
	inline Instruction::Instruction(Function* _pFunction, const spv::Op _op, Args&& ..._args) :
		m_parentType(ParentType::Function), List(_pFunction->getAllocator())
	{
		m_parent.pFunction = _pFunction;
		makeOpEx(_op, stdrep::forward<Args>(_args)...);
	}

	template<class ...Args>
	inline Instruction::Instruction(BasicBlock* _pBasicBlock, const spv::Op _op, Args&& ..._args) :
		m_parentType(ParentType::BasicBlock), List(_pBasicBlock->getAllocator())
	{
		m_parent.pBasicBlock = _pBasicBlock;
		makeOpEx(_op, stdrep::forward<Args>(_args)...);
	}

	template<class ...Args>
	inline Instruction* Instruction::makeOpEx(const spv::Op _op, Args ..._args)
	{
		reset();

		m_Operation = _op;

		if constexpr (sizeof...(_args) > 0u)
		{
			makeOpInternal(_args...);
		}

		return this;
	}
	
	template<class T, class ...Args>
	inline void Instruction::makeOpInternal(T _first, Args ..._args)
	{
		if constexpr (traits::is_same_base_type_v<T, Instruction*> || traits::is_same_base_type_v<T, BasicBlock*> || traits::is_same_base_type_v<T, spv::Id> || traits::is_same_base_type_v<T, literal_t>)
		{
			addOperand(_first);
		}
		else if constexpr (sizeof(T) == sizeof(literal_t)) // bitcast to 32 bit literal
		{
			addOperand(*reinterpret_cast<const literal_t*>(&_first));
		}
		else
		{
			appendLiterals(_first);
		}

		if constexpr (sizeof...(_args) > 0u)
		{
			makeOpInternal(_args...);
		}
	}

	template<class ...Args>
	inline void Instruction::appendLiterals(Args ..._args)
	{
		appendLiteralsToContainer(*this, _args...);
	}

	template<class ...Operands>
	inline Instruction* Instruction::opExtInst(Instruction* _pResultType, Instruction* _pExtensionId, unsigned int _instOpCode, Operands ..._operands)
	{
		return makeOpEx(spv::Op::OpExtInst, _pResultType, InvalidId, _pExtensionId, literal_t{ _instOpCode }, _operands...);
	}

	template<class ...ArgInstr>
	inline Instruction* Instruction::opFunctionCall(Instruction* _pResultType, Instruction* _pFunction, ArgInstr ..._args)
	{
		return makeOpEx(spv::Op::OpFunctionCall, _pResultType, InvalidId, _pFunction, _args...);
	}

	template<class ...ArgInstr>
	inline Instruction* Instruction::call(Function* _pFunction, ArgInstr ..._args)
	{
		return opFunctionCall(_pFunction->getReturnType(), _pFunction->getFunction(), _args...);
	}

	template<class ...Instr>
	inline void Instruction::opEntryPoint(const spv::ExecutionModel _model, Instruction* _pFunction, const char* _pName, Instr ..._instr)
	{
		makeOpEx(spv::Op::OpEntryPoint, _model, _pFunction, _pName, _instr...);
	}

	template<class ...Decorations>
	inline void Instruction::opDecorate(Instruction* _pTarget, spv::Decoration _decoration, Decorations ..._decorations)
	{
		makeOpEx(spv::Op::OpDecorate, _pTarget, _decoration, _decorations...);
	}

	template<class ...Decorations>
	inline void Instruction::opMemberDecorate(Instruction* _pTargetStructType, unsigned int _memberIndex, spv::Decoration _decoration, Decorations ..._decorations)
	{
		makeOpEx(spv::Op::OpMemberDecorate, _pTargetStructType, _memberIndex, _decoration, _decorations...);
	}

	template<class ...Instr>
	inline void Instruction::opMemberId(Instruction* _pTarget, spv::Decoration _decoration, Instruction* _pId, Instr* ..._ids)
	{
		makeOpEx(spv::Op::OpDecorateId, _pTarget, _decoration, _ids...);
	}

	template<class ...VarInst>
	inline Instruction* Instruction::opPhi(Instruction* _pVar, VarInst* ..._variables)
	{
		makeOpEx(spv::Op::OpPhi, _pVar->getType(), InvalidId);
		return opPhiInternal(_pVar, _variables...);
	}

	template<class ...VarInst>
	inline Instruction* Instruction::opPhiInternal(Instruction* _pVar, VarInst* ..._variables)
	{
		addOperand(_pVar);
		addOperand(_pVar->getBasicBlock());

		if constexpr(sizeof...(_variables) > 0)
		{
			opPhiInternal(_variables...);
		}

		return this;
	}

	template<class ...LoopControlParams>
	inline void Instruction::opLoopMerge(BasicBlock* _pMergeBlock, BasicBlock* _pContinueBlock, const Flag<spv::LoopControlMask> _loopControl, LoopControlParams ..._params)
	{
		makeOpEx(spv::Op::OpLoopMerge, _pMergeBlock, _pContinueBlock, literal_t{ _loopControl }, _params...);
	}

	template<class ...Instr>
	inline Instruction* Instruction::opAccessChain(Instruction* _pResultType, Instruction* _pBase, Instruction* _pConstIndex, Instr* ..._pIndices)
	{
		return makeOpEx(spv::Op::OpAccessChain, _pResultType, InvalidId, _pBase, _pConstIndex, _pIndices...);
	}

	template<class ...IntIndices>
	inline Instruction* Instruction::opAccessChain(Instruction* _pBase, const unsigned int _firstIndex, IntIndices ..._indices)
	{
		// Base must be a pointer, pointing to the base of a composite object.

		const Type* pBaseType = _pBase->getType();
		auto it = pBaseType->getSubType(0u, _firstIndex, _indices...); // base is a pointer type, so 0 is used to get the inner type
		Module* pModule = _pBase->getModule();
		Instruction* pResultType = nullptr;

		if (it != nullptr)
		{
			// Result Type must be an OpTypePointer.
			// Its Type operand must be the type reached by walking the Base’s type hierarchy down to the last provided index in Indexes, and its Storage Class operand must be the same as the Storage Class of Base.
	
			Type&& ptrType(it->wrap(spv::Op::OpTypePointer));
			ptrType.setStorageClass(pBaseType->getStorageClass());
			pResultType = pModule->addType(ptrType);
		}

		return makeOpEx(spv::Op::OpAccessChain, pResultType, InvalidId, _pBase, pModule->constant(_firstIndex), pModule->constant<unsigned int>(_indices)...);
	}

	template<class ...Instr>
	inline Instruction* Instruction::opInBoundsAccessChain(Instruction* _pResultType, Instruction* _pBase, Instruction* _pConstIndex, Instr* ..._pIndices)
	{
		return makeOpEx(spv::Op::OpInBoundsAccessChain, _pResultType, InvalidId, _pBase, _pConstIndex, _pIndices...);
	}

	template<class ...Operands>
	inline Instruction* Instruction::opLoad(Instruction* _pPointerToVar, const Flag<MemoryOperands> _memOperands, Operands ..._operands)
	{
		// Result Type is the type of the loaded object.It must be a type with ﬁxed size; i.e., it cannot be, nor include, any OpTypeRuntimeArray types.
		// Pointer is the pointer to load through.Its type must be an OpTypePointer whose Type operand is the same as Result Type.
		Instruction* pResultType = getModule()->addType(_pPointerToVar->getType()->front());
		return makeOpEx(spv::Op::OpLoad, pResultType, InvalidId, _pPointerToVar, _memOperands.mask, _operands...);
	}

	template<class ...Operands>
	inline void Instruction::opStore(Instruction* _pPointerToVar, Instruction* _valueToStore, const Flag<MemoryOperands> _memOperands, Operands ..._operands)
	{
		return makeOpEx(spv::Op::OpStore, _pPointerToVar, _valueToStore, _memOperands.mask, _operands...);
	}
} // !spvgentwo