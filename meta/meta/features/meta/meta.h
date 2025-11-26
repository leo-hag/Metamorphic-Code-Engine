#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include <random>
#include <memory>
#include <set>
#include <unordered_map>
#include <functional>
#include <algorithm>
#include <cstring>
#include <queue>
#include <stack>
#include <cassert>
#include <optional>
#include <array>
#include <bitset>

struct instruction_t;
struct basic_block_t;
struct control_flow_graph_t;

enum class register_type_e : uint8_t {
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    NONE
};

enum class opcode_e : uint16_t {
    MOV, ADD, SUB, XOR, OR, AND, SHL, SHR, SAR,
    PUSH, POP, CALL, RET, JMP, JE, JNE, JG, JL, JGE, JLE,
    CMP, TEST, LEA, NOP, IMUL, IDIV, INC, DEC,
    NOT, NEG, CDQ, CMOV, SETZ, SETNE, SETG, SETL,
    XCHG, BSWAP, ROL, ROR, BT, BTS, BTR, BTC,
    INVALID
};

enum class addressing_mode_e : uint8_t {
    REGISTER,
    IMMEDIATE,
    MEMORY_DIRECT,
    MEMORY_BASE_OFFSET,
    MEMORY_BASE_INDEX_SCALE,
    RIP_RELATIVE
};

struct operand_t {
    addressing_mode_e mode;
    register_type_e reg;
    register_type_e base_reg;
    register_type_e index_reg;
    uint8_t scale;
    int64_t displacement;
    uint64_t immediate;
    uint8_t size;

    operand_t( );
    bool operator==( const operand_t& other ) const;
};

struct instruction_t {
    opcode_e opcode;
    std::vector<operand_t> operands;
    uint64_t address;
    std::vector<uint8_t> original_bytes;

    bool is_junk;
    bool is_branch;
    bool is_conditional;
    uint64_t branch_target;

    std::set<register_type_e> reads;
    std::set<register_type_e> writes;

    instruction_t( );
    size_t encode( std::vector<uint8_t>& output ) const;
    bool has_side_effects( ) const;
};

struct basic_block_t {
    uint64_t id;
    uint64_t start_address;
    std::vector<instruction_t> instructions;
    std::vector<uint64_t> predecessors;
    std::vector<uint64_t> successors;
    bool is_entry;
    bool is_exit;
    uint32_t dispatcher_case_value;
    bool is_dispatcher;

    basic_block_t( );
};

struct control_flow_graph_t {
    std::map<uint64_t, basic_block_t> blocks;
    uint64_t entry_block_id;
    std::vector<uint64_t> exit_block_ids;

    control_flow_graph_t( );
};

enum class data_location_e : uint8_t {
    STACK,
    GLOBAL,
    HEAP
};

struct variable_mapping_t {
    data_location_e location;
    int64_t offset;
    register_type_e reg;
    size_t size;
    uint64_t original_address;

    variable_mapping_t( );
};

enum class opaque_predicate_type_e : uint8_t {
    ALWAYS_TRUE,
    ALWAYS_FALSE,
    COMPLEX_ARITHMETIC,
    POINTER_ALIGNMENT
};

enum class jump_type_e : uint8_t {
    DIRECT,
    INDIRECT,
    COMPUTED,
    CALL_RET_CHAIN,
    SEH_EXCEPTION
};

enum class loop_mutation_e : uint8_t {
    KEEP_ORIGINAL,
    TO_RECURSION,
    UNROLL,
    REVERSE_ITERATION,
    SENTINEL_BASED
};

struct metamorphic_config_t {
    bool enable_instruction_substitution;
    bool enable_register_renaming;
    bool enable_code_permutation;
    bool enable_junk_insertion;
    bool enable_opaque_predicates;
    bool enable_control_flow_flattening;
    bool enable_block_reordering;
    bool enable_jump_substitution;
    bool enable_loop_mutation;
    bool enable_stack_mutation;
    bool enable_alignment_randomization;

    uint32_t junk_insertion_probability;
    uint32_t max_junk_instructions;
    uint32_t max_nop_padding;

    metamorphic_config_t( );
};

struct instruction_equivalence_t {
    opcode_e original;
    std::vector<std::vector<instruction_t>> equivalents;
};

struct loop_info_t {
    std::vector<uint64_t> block_ids;
    uint64_t header_id;
    uint64_t exit_id;
    std::set<register_type_e> induction_variables;
    bool is_countable;
    int64_t iteration_count;
};

struct dependency_node_t {
    size_t instruction_index;
    std::set<size_t> dependencies;
    std::set<size_t> dependents;
    int64_t level;
};

class c_metamorphic_engine {
public:
    c_metamorphic_engine( );
    ~c_metamorphic_engine( );

    bool transform( const std::vector<uint8_t>& input_code,
        std::vector<uint8_t>& output_code,
        uint64_t base_address = 0x400000 );

    void set_config( const metamorphic_config_t& config );
    metamorphic_config_t get_config( ) const;
    void set_seed( uint64_t seed );

private:
    bool disassemble( const std::vector<uint8_t>& code,
        std::vector<instruction_t>& instructions,
        uint64_t base_address );

    void build_control_flow_graph( const std::vector<instruction_t>& instructions,
        control_flow_graph_t& cfg );

    void analyze_data_flow( control_flow_graph_t& cfg );

    void identify_loops( control_flow_graph_t& cfg,
        std::vector<loop_info_t>& loops );

    void substitute_instructions( basic_block_t& block );
    std::vector<instruction_t> get_equivalent_sequence( const instruction_t& inst );
    void initialize_equivalence_classes( );

    void rename_registers( control_flow_graph_t& cfg );
    std::map<register_type_e, register_type_e> generate_register_mapping(
        const std::set<register_type_e>& used_registers );
    void apply_register_mapping( instruction_t& inst,
        const std::map<register_type_e, register_type_e>& mapping );

    void permute_instructions( basic_block_t& block );
    bool are_instructions_independent( const instruction_t& inst1,
        const instruction_t& inst2 );
    void build_dependency_graph( const basic_block_t& block,
        std::vector<dependency_node_t>& dep_graph );
    std::vector<size_t> topological_sort_with_randomization(
        const std::vector<dependency_node_t>& dep_graph );

    void insert_junk_code( basic_block_t& block );
    instruction_t generate_junk_instruction( );
    std::vector<instruction_t> generate_junk_block( size_t instruction_count );

    void insert_opaque_predicates( basic_block_t& block );
    std::vector<instruction_t> generate_opaque_predicate(
        opaque_predicate_type_e type, bool result );
    std::vector<instruction_t> generate_always_true_predicate( );
    std::vector<instruction_t> generate_always_false_predicate( );
    std::vector<instruction_t> generate_complex_arithmetic_predicate( bool result );
    std::vector<instruction_t> generate_pointer_alignment_predicate( bool result );

    void flatten_control_flow( control_flow_graph_t& cfg );
    basic_block_t create_dispatcher_block( const control_flow_graph_t& cfg );
    void convert_to_dispatcher_model( control_flow_graph_t& cfg,
        uint64_t dispatcher_id );

    void reorder_blocks( control_flow_graph_t& cfg );
    std::vector<uint64_t> generate_random_block_order(
        const control_flow_graph_t& cfg );

    void substitute_jumps( control_flow_graph_t& cfg );
    void replace_direct_jump( instruction_t& jump_inst, jump_type_e new_type );
    std::vector<instruction_t> create_indirect_jump( uint64_t target );
    std::vector<instruction_t> create_computed_jump( uint64_t target );
    std::vector<instruction_t> create_call_ret_chain( uint64_t target );

    void mutate_loops( control_flow_graph_t& cfg,
        const std::vector<loop_info_t>& loops );
    void convert_loop_to_recursion( control_flow_graph_t& cfg,
        const loop_info_t& loop );
    void unroll_loop( control_flow_graph_t& cfg,
        const loop_info_t& loop,
        size_t unroll_factor );
    void reverse_loop_iteration( control_flow_graph_t& cfg,
        const loop_info_t& loop );
    void convert_to_sentinel_loop( control_flow_graph_t& cfg,
        const loop_info_t& loop );

    void mutate_data_locations( control_flow_graph_t& cfg );
    void identify_variables( const control_flow_graph_t& cfg,
        std::map<uint64_t, variable_mapping_t>& variables );
    void move_to_stack( control_flow_graph_t& cfg,
        const variable_mapping_t& var );
    void move_to_global( control_flow_graph_t& cfg,
        const variable_mapping_t& var );
    void move_to_heap( control_flow_graph_t& cfg,
        const variable_mapping_t& var );

    void randomize_alignment( control_flow_graph_t& cfg );
    void insert_random_padding( basic_block_t& block );
    void insert_random_nops( basic_block_t& block, size_t count );
    std::vector<uint8_t> generate_random_nop_sequence( size_t length );

    bool reassemble( const control_flow_graph_t& cfg, std::vector<uint8_t>& output );
    void fix_relocations( std::vector<uint8_t>& code,
        const std::map<uint64_t, uint64_t>& address_map );

    size_t encode_instruction( const instruction_t& inst,
        std::vector<uint8_t>& output ) const;
    uint8_t encode_modrm( uint8_t mod, uint8_t reg, uint8_t rm ) const;
    uint8_t encode_sib( uint8_t scale, uint8_t index, uint8_t base ) const;
    uint8_t encode_rex( bool w, bool r, bool x, bool b ) const;
    uint8_t register_to_encoding( register_type_e reg ) const;

    void analyze_register_usage( const basic_block_t& block,
        std::set<register_type_e>& read_regs,
        std::set<register_type_e>& written_regs );

    bool can_reorder_instructions( const instruction_t& inst1,
        const instruction_t& inst2 );

    void compute_live_registers( control_flow_graph_t& cfg,
        std::map<uint64_t, std::set<register_type_e>>& live_in,
        std::map<uint64_t, std::set<register_type_e>>& live_out );

    uint64_t random_uint64( );
    uint32_t random_uint32( );
    uint8_t random_uint8( );
    bool random_bool( uint32_t probability = 50 );
    register_type_e get_random_register( const std::set<register_type_e>& exclude );

    template<typename T>
    void shuffle_vector( std::vector<T>& vec );

    uint64_t allocate_block_id( );

    metamorphic_config_t config_;
    std::mt19937_64 rng_;
    uint64_t next_block_id_;

    std::map<opcode_e, std::vector<std::vector<instruction_t>>> equivalence_db_;

    std::set<register_type_e> general_purpose_registers_;
    std::set<register_type_e> preserved_registers_;
    std::set<register_type_e> scratch_registers_;

    std::map<uint64_t, variable_mapping_t> variable_map_;
    size_t stack_offset_;
    std::vector<uint64_t> heap_allocations_;

    std::map<uint64_t, uint64_t> old_to_new_address_;
};
