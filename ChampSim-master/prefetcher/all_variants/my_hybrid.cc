#include "cache.h"
#include "ooo_cpu.h"


#include <array>
#include <vector>
#include <algorithm>
#include <utility>
#include <memory>


// ========================================================================================================================
// ========================================================================================================================
// =================================================== Set-D Start.========================================================
// ========================================================================================================================
// ========================================================================================================================

//Set dualing








// ========================================================================================================================
// ========================================================================================================================
// ==================================================== Set-D END.=========================================================
// ========================================================================================================================
// ========================================================================================================================






// ========================================================================================================================
// ========================================================================================================================
// ==================================================== D-JOLT Start.======================================================
// ========================================================================================================================
// ========================================================================================================================

#include <numeric>

namespace { // anonymous

// ============================================================
//  D-JOLT parameters.
// ============================================================
static constexpr size_t UpperBitPtrBits = 5; // This determines that the number of upper bit variations that D-JOLT can handle.
static constexpr size_t UpperBitMask = 0xffffffffff000000; // This defines where upper bit is.

static constexpr size_t SignatureBits = 23; // Note: if you change this, you may need to re-tune the hash function in siggens.

#define LongRangePrefetcherSiggen Siggen_FifoRetCnt<7>
static constexpr size_t LongRangePrefetcherDistance = 15;
static constexpr size_t LongRangePrefetcher_N_Sets = 2048;
static constexpr size_t LongRangePrefetcher_N_Ways = 4;
static constexpr size_t LongRangePrefetcher_N_Vectors = 2;
static constexpr size_t LongRangePrefetcher_VectorSize = 8;
static constexpr size_t LongRangePrefetcher_TagBits = 12;
// -------------------------------------
//  miss table of long-range prefetcher
// -------------------------------------
// 4 way, 2048 Sets (8192 entry)
// Budget:
//  Signature Tag :      (23 - 11) bits X 8192 entry =  98304 bits
//  miss vector : (5 + 18 + 8) bits X 2 X 8192 entry = 507904 bits
//     compressed upper address :  5 bits
//     lower address            : 18 bits
//     bit vector               :  8 bits
//  lru bit :                    2 bits X 8192 entry =  16384 bits
//                                               Total 622592 bits

// ----------------------------------------------
//  signature generator of long-range prefetcher
// ----------------------------------------------
// Budget:
//  7 entry Queue
//   address : 32 bits X 7 entry = 224 bits
//   head pointer :                  3 bits
//   return counter :               32 bits
//                           Total 259 bits

// ----------------------------------------------
//  signature queue of long-range prefetcher
// ----------------------------------------------
// Budget:
//  15 entry Queue
//   signature : 23 bits X 15 entry = 345 bits
//   head pointer :                     4 bits
//                              Total 349 bits

#define ShortRangePrefetcherSiggen Siggen_FifoRetCnt<4>
static constexpr size_t ShortRangePrefetcherDistance = 4;
static constexpr size_t ShortRangePrefetcher_N_Sets = 1024;
static constexpr size_t ShortRangePrefetcher_N_Ways = 4;
static constexpr size_t ShortRangePrefetcher_N_Vectors = 2;
static constexpr size_t ShortRangePrefetcher_VectorSize = 8;
static constexpr size_t ShortRangePrefetcher_TagBits = 13;
// --------------------------------------
//  miss table of short-range prefetcher
// --------------------------------------
// 4 way, 1024 Sets (4096 entry)
// Budget:
//  Signature Tag :      (23 - 10) bits X 4096 entry =  53248 bits
//  miss vector : (5 + 18 + 8) bits X 2 X 4096 entry = 253952 bits
//     compressed upper address :  5bits
//     lower address            : 18bits
//     bit vector               :  8bits
//  lru bit :                     2bits X 4096 entry =   8192 bits
//                                               Total 315392 bits

// ----------------------------------------------
//  signature generator of short-range prefetcher
// ----------------------------------------------
// Budget:
//  4 entry Queue
//   address : 3 2bits X 4 entry = 128 bits
//   head pointer :                  2 bits
//   return counter :               32 bits
//                           Total 162 bits

// ----------------------------------------------
//  signature queue of short-range prefetcher
// ----------------------------------------------
// Budget:
//  4 entry Queue
//   signature : 23 bits X 4 entry = 92 bits
//   head pointer :                   2 bits
//                             Total 94 bits

static constexpr size_t ExtraMissTable_N_Sets = 256;
static constexpr size_t ExtraMissTable_N_Ways = 4;
static constexpr size_t ExtraMissTable_N_Vectors = 2;
static constexpr size_t ExtraMissTable_VectorSize = 8;
static constexpr size_t ExtraMissTable_TagBits = 15;
// ---------------------
//  extra miss table
// ---------------------
// 4 way, 256 Sets (1024 entry)
// Budget:
//  signature Tag :         (23 - 8) bits X 1024 entry = 15360 bits
//  miss vector :   (5 + 18 + 8) bits X 2 X 1024 entry = 63488 bits
//     compressed upper address :  5 bits
//     lower address            : 18 bits
//     bit vector               :  8 bits
//  lru bit :                      2 bits X 1024 entry =  2048 bits
//                                                 Total 80896 bits

// ============================================================

// This is a compressed expression of upper bit.
struct UpperBitPtr {
    size_t ptr;
    bool operator==(const UpperBitPtr& rhs) const noexcept { return ptr == rhs.ptr; }
    bool operator!=(const UpperBitPtr& rhs) const noexcept { return ptr != rhs.ptr; }
};

// This is a compressed representation of line address.
struct CompressedLineAddress {
    UpperBitPtr upper_part;
    uint64_t lower_part;
    bool isValid() const noexcept { return upper_part.ptr != 0; }
};

// This table records the correspondence between the compressed expression and the original expression.
class UpperBitTable {
    struct Entry { bool valid; uint64_t upper_bits; };
    std::array<Entry, (1ull << UpperBitPtrBits) - 1> table = {};
public:
    std::pair<bool, CompressedLineAddress> compress(uint64_t full_address) {
        const uint64_t upper_bits = full_address & UpperBitMask;
        const uint64_t lower_bits = (full_address & ~UpperBitMask) >> LOG2_BLOCK_SIZE;

        const auto exists_pos = std::find_if(table.begin(), table.end(), [upper_bits](const Entry& e) noexcept { return e.valid && upper_bits == e.upper_bits; });
        const bool entry_exists = exists_pos != table.end();

        if (entry_exists) {
            return { true, { static_cast<size_t>(exists_pos - table.begin()) + 1, lower_bits } };
        } else {
            const auto invalid_pos = std::find_if(table.begin(), table.end(), [](const Entry& e) noexcept { return !e.valid; });
            const bool invalid_entry_found = invalid_pos != table.end();

            if (invalid_entry_found) {
                (*invalid_pos) = { true, upper_bits };
                return { true, { static_cast<size_t>(invalid_pos - table.begin()) + 1, lower_bits } };
            } else {
                return { false, {} };
            }
        }
    }

    uint64_t decompress(CompressedLineAddress cla) const {
        return table.at(cla.upper_part.ptr - 1).upper_bits + (cla.lower_part << LOG2_BLOCK_SIZE);
    }
};

// ---------------------
//  upper bit table
// ---------------------
// 31 Sets Fully-asociative table
// Budget:
//  upper bit : 40 bits X 31 entry = 1240 bits
//  Valid :      1 bit  X 31 entry =   31 bits
//                             Total 1271 bits

// utility functions

template<size_t N>
std::array<size_t, N> make_initialized_lru_order() {
    std::array<size_t, N> ret;
    iota(ret.begin(), ret.end(), 0);
    return ret;
}

template<class T>
void update_lru_order(T& lru_order, size_t touch_pos) noexcept {
    assert(touch_pos < lru_order.size());
    for (auto& e : lru_order) {
        if (e < lru_order.at(touch_pos)) { ++e; }
    }
    lru_order.at(touch_pos) = 0;
}

template<size_t HistLen>
class Siggen_FifoRetCnt {
    std::array<uint32_t, HistLen> ghist = {};
    size_t head = 0;
    size_t return_count = 0;

    uint32_t makeSig() const noexcept {
        uint32_t sig = 0;
        for (size_t i = head; i < head + HistLen; ++i) {
            const uint32_t pc = ghist.at(i % HistLen);
            sig = (sig << (SignatureBits - 5)) | (sig >> 5);
            sig ^= pc ^ pc >> 2; // work well on both A64/x86
            sig &= ((1ull << SignatureBits) - 1);
        }
        sig ^= return_count * 0xabcd;
        return sig & ((1ull << SignatureBits) - 1);
    }
public:
    uint32_t onReturnInstruction(uint64_t, uint64_t) {
        ++return_count;
        return makeSig();
    }
    uint32_t onCallInstruction(uint64_t ip, uint64_t) {
        return_count = 0;
        ghist.at(head) = ip;
        head = (head + 1) % HistLen;
        return makeSig();
    }
};

template<size_t VectorSize>
class MissInfo {
    CompressedLineAddress base_address = {};
    std::array<bool, VectorSize> bit_vector = {};
public:
    bool add(CompressedLineAddress address) noexcept {
        if (base_address.isValid()) {
            if (base_address.upper_part.ptr != address.upper_part.ptr) { return false; }
            const int64_t diff = address.lower_part - base_address.lower_part;
            if (diff < 0) {
                return false;
            } else if (diff == 0) {
                return true;
            } else if (static_cast<size_t>(diff-1) < bit_vector.size()) {
                bit_vector.at(diff-1) = true;
                return true;
            } else {
                return false;
            }
        } else {
            base_address = address;
            return true;
        }
    }
    bool isValid() const noexcept { return base_address.isValid(); }
    std::vector<CompressedLineAddress> getAddresses() const {
        assert(isValid());
        std::vector<CompressedLineAddress> ret;
        ret.push_back(base_address);
        for (size_t i = 0; i < bit_vector.size(); ++i) {
            if (bit_vector.at(i)) { CompressedLineAddress tmp = base_address; tmp.lower_part += (i+1); ret.push_back(tmp); }
        }
        return ret;
    }
};

template<size_t N_Vectors, size_t VectorSize>
class MissTableEntry {
    std::array<MissInfo<VectorSize>, N_Vectors> elems = {};
public:
    bool insert_but_do_not_evict(CompressedLineAddress address) {
        for (size_t i = 0; i < N_Vectors; ++i) {
            const bool success = elems.at(i).add(address);
            if (success) { return true; }
        }
        return false;
    }
    std::vector<MissInfo<VectorSize>> getValidEntries() const {
        std::vector<MissInfo<VectorSize>> ret;
        for (const auto& e : elems) {
            if (e.isValid()) { ret.push_back(e); }
        }
        return ret;
    }
};

template<size_t N_Ways, class T, class U, class Hasher>
class FullyAssociativeLRUTable {
    struct Entry {
        size_t tag;
        U value;
        bool valid;
        Entry() : tag(0), value(), valid(false) {}
    };
    std::array<Entry, N_Ways> table = {};
    std::array<size_t, N_Ways> lru_order = make_initialized_lru_order<N_Ways>();

    size_t find_index_of(const T& key) const {
        const size_t tag = Hasher{}(key);
        return std::find_if(table.begin(), table.end(), [tag](const Entry& entry) noexcept { return entry.valid && entry.tag == tag; }) - table.begin();
    }
public:
    const U& operator[](const T& key) const {
        assert(contains(key));
        return table.at(find_index_of(key)).value;
    }
    U& operator[](const T& key) {
        assert(contains(key));
        return table.at(find_index_of(key)).value;
    }

    void touch(const T& key) {
        assert(contains(key));
        update_lru_order(lru_order, find_index_of(key));
    }
    void insert(const T& key, const U& elem) {
        if (contains(key)) {
            const size_t index = find_index_of(key);
            table.at(index).value = elem;
            touch(key);
        } else {
            const size_t victim_index = std::max_element(lru_order.begin(), lru_order.end()) - lru_order.begin();
            table.at(victim_index).tag = Hasher{}(key);
            table.at(victim_index).value = elem;
            table.at(victim_index).valid = true;
            touch(key);
        }
    }
    bool contains(const T& key) const {
        return find_index_of(key) != N_Ways;
    }
};

template<size_t N_Ways, class T>
class FullyAssociativeLRUSet {
    std::array<T, N_Ways> table = {};
    std::array<size_t, N_Ways> lru_order = make_initialized_lru_order<N_Ways>();
public:
    T& at(size_t i) { return table.at(i); }
    const T& at(size_t i) const { return table.at(i); }
    void touch(size_t i) { update_lru_order(lru_order, i); }
    size_t find_lru_index() { return static_cast<size_t>(std::max_element(lru_order.begin(), lru_order.end()) - lru_order.begin()); }
};

template<size_t N_Sets, size_t N_Ways, class T, class U, class Hasher>
class SetAssociativeLRUTable {
    struct HasherForIndex { size_t operator()(const T& key) const { return Hasher{}(key) % N_Sets; } };
    struct HasherForTag { size_t operator()(const T& key) const { return Hasher{}(key) / N_Sets; } };
    using Entry = FullyAssociativeLRUTable<N_Ways, T, U, HasherForTag>;
    std::array<Entry, N_Sets> table = {};
public:
    const U& operator[](const T& key) const { return table.at(HasherForIndex{}(key))[key]; }
    U& operator[](const T& key) { return table.at(HasherForIndex{}(key))[key]; }
    void touch(const T& key) { table.at(HasherForIndex{}(key)).touch(key); }
    void insert(const T& key, const U& elem) { table.at(HasherForIndex{}(key)).insert(key, elem); }
    bool contains(const T& key) const { return table.at(HasherForIndex{}(key)).contains(key); }
};

class WindowBasedStreamPrefetcher {
    static constexpr size_t TrainingThreshold = 3;
    static constexpr size_t WindowSize = 2;
    static constexpr size_t Distance = 2;
    static constexpr size_t Degree = 2;
    static constexpr size_t TrainingTableSize = 16;
    static constexpr size_t MonitoringTableSize = 16;

    struct TrainingStreamEntry {
        bool valid;
        uint64_t start_line_address;
        size_t count;
    };

    struct MonitoringStreamEntry {
        bool valid;
        uint64_t start_line_address;
    };

    FullyAssociativeLRUSet<TrainingTableSize, TrainingStreamEntry> training_table = {};
    FullyAssociativeLRUSet<MonitoringTableSize, MonitoringStreamEntry> monitoring_table = {};
// ---------------------
//  train table
// ---------------------
// 16 entry fully-asociative table
// Budget:
//  line address : 58 bits X 16 entry = 928 bits
//  valid :         1 bit  X 16 entry =  16 bits
//  counter :       2 bits X 16 entry =  32 bits
//  lru bit :       4 bits X 16 entry =  64 bits
//                               Total 1040 bits

// ---------------------
//  monitor table
// ---------------------
// 16 entry fully-asociative table
// Budget:
//  line address : 58 bits X 16 entry = 928 bits
//  valid :         1 bit  X 16 entry =  16 bits
//  lru bit :       4 bits X 16 entry =  64 bits
//                               Total 1008 bits

    // Is line_address in [start_line_adress, start_line_adress + range_size)?
    static bool is_in_range(uint64_t line_address, uint64_t start_line_address, size_t range_size) noexcept {
        return start_line_address <= line_address && line_address < start_line_address + range_size;
    }

    void allocate_training_stream(uint64_t line_address) {
        const size_t lru_index = training_table.find_lru_index();
        training_table.at(lru_index) = TrainingStreamEntry { /* valid = */true, /* start_line_address = */ line_address, /* count = */0 };
        training_table.touch(lru_index);
    }

    bool update_training_stream_and_prefetch(uint64_t line_address, O3_CPU* pO3_CPU) {
        for (size_t i = 0; i < TrainingTableSize; ++i) {
            TrainingStreamEntry& stream = training_table.at(i);
            if (!stream.valid) { continue; }

            if (!is_in_range(line_address, stream.start_line_address, WindowSize)) { continue; }

            ++stream.count;

            if (stream.count >= TrainingThreshold) {
                prefetch_initial_stream(line_address, stream, pO3_CPU);
                allocate_monitoring_stream(MonitoringStreamEntry { /* valid = */ true, /* start_line_address = */ line_address }); // line_address, line_address+1, ... will be prefetched.
                stream.valid = false;
            } else {
                training_table.touch(i);
            }
            return true;
        }

        return false;
    }

    void allocate_monitoring_stream(MonitoringStreamEntry entry) {
        const size_t lru_index = monitoring_table.find_lru_index();
        monitoring_table.at(lru_index) = std::move(entry);
        monitoring_table.touch(lru_index);
    }

    bool update_monitoring_stream_and_prefetch(uint64_t line_address, O3_CPU* pO3_CPU) {
        for (size_t i = 0; i < MonitoringTableSize; ++i) {
            MonitoringStreamEntry& stream = monitoring_table.at(i);
            if (!stream.valid) { continue; }

            // Check a missed address is in a prefetch window.
            if (!is_in_range(line_address, stream.start_line_address, Distance)) { continue; }

            // Update, issue prefetch, and touch a entry
            for (size_t j = 0; j < Degree; ++j) {
                const uint64_t pf_addr = (stream.start_line_address + Distance) << LOG2_BLOCK_SIZE;

                pO3_CPU->prefetch_code_line(pf_addr);

                ++stream.start_line_address;
            }
            monitoring_table.touch(i);
            return true;
        }
        return false;
    }

    void prefetch_initial_stream(uint64_t line_address, const TrainingStreamEntry& stream, O3_CPU* pO3_CPU) {
        // i == 0 is not needed since it is the same line as the demand access.
        for (size_t i = 1; i < Distance; ++i) {
            const uint64_t pf_addr = (line_address + i) << LOG2_BLOCK_SIZE;
            pO3_CPU->prefetch_code_line(pf_addr);
        }
    }

public:
    void cache_operate(uint64_t address, uint8_t cache_hit, uint8_t prefetch_hit, O3_CPU* pO3_CPU) {
        const bool virtual_miss = cache_hit == 0 || prefetch_hit == 1;
        const uint64_t line_address = address >> LOG2_BLOCK_SIZE;

        const bool already_monitored_stream = update_monitoring_stream_and_prefetch(line_address, pO3_CPU);

        if (virtual_miss) {
            const bool already_training_stream = update_training_stream_and_prefetch(line_address, pO3_CPU);

            if (!already_monitored_stream && !already_training_stream) {
                allocate_training_stream(line_address);
            }
        }
    }
};

template<size_t N>
class SignatureQueue {
    std::array<uint32_t, N> queue = {};
    size_t head = 0;
public:
    uint32_t back() const noexcept { return queue.at((head + 1) % N); }
    void insert(uint32_t x) noexcept { queue.at((head + 1) % N) = x; head = (head + 1) % N; }
};


class D_JOLT_PREFETCHER {
    O3_CPU* pO3_CPU;
    struct SigHasher { size_t operator()(const uint32_t& x) const noexcept { return x; } };

    ShortRangePrefetcherSiggen siggen_1 = {};
    LongRangePrefetcherSiggen siggen_2 = {};

    SignatureQueue<ShortRangePrefetcherDistance> sig_history_1 = {};
    SignatureQueue<LongRangePrefetcherDistance> sig_history_2 = {};

    SetAssociativeLRUTable<ShortRangePrefetcher_N_Sets, ShortRangePrefetcher_N_Ways, uint32_t, MissTableEntry<ShortRangePrefetcher_N_Vectors, ShortRangePrefetcher_VectorSize>, SigHasher> miss_table_1 = {};
    SetAssociativeLRUTable<LongRangePrefetcher_N_Sets, LongRangePrefetcher_N_Ways, uint32_t, MissTableEntry<LongRangePrefetcher_N_Vectors, LongRangePrefetcher_VectorSize>, SigHasher> miss_table_2 = {};
    SetAssociativeLRUTable<ExtraMissTable_N_Sets, ExtraMissTable_N_Ways, uint32_t, MissTableEntry<ExtraMissTable_N_Vectors, ExtraMissTable_VectorSize>, SigHasher> extra_miss_table = {};

    WindowBasedStreamPrefetcher stream_prefetcher = {};

    UpperBitTable upper_bit_table = {};

    template<class T>
    void print_parameter(const std::string& str, T& param) {
        std::cout << str << ": " << param << std::endl;
    }

public:
    D_JOLT_PREFETCHER(O3_CPU* pO3_CPU);

    template<class Table>
    void prefetch_with_sig(const Table& table, uint32_t sig);
    template<class Table>
    void learn_with_sig(Table& table, uint32_t sig, CompressedLineAddress c_address);
    void branch_operate(uint64_t ip, uint8_t branch_type, uint64_t branch_target);
    void cache_operate(uint64_t addr, uint8_t cache_hit, uint8_t prefetch_hit);
    void cycle_operate();
    void final_stats();
    void cache_fill(uint64_t v_addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_v_addr);
};

D_JOLT_PREFETCHER::D_JOLT_PREFETCHER(O3_CPU* pO3_CPU) : pO3_CPU(pO3_CPU) {
    std::cout << "L1I D-JOLT instruction prefetcher has been constructed!" << std::endl;
}

template<class Table>
void D_JOLT_PREFETCHER::prefetch_with_sig(const Table& table, uint32_t sig) {
    if (table.contains(sig)) {
        for (const auto& v : table[sig].getValidEntries()) {
            for (const auto& address : v.getAddresses()) {
                const uint64_t pf_addr = upper_bit_table.decompress(address);
                const int success = pO3_CPU->prefetch_code_line(pf_addr);
            }
        }
    }
}

void D_JOLT_PREFETCHER::branch_operate(uint64_t ip, uint8_t branch_type, uint64_t branch_target) {
    uint32_t sig_1;
    uint32_t sig_2;

    if (branch_type == BRANCH_DIRECT_CALL || branch_type == BRANCH_INDIRECT_CALL) {
        sig_1 = siggen_1.onCallInstruction(ip, branch_target);
        sig_2 = siggen_2.onCallInstruction(ip, branch_target);
    } else if (branch_type == BRANCH_RETURN) {
        sig_1 = siggen_1.onReturnInstruction(ip, branch_target);
        sig_2 = siggen_2.onReturnInstruction(ip, branch_target);
    } else {
        return;
    }

    // Make sure storage limits are adhered to...
    assert(sig_1 < (1ull<<ExtraMissTable_TagBits) * ExtraMissTable_N_Sets);
    assert(sig_2 < (1ull<<ExtraMissTable_TagBits) * ExtraMissTable_N_Sets);
    assert(sig_1 < (1ull<<ShortRangePrefetcher_TagBits) * ShortRangePrefetcher_N_Sets);
    assert(sig_2 < (1ull<<LongRangePrefetcher_TagBits) * LongRangePrefetcher_N_Sets);

    sig_history_1.insert(sig_1);
    sig_history_2.insert(sig_2);

    prefetch_with_sig(miss_table_1, sig_1);
    prefetch_with_sig(extra_miss_table, sig_1);
    prefetch_with_sig(miss_table_2, sig_2);
    prefetch_with_sig(extra_miss_table, sig_2);
}

template<class Table>
void D_JOLT_PREFETCHER::learn_with_sig(Table& table, uint32_t sig, CompressedLineAddress c_address) {
    if (!table.contains(sig)) {
        table.insert(sig, {});
    } else {
        table.touch(sig);
    }
    const bool success = table[sig].insert_but_do_not_evict(c_address);
    if (!success) {
        if (!extra_miss_table.contains(sig)) {
            extra_miss_table.insert(sig, {});
        } else {
            extra_miss_table.touch(sig);
        }
        extra_miss_table[sig].insert_but_do_not_evict(c_address);
    } else if (extra_miss_table.contains(sig)) {
        extra_miss_table.touch(sig);
    }
}

void D_JOLT_PREFETCHER::cache_operate(uint64_t addr, uint8_t cache_hit, uint8_t prefetch_hit) {
    const bool miss = cache_hit == 0;
    const bool virtual_miss = cache_hit == 0 || prefetch_hit == 1;
    stream_prefetcher.cache_operate(addr, cache_hit, prefetch_hit, pO3_CPU);

    if (miss) {
        const auto compress_result = upper_bit_table.compress(addr);
        const bool compress_success = compress_result.first;
        const CompressedLineAddress c_address = compress_result.second;

        if (!compress_success) { return; }

        learn_with_sig(miss_table_1, sig_history_1.back(), c_address);
        learn_with_sig(miss_table_2, sig_history_2.back(), c_address);
    }
}

void D_JOLT_PREFETCHER::cycle_operate()
{
}

void D_JOLT_PREFETCHER::final_stats()
{
}

void D_JOLT_PREFETCHER::cache_fill(uint64_t v_addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_v_addr)
{
}

std::array<std::unique_ptr<D_JOLT_PREFETCHER>, NUM_CPUS> l1i_prefetcher;

} // namespace anonymous


// ========================================================================================================================
// ========================================================================================================================
// ==================================================== D-JOLT END.========================================================
// ========================================================================================================================
// ========================================================================================================================








// ========================================================================================================================
// ========================================================================================================================
// ==================================================== EIP Start.=========================================================
// ========================================================================================================================
// ========================================================================================================================

#define L1I_PQ_SIZE 32 // fixed
#define L1I_MSHR_SIZE 8 // fixed
#define L1I_SET 64 // fixed
#define L1I_WAY 8 // fixed
uint32_t cpu = 0;
O3_CPU* my_pO3_CPU;
extern std::array<CACHE*, NUM_CACHES> caches;

////////////////////////////////////////////////////////////////////////
//
//  Code submitted for the First Instruction Prefetching Championship
//
//  Authors: Alberto Ros (aros@ditec.um.es)
//           Alexandra Jimborean (alexandra.jimborean@um.es)
//
//  Paper #30: The Entangling Instruction Prefetcher
//
////////////////////////////////////////////////////////////////////////

#include "ooo_cpu.h"

// To access cpu in my functions
uint32_t l1i_cpu_id;

uint64_t l1i_last_basic_block;
uint32_t l1i_consecutive_count;
uint32_t l1i_basic_block_merge_diff;


// LINE AND MERGE BASIC BLOCK SIZE

#define L1I_MERGE_BBSIZE_BITS 7
#define L1I_MERGE_BBSIZE_MAX_VALUE ((1 << L1I_MERGE_BBSIZE_BITS) - 1)

// TIME AND OVERFLOWS

#define L1I_TIME_DIFF_BITS 20
#define L1I_TIME_DIFF_OVERFLOW ((uint64_t)1 << L1I_TIME_DIFF_BITS)
#define L1I_TIME_DIFF_MASK (L1I_TIME_DIFF_OVERFLOW - 1)

#define L1I_TIME_BITS 12
#define L1I_TIME_OVERFLOW ((uint64_t)1 << L1I_TIME_BITS)
#define L1I_TIME_MASK (L1I_TIME_OVERFLOW - 1)

uint64_t l1i_get_latency(uint64_t cycle, uint64_t cycle_prev) {
    uint64_t cycle_masked = cycle & L1I_TIME_MASK;
    uint64_t cycle_prev_masked = cycle_prev & L1I_TIME_MASK;
    if (cycle_prev_masked > cycle_masked) {
        return (cycle_masked + L1I_TIME_OVERFLOW) - cycle_prev_masked;
    }
    return cycle_masked - cycle_prev_masked;
}

// ENTANGLED COMPRESSION FORMAT

#define L1I_ENTANGLED_MAX_FORMATS 7

// HISTORY TABLE

#define L1I_HIST_TABLE_ENTRIES 1072
#define L1I_HIST_TABLE_MASK (L1I_HIST_TABLE_ENTRIES - 1)
#define L1I_BB_MERGE_ENTRIES 4
#define L1I_HIST_TAG_BITS 58
#define L1I_HIST_TAG_MASK (((uint64_t)1 << L1I_HIST_TAG_BITS) - 1)

typedef struct __l1i_hist_entry {
    uint64_t tag; // L1I_HIST_TAG_BITS bits
    uint64_t time_diff; // L1I_TIME_DIFF_BITS bits
    uint32_t bb_size; // L1I_MERGE_BBSIZE_BITS bits
} l1i_hist_entry;

l1i_hist_entry l1i_hist_table[NUM_CPUS][L1I_HIST_TABLE_ENTRIES];
uint64_t l1i_hist_table_head[NUM_CPUS]; // log_2 (L1I_HIST_TABLE_ENTRIES)
uint64_t l1i_hist_table_head_time[NUM_CPUS]; // 64 bits

void l1i_init_hist_table() {
    l1i_hist_table_head[l1i_cpu_id] = 0;
    l1i_hist_table_head_time[l1i_cpu_id] = current_core_cycle[l1i_cpu_id];
    for (uint32_t i = 0; i < L1I_HIST_TABLE_ENTRIES; i++) {
        l1i_hist_table[l1i_cpu_id][i].tag = 0;
        l1i_hist_table[l1i_cpu_id][i].time_diff = 0;
        l1i_hist_table[l1i_cpu_id][i].bb_size = 0;
    }
}

uint64_t l1i_find_hist_entry(uint64_t line_addr) {
    uint64_t tag = line_addr & L1I_HIST_TAG_MASK; 
    for (uint32_t count = 0, i = (l1i_hist_table_head[l1i_cpu_id] + L1I_HIST_TABLE_MASK) % L1I_HIST_TABLE_ENTRIES; count < L1I_HIST_TABLE_ENTRIES; count++, i = (i + L1I_HIST_TABLE_MASK) % L1I_HIST_TABLE_ENTRIES) {
        if (l1i_hist_table[l1i_cpu_id][i].tag == tag) return i;
    }
    return L1I_HIST_TABLE_ENTRIES;
}

// It can have duplicated entries if the line was evicted in between
void l1i_add_hist_table(uint64_t line_addr) {
    // Insert empty addresses in hist not to have timediff overflows
    while(current_core_cycle[l1i_cpu_id] - l1i_hist_table_head_time[l1i_cpu_id] >= L1I_TIME_DIFF_OVERFLOW) {
        l1i_hist_table[l1i_cpu_id][l1i_hist_table_head[l1i_cpu_id]].tag = 0;
        l1i_hist_table[l1i_cpu_id][l1i_hist_table_head[l1i_cpu_id]].time_diff = L1I_TIME_DIFF_MASK;
        l1i_hist_table[l1i_cpu_id][l1i_hist_table_head[l1i_cpu_id]].bb_size = 0;
        l1i_hist_table_head[l1i_cpu_id] = (l1i_hist_table_head[l1i_cpu_id] + 1) % L1I_HIST_TABLE_ENTRIES;
        l1i_hist_table_head_time[l1i_cpu_id] += L1I_TIME_DIFF_MASK;
    }

    // Allocate a new entry (evict old one if necessary)
    l1i_hist_table[l1i_cpu_id][l1i_hist_table_head[l1i_cpu_id]].tag = line_addr & L1I_HIST_TAG_MASK;
    l1i_hist_table[l1i_cpu_id][l1i_hist_table_head[l1i_cpu_id]].time_diff = (current_core_cycle[l1i_cpu_id] - l1i_hist_table_head_time[l1i_cpu_id]) & L1I_TIME_DIFF_MASK;
    l1i_hist_table[l1i_cpu_id][l1i_hist_table_head[l1i_cpu_id]].bb_size = 0;
    l1i_hist_table_head[l1i_cpu_id] = (l1i_hist_table_head[l1i_cpu_id] + 1) % L1I_HIST_TABLE_ENTRIES;
    l1i_hist_table_head_time[l1i_cpu_id] = current_core_cycle[l1i_cpu_id];
}

void l1i_add_bb_size_hist_table(uint64_t line_addr, uint32_t bb_size) {
    uint64_t index = l1i_find_hist_entry(line_addr);
    l1i_hist_table[l1i_cpu_id][index].bb_size = bb_size & L1I_MERGE_BBSIZE_MAX_VALUE;
}

uint32_t l1i_find_bb_merge_hist_table(uint64_t line_addr) {
    uint64_t tag = line_addr & L1I_HIST_TAG_MASK; 
    for (uint32_t count = 0, i = (l1i_hist_table_head[l1i_cpu_id] + L1I_HIST_TABLE_MASK) % L1I_HIST_TABLE_ENTRIES; count < L1I_HIST_TABLE_ENTRIES; count++, i = (i + L1I_HIST_TABLE_MASK) % L1I_HIST_TABLE_ENTRIES) {
        if (count >= L1I_BB_MERGE_ENTRIES) {
            return 0;
        }
        if (tag > l1i_hist_table[l1i_cpu_id][i].tag && (tag - l1i_hist_table[l1i_cpu_id][i].tag) <= l1i_hist_table[l1i_cpu_id][i].bb_size) {
            return tag - l1i_hist_table[l1i_cpu_id][i].tag;
        }
    }
    assert(false);
}

// return bere (best request -- entangled address)
uint64_t l1i_get_bere_hist_table(uint64_t line_addr, uint64_t latency, uint32_t skip = 0) {
    uint64_t tag = line_addr & L1I_HIST_TAG_MASK; 
    assert(tag);
    uint32_t first = (l1i_hist_table_head[l1i_cpu_id] + L1I_HIST_TABLE_MASK) % L1I_HIST_TABLE_ENTRIES;
    uint64_t time_i = l1i_hist_table_head_time[l1i_cpu_id];
    uint64_t req_time = 0;
    uint32_t num_skipped = 0;
    for (uint32_t count = 0, i = first; count < L1I_HIST_TABLE_ENTRIES; count++, i = (i + L1I_HIST_TABLE_MASK) % L1I_HIST_TABLE_ENTRIES) {
        // Against the time overflow
        if (req_time == 0 && l1i_hist_table[l1i_cpu_id][i].tag == tag && time_i + latency >= current_core_cycle[l1i_cpu_id]) { // Its me (miss or late prefetcher)
          req_time = time_i;
        } else if (req_time) { // Not me (check only older than me)
            if (l1i_hist_table[l1i_cpu_id][i].tag == tag) {
                return 0; // Second time it appeared (it was evicted in between) or many for the same set. No entangle
            }
            if (time_i + latency <= req_time && l1i_hist_table[l1i_cpu_id][i].tag) {
                if (skip == num_skipped) {
                    return l1i_hist_table[l1i_cpu_id][i].tag;
                } else {
                    num_skipped++;
                }
            }
        }
        time_i -= l1i_hist_table[l1i_cpu_id][i].time_diff;  
    }
    return 0;
}

// TIMING TABLES

#define L1I_SET_BITS 6
#define L1I_TIMING_MSHR_SIZE (L1I_PQ_SIZE+L1I_MSHR_SIZE+2)
#define L1I_TIMING_MSHR_TAG_BITS 42
#define L1I_TIMING_MSHR_TAG_MASK (((uint64_t)1 << L1I_HIST_TAG_BITS) - 1)
#define L1I_TIMING_CACHE_TAG_BITS (L1I_TIMING_MSHR_TAG_BITS - L1I_SET_BITS)
#define L1I_TIMING_CACHE_TAG_MASK (((uint64_t)1 << L1I_HIST_TAG_BITS) - 1)

// We do not have access to the MSHR, so we aproximate it using this structure
typedef struct __l1i_timing_mshr_entry {
    bool valid; // 1 bit
    uint64_t tag; // L1I_TIMING_MSHR_TAG_BITS bits
    uint64_t bere_line_addr; // 58 bits
    uint64_t timestamp; // L1I_TIME_BITS bits // time when issued
    bool accessed; // 1 bit
} l1i_timing_mshr_entry;

// We do not have access to the cache, so we aproximate it using this structure
typedef struct __l1i_timing_cache_entry {
    bool valid; // 1 bit
    uint64_t tag; // L1I_TIMING_CACHE_TAG_BITS bits
    uint64_t bere_line_addr; // 58 bits
    bool accessed; // 1 bit
} l1i_timing_cache_entry;

l1i_timing_mshr_entry l1i_timing_mshr_table[NUM_CPUS][L1I_TIMING_MSHR_SIZE];
l1i_timing_cache_entry l1i_timing_cache_table[NUM_CPUS][L1I_SET][L1I_WAY];

void l1i_init_timing_tables() {
    for (uint32_t i = 0; i < L1I_TIMING_MSHR_SIZE; i++) {
        l1i_timing_mshr_table[l1i_cpu_id][i].valid = 0;
    }
    for (uint32_t i = 0; i < L1I_SET; i++) {
        for (uint32_t j = 0; j < L1I_WAY; j++) {
            l1i_timing_cache_table[l1i_cpu_id][i][j].valid = 0;
        }
    }
}

uint64_t l1i_find_timing_mshr_entry(uint64_t line_addr) {
    for (uint32_t i = 0; i < L1I_TIMING_MSHR_SIZE; i++) {
        if (l1i_timing_mshr_table[l1i_cpu_id][i].tag == (line_addr & L1I_TIMING_MSHR_TAG_MASK) && l1i_timing_mshr_table[l1i_cpu_id][i].valid)
            return i;
    }
    return L1I_TIMING_MSHR_SIZE;
}

uint64_t l1i_find_timing_cache_entry(uint64_t line_addr) {
    uint64_t i = line_addr % L1I_SET;
    for (uint32_t j = 0; j < L1I_WAY; j++) {
        if (l1i_timing_cache_table[l1i_cpu_id][i][j].tag == ((line_addr >> L1I_SET_BITS) & L1I_TIMING_CACHE_TAG_MASK) && l1i_timing_cache_table[l1i_cpu_id][i][j].valid)
            return j;
    }
    return L1I_WAY;
}

uint32_t l1i_get_invalid_timing_mshr_entry() {
    for (uint32_t i = 0; i < L1I_TIMING_MSHR_SIZE; i++) {
        if (!l1i_timing_mshr_table[l1i_cpu_id][i].valid)
            return i;
    }
    assert(false); // It must return a free entry
    return L1I_TIMING_MSHR_SIZE;  
}

uint32_t l1i_get_invalid_timing_cache_entry(uint64_t line_addr) {
    uint32_t i = line_addr % L1I_SET;
    for (uint32_t j = 0; j < L1I_WAY; j++) {
        if (!l1i_timing_cache_table[l1i_cpu_id][i][j].valid) 
            return j;
    }
    assert(false); // It must return a free entry
    return L1I_WAY;  
}

void l1i_add_timing_entry(uint64_t line_addr, uint64_t bere_line_addr) {
    // First find for coalescing
    if (l1i_find_timing_mshr_entry(line_addr) < L1I_TIMING_MSHR_SIZE) return;
    if (l1i_find_timing_cache_entry(line_addr) < L1I_WAY) return;

    uint32_t i = l1i_get_invalid_timing_mshr_entry();
    l1i_timing_mshr_table[l1i_cpu_id][i].valid = true;
    l1i_timing_mshr_table[l1i_cpu_id][i].tag = line_addr & L1I_TIMING_MSHR_TAG_MASK;
    l1i_timing_mshr_table[l1i_cpu_id][i].bere_line_addr = bere_line_addr;
    l1i_timing_mshr_table[l1i_cpu_id][i].timestamp = current_core_cycle[l1i_cpu_id] & L1I_TIME_MASK;
    l1i_timing_mshr_table[l1i_cpu_id][i].accessed = false;
}

void l1i_invalid_timing_mshr_entry(uint64_t line_addr) {
    uint32_t index = l1i_find_timing_mshr_entry(line_addr);
    assert(index < L1I_TIMING_MSHR_SIZE);
    l1i_timing_mshr_table[l1i_cpu_id][index].valid = false;
}

void l1i_move_timing_entry(uint64_t line_addr) {
    uint32_t index_mshr = l1i_find_timing_mshr_entry(line_addr); 
    if (index_mshr == L1I_TIMING_MSHR_SIZE) {
        uint32_t set = line_addr % L1I_SET;
        uint32_t index_cache = l1i_get_invalid_timing_cache_entry(line_addr);
        l1i_timing_cache_table[l1i_cpu_id][set][index_cache].valid = true;
        l1i_timing_cache_table[l1i_cpu_id][set][index_cache].tag = (line_addr >> L1I_SET_BITS) & L1I_TIMING_CACHE_TAG_MASK;
        l1i_timing_cache_table[l1i_cpu_id][set][index_cache].accessed = true;
        return;
    }
    uint64_t set = line_addr % L1I_SET;
    uint64_t index_cache = l1i_get_invalid_timing_cache_entry(line_addr);
    l1i_timing_cache_table[l1i_cpu_id][set][index_cache].valid = true;
    l1i_timing_cache_table[l1i_cpu_id][set][index_cache].tag = (line_addr >> L1I_SET_BITS) & L1I_TIMING_CACHE_TAG_MASK;
    l1i_timing_cache_table[l1i_cpu_id][set][index_cache].bere_line_addr = l1i_timing_mshr_table[l1i_cpu_id][index_mshr].bere_line_addr;
    l1i_timing_cache_table[l1i_cpu_id][set][index_cache].accessed = l1i_timing_mshr_table[l1i_cpu_id][index_mshr].accessed;
    l1i_invalid_timing_mshr_entry(line_addr);
}

// returns if accessed
bool l1i_invalid_timing_cache_entry(uint64_t line_addr, uint64_t &bere_line_addr) {
    uint32_t set = line_addr % L1I_SET;
    uint32_t way = l1i_find_timing_cache_entry(line_addr);
    assert(way < L1I_WAY);
    l1i_timing_cache_table[l1i_cpu_id][set][way].valid = false;
    bere_line_addr = l1i_timing_cache_table[l1i_cpu_id][set][way].bere_line_addr;
    return l1i_timing_cache_table[l1i_cpu_id][set][way].accessed;
}

void l1i_access_timing_entry(uint64_t line_addr) {
    uint32_t index = l1i_find_timing_mshr_entry(line_addr);
    if (index < L1I_TIMING_MSHR_SIZE) {
        if (!l1i_timing_mshr_table[l1i_cpu_id][index].accessed) {
            l1i_timing_mshr_table[l1i_cpu_id][index].accessed = true;
        }
        return;
    }
    uint32_t set = line_addr % L1I_SET;
    uint32_t way = l1i_find_timing_cache_entry(line_addr);
    if (way < L1I_WAY) {
        l1i_timing_cache_table[l1i_cpu_id][set][way].accessed = true;
    }
}

bool l1i_is_accessed_timing_entry(uint64_t line_addr) {
    uint32_t index = l1i_find_timing_mshr_entry(line_addr);
    if (index < L1I_TIMING_MSHR_SIZE) {
        return l1i_timing_mshr_table[l1i_cpu_id][index].accessed;
    }
    uint32_t set = line_addr % L1I_SET;
    uint32_t way = l1i_find_timing_cache_entry(line_addr);
    if (way < L1I_WAY) {
        return l1i_timing_cache_table[l1i_cpu_id][set][way].accessed;
    }
    return false;
}

bool l1i_completed_request(uint64_t line_addr) {
    return l1i_find_timing_cache_entry(line_addr) < L1I_WAY;
}

bool l1i_ongoing_request(uint64_t line_addr) {
    return l1i_find_timing_mshr_entry(line_addr) < L1I_TIMING_MSHR_SIZE;
}

bool l1i_ongoing_accessed_request(uint64_t line_addr) {
    uint32_t index = l1i_find_timing_mshr_entry(line_addr);
    if (index == L1I_TIMING_MSHR_SIZE) return false;
    return l1i_timing_mshr_table[l1i_cpu_id][index].accessed;
}

uint64_t l1i_get_latency_timing_mshr(uint64_t line_addr) {
    uint32_t index = l1i_find_timing_mshr_entry(line_addr);
    if (index == L1I_TIMING_MSHR_SIZE)
        return 0;
    if (!l1i_timing_mshr_table[l1i_cpu_id][index].accessed)
        return 0;
    return l1i_get_latency(current_core_cycle[l1i_cpu_id], l1i_timing_mshr_table[l1i_cpu_id][index].timestamp);
}

// RECORD ENTANGLED TABLE

uint32_t L1I_ENTANGLED_FORMATS[L1I_ENTANGLED_MAX_FORMATS] = {58, 28, 18, 13, 10, 8, 6};
#define L1I_ENTANGLED_NUM_FORMATS 6

uint32_t l1i_get_format_entangled(uint64_t line_addr, uint64_t entangled_addr) {
    for (uint32_t i = L1I_ENTANGLED_NUM_FORMATS; i != 0; i--) {
        if ((line_addr >> L1I_ENTANGLED_FORMATS[i-1]) == (entangled_addr >> L1I_ENTANGLED_FORMATS[i-1])) {
            return i;
        }
    }
    assert(false);
}

uint64_t l1i_extend_format_entangled(uint64_t line_addr, uint64_t entangled_addr, uint32_t format) {
    return ((line_addr >> L1I_ENTANGLED_FORMATS[format-1]) << L1I_ENTANGLED_FORMATS[format-1]) | (entangled_addr & (((uint64_t)1 << L1I_ENTANGLED_FORMATS[format-1]) - 1));
}

uint64_t l1i_compress_format_entangled(uint64_t entangled_addr, uint32_t format) {
    return entangled_addr & (((uint64_t)1 << L1I_ENTANGLED_FORMATS[format-1]) - 1);
}

#define L1I_ENTANGLED_TABLE_INDEX_BITS 8
#define L1I_ENTANGLED_TABLE_SETS (1 << L1I_ENTANGLED_TABLE_INDEX_BITS)
#define L1I_ENTANGLED_TABLE_WAYS 34
#define L1I_MAX_ENTANGLED_PER_LINE L1I_ENTANGLED_NUM_FORMATS
#define L1I_TAG_BITS (42 - L1I_ENTANGLED_TABLE_INDEX_BITS)
#define L1I_TAG_MASK (((uint64_t)1 << L1I_TAG_BITS) - 1)
#define L1I_CONFIDENCE_COUNTER_BITS 2
#define L1I_CONFIDENCE_COUNTER_MAX_VALUE ((1 << L1I_CONFIDENCE_COUNTER_BITS) - 1)
#define L1I_CONFIDENCE_COUNTER_THRESHOLD 1

#define L1I_TRIES_AVAIL_ENTANGLED 6
#define L1I_TRIES_AVAIL_ENTANGLED_NOT_PRESENT 2

typedef struct __l1i_entangled_entry {
    uint64_t tag; // L1I_TAG_BITS bits
    uint32_t format; // 3 bits
    uint64_t entangled_addr[L1I_MAX_ENTANGLED_PER_LINE]; // keep just diff
    uint32_t entangled_conf[L1I_MAX_ENTANGLED_PER_LINE]; // L1I_CONFIDENCE_COUNTER_BITS bits
    uint32_t bb_size; // L1I_MERGE_BBSIZE_BITS bits
} l1i_entangled_entry;

l1i_entangled_entry l1i_entangled_table[NUM_CPUS][L1I_ENTANGLED_TABLE_SETS][L1I_ENTANGLED_TABLE_WAYS];
uint32_t l1i_entangled_fifo[NUM_CPUS][L1I_ENTANGLED_TABLE_SETS]; // log2(L1I_ENTANGLED_TABLE_WAYS) * L1I_ENTANGLED_TABLE_SETS bits

void l1i_init_entangled_table() {
    for (uint32_t i = 0; i < L1I_ENTANGLED_TABLE_SETS; i++) {
        for (uint32_t j = 0; j < L1I_ENTANGLED_TABLE_WAYS; j++) {
            l1i_entangled_table[l1i_cpu_id][i][j].tag = 0;
            l1i_entangled_table[l1i_cpu_id][i][j].format = 1;
            for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
                l1i_entangled_table[l1i_cpu_id][i][j].entangled_addr[k] = 0;
                l1i_entangled_table[l1i_cpu_id][i][j].entangled_conf[k] = 0;
            }
            l1i_entangled_table[l1i_cpu_id][i][j].bb_size = 0;
        }
        l1i_entangled_fifo[l1i_cpu_id][i] = 0;
    }
}

uint32_t l1i_get_way_entangled_table(uint64_t line_addr) {
    uint64_t tag = (line_addr >> L1I_ENTANGLED_TABLE_INDEX_BITS) & L1I_TAG_MASK; 
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    for (int i = 0; i < L1I_ENTANGLED_TABLE_WAYS; i++) {
        if (l1i_entangled_table[l1i_cpu_id][set][i].tag == tag) { // Found
            return i;
        }
    }
    return L1I_ENTANGLED_TABLE_WAYS;
}

void l1i_add_entangled_table(uint64_t line_addr, uint64_t entangled_addr) {
    uint64_t tag = (line_addr >> L1I_ENTANGLED_TABLE_INDEX_BITS) & L1I_TAG_MASK; 
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    uint32_t way = l1i_get_way_entangled_table(line_addr);
    if (way == L1I_ENTANGLED_TABLE_WAYS) {
        way = l1i_entangled_fifo[l1i_cpu_id][set];
        l1i_entangled_table[l1i_cpu_id][set][way].tag = tag;
        l1i_entangled_table[l1i_cpu_id][set][way].format = 1;
        for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k] = 0;
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] = 0;
        }
        l1i_entangled_table[l1i_cpu_id][set][way].bb_size = 0;
        l1i_entangled_fifo[l1i_cpu_id][set] = (l1i_entangled_fifo[l1i_cpu_id][set] + 1) % L1I_ENTANGLED_TABLE_WAYS;
    }
    for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
        if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD && l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k], l1i_entangled_table[l1i_cpu_id][set][way].format) == entangled_addr) {
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] = L1I_CONFIDENCE_COUNTER_MAX_VALUE;
            return;
        }
    }

    // Adding a new entangled
    uint32_t format_new = l1i_get_format_entangled(line_addr, entangled_addr);

    // Check for evictions
    while(true) {
        uint32_t min_format = format_new;
        uint32_t num_valid = 1;
        uint32_t min_value = L1I_CONFIDENCE_COUNTER_MAX_VALUE + 1;
        uint32_t min_pos = 0;
        for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
            if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD) {
                num_valid++;
                uint32_t format_k = l1i_get_format_entangled(line_addr, l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k], l1i_entangled_table[l1i_cpu_id][set][way].format));
                if (format_k < min_format) {
                    min_format = format_k;
                }
                if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] < min_value) {
                    min_value = l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k];
                    min_pos = k;
                }
            }
        }
        if (num_valid > min_format) { // Eviction is necessary. We chose the lower confidence one 
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[min_pos] = 0;
        } else {
            // Reformat
            for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
                if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD) {
                    l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k] = l1i_compress_format_entangled(l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k], l1i_entangled_table[l1i_cpu_id][set][way].format), min_format);
                }
            }
            l1i_entangled_table[l1i_cpu_id][set][way].format = min_format;
            break;
        }
    }
    for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
        if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] < L1I_CONFIDENCE_COUNTER_THRESHOLD) {
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k] = l1i_compress_format_entangled(entangled_addr, l1i_entangled_table[l1i_cpu_id][set][way].format);
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] = L1I_CONFIDENCE_COUNTER_MAX_VALUE;
            return;
        }
    }
}

bool l1i_avail_entangled_table(uint64_t line_addr, uint64_t entangled_addr, bool insert_not_present) {
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    uint32_t way = l1i_get_way_entangled_table(line_addr);
    if (way == L1I_ENTANGLED_TABLE_WAYS) return insert_not_present;
    for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
        if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD && l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k], l1i_entangled_table[l1i_cpu_id][set][way].format) == entangled_addr) {
            return true;
        }
    }
    // Check for availability
    uint32_t min_format = l1i_get_format_entangled(line_addr, entangled_addr);
    uint32_t num_valid = 1;
    for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
        if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD) {
            num_valid++;
            uint32_t format_k = l1i_get_format_entangled(line_addr, l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k], l1i_entangled_table[l1i_cpu_id][set][way].format));
            if (format_k < min_format) {
                min_format = format_k;
            }
        }
    }
    if (num_valid > min_format) { // Eviction is necessary
        return false;
    } else {
        return true;
    }
}

void l1i_add_bbsize_table(uint64_t line_addr, uint32_t bb_size) {
    uint64_t tag = (line_addr >> L1I_ENTANGLED_TABLE_INDEX_BITS) & L1I_TAG_MASK; 
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    uint32_t way = l1i_get_way_entangled_table(line_addr);
    if (way == L1I_ENTANGLED_TABLE_WAYS) {
        way = l1i_entangled_fifo[l1i_cpu_id][set];
        l1i_entangled_table[l1i_cpu_id][set][way].tag = tag;
        l1i_entangled_table[l1i_cpu_id][set][way].format = 1;
        for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k] = 0;
            l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] = 0;
        }
        l1i_entangled_table[l1i_cpu_id][set][way].bb_size = 0;
        l1i_entangled_fifo[l1i_cpu_id][set] = (l1i_entangled_fifo[l1i_cpu_id][set] + 1) % L1I_ENTANGLED_TABLE_WAYS;
    }
    if (bb_size > l1i_entangled_table[l1i_cpu_id][set][way].bb_size) {
        l1i_entangled_table[l1i_cpu_id][set][way].bb_size = bb_size & L1I_MERGE_BBSIZE_MAX_VALUE;
    }
}

uint64_t l1i_get_entangled_addr_entangled_table(uint64_t line_addr, uint32_t index_k) {
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    uint32_t way = l1i_get_way_entangled_table(line_addr);
    if (way < L1I_ENTANGLED_TABLE_WAYS) {
        if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[index_k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD) {
            return l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[index_k], l1i_entangled_table[l1i_cpu_id][set][way].format);
        }
    }
    return 0;
}

uint32_t l1i_get_bbsize_entangled_table(uint64_t line_addr) {
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    uint32_t way = l1i_get_way_entangled_table(line_addr);
    if (way < L1I_ENTANGLED_TABLE_WAYS) {
        return l1i_entangled_table[l1i_cpu_id][set][way].bb_size;
    }
    return 0;
}

void l1i_update_confidence_entangled_table(uint64_t line_addr, uint64_t entangled_addr, bool accessed) {
    uint32_t set = line_addr % L1I_ENTANGLED_TABLE_SETS;
    uint32_t way = l1i_get_way_entangled_table(line_addr);
    if (way < L1I_ENTANGLED_TABLE_WAYS) {
        for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
            if (l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] >= L1I_CONFIDENCE_COUNTER_THRESHOLD && l1i_extend_format_entangled(line_addr, l1i_entangled_table[l1i_cpu_id][set][way].entangled_addr[k], l1i_entangled_table[l1i_cpu_id][set][way].format) == entangled_addr) {
                if (accessed && l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] < L1I_CONFIDENCE_COUNTER_MAX_VALUE) {
                    l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k]++;
                }
                if (!accessed && l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k] > 0) {
                    l1i_entangled_table[l1i_cpu_id][set][way].entangled_conf[k]--;
                }
            }
        }
    }
}

// EXTRA PREFETCH QUEUE

#define L1I_XPQ_ENTRIES 32
#define L1I_XPQ_MASK (L1I_XPQ_ENTRIES - 1)

typedef struct __l1i_xpq_entry {
uint64_t line_addr; // 58 bits
uint64_t entangled_addr; // 58 bits
uint32_t bb_size; // L1I_MERGE_BBSIZE_BITS bits
} l1i_xpq_entry;

l1i_xpq_entry l1i_xpq[NUM_CPUS][L1I_XPQ_ENTRIES];
uint64_t l1i_xpq_head[NUM_CPUS]; // log_2 (L1I_XPQ_ENTRIES)

void l1i_init_xpq() {
    l1i_xpq_head[l1i_cpu_id] = 0;
    for (uint32_t i = 0; i < L1I_XPQ_ENTRIES; i++) {
        l1i_xpq[l1i_cpu_id][i].line_addr = 0;
        l1i_xpq[l1i_cpu_id][i].entangled_addr = 0;
        l1i_xpq[l1i_cpu_id][i].bb_size = 0;
    }
}

void l1i_add_xpq(uint64_t line_addr, uint64_t entangled_addr, uint32_t bb_size) {
    assert(bb_size > 0);

// Merge if possible
    uint32_t first = (l1i_xpq_head[l1i_cpu_id] + L1I_XPQ_MASK) % L1I_XPQ_ENTRIES;
    for (uint32_t count = 0, i = first; count < L1I_XPQ_ENTRIES; count++, i = (i + L1I_XPQ_MASK) % L1I_XPQ_ENTRIES) {
        if (l1i_xpq[l1i_cpu_id][l1i_xpq_head[l1i_cpu_id]].bb_size && line_addr == l1i_xpq[l1i_cpu_id][i].line_addr) {
            if (l1i_xpq[l1i_cpu_id][l1i_xpq_head[l1i_cpu_id]].bb_size < bb_size) {
                l1i_xpq[l1i_cpu_id][l1i_xpq_head[l1i_cpu_id]].bb_size = bb_size;
                return;
            }
        }
    }

    l1i_xpq[l1i_cpu_id][l1i_xpq_head[l1i_cpu_id]].line_addr = line_addr;
    l1i_xpq[l1i_cpu_id][l1i_xpq_head[l1i_cpu_id]].entangled_addr = entangled_addr;
    l1i_xpq[l1i_cpu_id][l1i_xpq_head[l1i_cpu_id]].bb_size = bb_size;
    l1i_xpq_head[l1i_cpu_id] = (l1i_xpq_head[l1i_cpu_id] + 1) % L1I_XPQ_ENTRIES;
}

bool l1i_empty_xpq() {
    return l1i_xpq[l1i_cpu_id][(l1i_xpq_head[l1i_cpu_id] + L1I_XPQ_MASK) % L1I_XPQ_ENTRIES].bb_size == 0;
}

// Returns next line to prefetch
uint64_t l1i_get_xpq(uint64_t &entangled_addr) {
    assert(!l1i_empty_xpq());

    // find tail
    uint32_t tail;
    for (tail = l1i_xpq_head[l1i_cpu_id]; tail != (l1i_xpq_head[l1i_cpu_id] + L1I_XPQ_MASK) % L1I_XPQ_ENTRIES; tail = (tail + 1) % L1I_XPQ_ENTRIES) {
        if (l1i_xpq[l1i_cpu_id][tail].bb_size) {
            break;
        }
    }

    // get address to prefetch
    uint64_t pf_addr = l1i_xpq[l1i_cpu_id][tail].line_addr;
    entangled_addr = l1i_xpq[l1i_cpu_id][tail].entangled_addr;

    // update queue
    l1i_xpq[l1i_cpu_id][tail].bb_size--;
    if (l1i_xpq[l1i_cpu_id][tail].bb_size == 0) {
        return pf_addr;
    }
    l1i_xpq[l1i_cpu_id][tail].line_addr++;
    l1i_xpq[l1i_cpu_id][tail].entangled_addr = 0;
    return pf_addr;
}



// INTERFACE

void eip_l1i_prefetcher_initialize() 
{
    cout << "CPU " << my_pO3_CPU->cpu << " EPI prefetcher" << endl;

    l1i_cpu_id = cpu;
    l1i_last_basic_block = 0;
    l1i_consecutive_count = 0;
    l1i_basic_block_merge_diff = 0;

    l1i_init_hist_table();
    l1i_init_timing_tables();
    l1i_init_entangled_table();
    l1i_init_xpq();
}

void eip_l1i_prefetcher_branch_operate(uint64_t ip, uint8_t branch_type, uint64_t branch_target)
{
}

void eip_l1i_prefetcher_cache_operate(uint64_t v_addr, uint8_t cache_hit, uint8_t prefetch_hit)
{
    l1i_cpu_id = my_pO3_CPU->cpu;
    uint64_t line_addr = v_addr >> LOG2_BLOCK_SIZE;

    bool consecutive = false; 
    if (l1i_last_basic_block + l1i_consecutive_count == line_addr) { // Same
        return;
    } else if (l1i_last_basic_block + l1i_consecutive_count + 1 == line_addr) { // Consecutive
        l1i_consecutive_count++;
        consecutive = true;
    }

    // Queue basic block prefetches
    uint32_t bb_size = l1i_get_bbsize_entangled_table(line_addr);
    if (bb_size > 0) {
        l1i_add_xpq(line_addr + 1, 0, bb_size);
    }
    
    // Queue entangled and basic block of entangled prefetches
    for (uint32_t k = 0; k < L1I_MAX_ENTANGLED_PER_LINE; k++) {
        uint64_t entangled_addr = l1i_get_entangled_addr_entangled_table(line_addr, k);
        if (entangled_addr && (entangled_addr != line_addr)) {
            uint32_t bb_size = l1i_get_bbsize_entangled_table(entangled_addr);
            l1i_add_xpq(entangled_addr, line_addr, bb_size + 1);
        }
    }

    if (!consecutive) { // New basic block found
        uint32_t max_bb_size = l1i_get_bbsize_entangled_table(l1i_last_basic_block);

        // Check for merging bb opportunities
        if (l1i_consecutive_count) { // single blocks no need to merge
            if (l1i_basic_block_merge_diff > 0) {
                l1i_add_bbsize_table(l1i_last_basic_block - l1i_basic_block_merge_diff, l1i_consecutive_count + l1i_basic_block_merge_diff);
                l1i_add_bb_size_hist_table(l1i_last_basic_block - l1i_basic_block_merge_diff, l1i_consecutive_count + l1i_basic_block_merge_diff);
            } else {
                l1i_add_bbsize_table(l1i_last_basic_block, max(max_bb_size, l1i_consecutive_count));
                l1i_add_bb_size_hist_table(l1i_last_basic_block, max(max_bb_size, l1i_consecutive_count));
            }
        }
    }

    if (!consecutive) { // New basic block found
        l1i_consecutive_count = 0;
        l1i_last_basic_block = line_addr;
    }  

    if (!consecutive) {
        l1i_basic_block_merge_diff = l1i_find_bb_merge_hist_table(l1i_last_basic_block);
    }

    // Add the request in the history buffer
    if (!consecutive && l1i_basic_block_merge_diff == 0) {
        if ((l1i_find_hist_entry(line_addr) == L1I_HIST_TABLE_ENTRIES)) {
            l1i_add_hist_table(line_addr);
        } else {
            if (!cache_hit && !l1i_ongoing_accessed_request(line_addr)) {
                l1i_add_hist_table(line_addr);      
            }
        }
    }

    // Add miss in the latency table
    if (!cache_hit && !l1i_ongoing_request(line_addr)) {
        l1i_add_timing_entry(line_addr, 0);
        l1i_access_timing_entry(line_addr);
    } else {
        l1i_access_timing_entry(line_addr);
    }

    // Do prefetches
    while (caches[4]->PQ.occupancy() < caches[4]->PQ_SIZE && !l1i_empty_xpq()) {
        uint64_t entangled_addr = 0; 
        uint64_t pf_line_addr = l1i_get_xpq(entangled_addr); 
        uint64_t pf_addr = (pf_line_addr << LOG2_BLOCK_SIZE); 
        if (!l1i_ongoing_request(pf_line_addr)) {
            my_pO3_CPU->prefetch_code_line(pf_addr);
            l1i_add_timing_entry(pf_line_addr, entangled_addr);
        }
    }
}

inline void eip_l1i_prefetcher_cycle_operate()
{
    // Do prefetches
    while (caches[4]->PQ.occupancy() < caches[4]->PQ_SIZE && !l1i_empty_xpq()) {
        uint64_t entangled_addr = 0; 
        uint64_t pf_line_addr = l1i_get_xpq(entangled_addr); 
        uint64_t pf_addr = (pf_line_addr << LOG2_BLOCK_SIZE); 
        if (!l1i_ongoing_request(pf_line_addr)) {
            my_pO3_CPU->prefetch_code_line(pf_addr);
            l1i_add_timing_entry(pf_line_addr, entangled_addr);
        }
    }
}

inline void eip_l1i_prefetcher_cache_fill(uint64_t v_addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_v_addr)
{
    l1i_cpu_id = cpu;
    uint64_t line_addr = (v_addr >> LOG2_BLOCK_SIZE);
    uint64_t evicted_line_addr = (evicted_v_addr >> LOG2_BLOCK_SIZE);

    // Line is in cache
    if (evicted_v_addr) {
        uint64_t bere_line_addr = 0;
        bool accessed = l1i_invalid_timing_cache_entry(evicted_line_addr, bere_line_addr);
        if (bere_line_addr != 0) {
            // If accessed hit, but if not wrong
            l1i_update_confidence_entangled_table(bere_line_addr, evicted_line_addr, accessed);
        }
    }

    uint64_t latency = l1i_get_latency_timing_mshr(line_addr);

    l1i_move_timing_entry(line_addr);

    // Get and update entangled
    if (latency) {
        bool inserted = false;
        for (uint32_t i = 0; i < L1I_TRIES_AVAIL_ENTANGLED; i++) {
            uint64_t bere = l1i_get_bere_hist_table(line_addr, latency, i);
            if (bere && line_addr != bere) {
                if (l1i_avail_entangled_table(bere, line_addr, false)) {
                    l1i_add_entangled_table(bere, line_addr);
                    inserted = true;
                    break;
                }
            }
        }
        if (!inserted) {
            for (uint32_t i = 0; i < L1I_TRIES_AVAIL_ENTANGLED_NOT_PRESENT; i++) {
                uint64_t bere = l1i_get_bere_hist_table(line_addr, latency, i);
                if (bere && line_addr != bere) {
                    if (l1i_avail_entangled_table(bere, line_addr, true)) {
                        l1i_add_entangled_table(bere, line_addr);
                        inserted = true;
                        break;
                    }
                }
            }
        }
        if (!inserted) {
            uint64_t bere = l1i_get_bere_hist_table(line_addr, latency);
            if (bere && line_addr != bere) {
                l1i_add_entangled_table(bere, line_addr);
            }
        }
    }
}

inline void eip_l1i_prefetcher_final_stats()
{
    cout << "CPU " << cpu << " L1I EPI prefetcher final stats" << endl;
}



// ========================================================================================================================
// ========================================================================================================================
// ====================================================== EIP END.=========================================================
// ========================================================================================================================
// ========================================================================================================================






// -> prefetch_code_line();




void O3_CPU::prefetcher_initialize() {
    my_pO3_CPU = this;
    //::l1i_prefetcher.at(cpu).reset(new ::D_JOLT_PREFETCHER(this));
    eip_l1i_prefetcher_initialize();
}

void O3_CPU::prefetcher_branch_operate(uint64_t ip, uint8_t branch_type, uint64_t branch_target) {
    //::l1i_prefetcher.at(cpu)->branch_operate(ip, branch_type, branch_target);
    eip_l1i_prefetcher_branch_operate(ip, branch_type, branch_target);
}

uint32_t O3_CPU::prefetcher_cache_operate(uint64_t v_addr, uint8_t cache_hit, uint8_t prefetch_hit, uint32_t metadata_in) {
    //::l1i_prefetcher.at(cpu)->cache_operate(v_addr, cache_hit, prefetch_hit);
    eip_l1i_prefetcher_cache_operate(v_addr, cache_hit, prefetch_hit);
    return metadata_in;
}

void O3_CPU::prefetcher_cycle_operate() {
    //::l1i_prefetcher.at(cpu)->cycle_operate();
    eip_l1i_prefetcher_cycle_operate();
}

uint32_t O3_CPU::prefetcher_cache_fill(uint64_t v_addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_v_addr, uint32_t metadata_in) {
    //::l1i_prefetcher.at(cpu)->cache_fill(v_addr, set, way, prefetch, evicted_v_addr);
    eip_l1i_prefetcher_cache_fill(v_addr, set, way, prefetch, evicted_v_addr);
    return metadata_in;
}

void O3_CPU::prefetcher_final_stats() {
    //::l1i_prefetcher.at(cpu)->final_stats();
    eip_l1i_prefetcher_final_stats();
}