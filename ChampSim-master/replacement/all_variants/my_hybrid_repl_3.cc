// my_hybrid_2 + hysterysis (+-64)

//===================================================================================================
//===================================================================================================
//==================================== Hawkeye Cache Replacement ====================================
//===================================================================================================
//===================================================================================================

// Source code for configs 1 and 2

#include <map>
#include <algorithm>
#include <iterator>

#include "cache.h"
#include "util.h"

#define NUM_CORE 1
#define LLC_SETS NUM_CORE*2048
#define LLC_WAYS 16

//3-bit RRIP counters or all lines
#define maxRRPV 3 //changed 2 RRIP counters
uint32_t rrpv[LLC_SETS][LLC_WAYS];


//Per-set timers; we only use 64 of these
//Budget = 64 sets * 1 timer per set * 10 bits per timer = 80 bytes
#define TIMER_SIZE 1024
uint64_t perset_mytimer[LLC_SETS];

// Signatures for sampled sets; we only use 64 of these
// Budget = 64 sets * 16 ways * 12-bit signature per line = 1.5B
uint64_t signatures[LLC_SETS][LLC_WAYS];
bool prefetched[LLC_SETS][LLC_WAYS];

// Hawkeye Predictors for demand and prefetch requests
// Predictor with 2K entries and 5-bit counter per entry
// Budget = 2048*5/8 bytes = 1.2KB
#define MAX_SHCT 31
#define SHCT_SIZE_BITS 10 //changed
#define SHCT_SIZE (1<<SHCT_SIZE_BITS)
#include "hawkeye_predictor.h"
HAWKEYE_PC_PREDICTOR* demand_predictor;  //Predictor
HAWKEYE_PC_PREDICTOR* prefetch_predictor;  //Predictor

#define OPTGEN_VECTOR_SIZE 64 //changed
#include "optgen.h"
OPTgen perset_optgen[LLC_SETS]; // per-set occupancy vectors; we only use 64 of these

#include <math.h>
#define bitmask(l) (((l) == 64) ? (unsigned long long)(-1LL) : ((1LL << (l))-1LL))
#define bits(x, i, l) (((x) >> (i)) & bitmask(l))
//Sample 64 sets per core
#define SAMPLED_SET(set) (bits(set, 0 , 6) == bits(set, ((unsigned long long)log2(LLC_SETS) - 6), 6) )

// Sampler to track 8x cache history for sampled sets
// 2800 entris * 4 bytes per entry = 11.2KB
#define SAMPLED_CACHE_SIZE 824 //changed
#define SAMPLER_WAYS 8
#define SAMPLER_SETS SAMPLED_CACHE_SIZE/SAMPLER_WAYS
vector<map<uint64_t, ADDR_INFO> > addr_history; // Sampler

// initialize replacement state
void Hawkeye_initialize_replacement()
{
    for (int i=0; i<LLC_SETS; i++) {
        for (int j=0; j<LLC_WAYS; j++) {
            rrpv[i][j] = maxRRPV;
            signatures[i][j] = 0;
            prefetched[i][j] = false;
        }
        perset_mytimer[i] = 0;
        perset_optgen[i].init(LLC_WAYS-2);
    }

    addr_history.resize(SAMPLER_SETS);
    for (int i=0; i<SAMPLER_SETS; i++) 
        addr_history[i].clear();

    demand_predictor = new HAWKEYE_PC_PREDICTOR();
    prefetch_predictor = new HAWKEYE_PC_PREDICTOR();

    cout << "Initialize Hawkeye state" << endl;
}

// find replacement victim
// return value should be 0 ~ 15 or 16 (bypass)
uint32_t Hawkeye_find_victim (uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t PC, uint64_t paddr, uint32_t type)
{
    // look for the maxRRPV line
    for (uint32_t i=0; i<LLC_WAYS; i++)
        if (rrpv[set][i] == maxRRPV)
            return i;

    //If we cannot find a cache-averse line, we evict the oldest cache-friendly line
    uint32_t max_rrip = 0;
    int32_t lru_victim = -1;
    for (uint32_t i=0; i<LLC_WAYS; i++)
    {
        if (rrpv[set][i] >= max_rrip)
        {
            max_rrip = rrpv[set][i];
            lru_victim = i;
        }
    }

    assert (lru_victim != -1);
    //The predictor is trained negatively on LRU evictions
    if( SAMPLED_SET(set) )
    {
        if(prefetched[set][lru_victim])
            prefetch_predictor->decrement(signatures[set][lru_victim]);
        else
            demand_predictor->decrement(signatures[set][lru_victim]);
    }
    return lru_victim;

    // WE SHOULD NOT REACH HERE
    assert(0);
    return 0;
}

void replace_addr_history_element(unsigned int sampler_set)
{
    uint64_t lru_addr = 0;
    
    for(map<uint64_t, ADDR_INFO>::iterator it=addr_history[sampler_set].begin(); it != addr_history[sampler_set].end(); it++)
    {
   //     uint64_t timer = (it->second).last_quanta;

        if((it->second).lru == (SAMPLER_WAYS-1))
        {
            //lru_time =  (it->second).last_quanta;
            lru_addr = it->first;
            break;
        }
    }

    addr_history[sampler_set].erase(lru_addr);
}

void update_addr_history_lru(unsigned int sampler_set, unsigned int curr_lru)
{
    for(map<uint64_t, ADDR_INFO>::iterator it=addr_history[sampler_set].begin(); it != addr_history[sampler_set].end(); it++)
    {
        if((it->second).lru < curr_lru)
        {
            (it->second).lru++;
            assert((it->second).lru < SAMPLER_WAYS); 
        }
    }
}


// called on every cache hit and cache fill
void Hawkeye_update_replacement_state (uint32_t cpu, uint32_t set, uint32_t way, uint64_t paddr, uint64_t PC, uint64_t victim_addr, uint32_t type, uint8_t hit)
{
    paddr = (paddr >> 6) << 6;

    if(type == PREFETCH)
    {
        if (!hit)
            prefetched[set][way] = true;
    }
    else
        prefetched[set][way] = false;

    //Ignore writebacks
    if (type == WRITEBACK)
        return;


    //If we are sampling, OPTgen will only see accesses from sampled sets
    if(SAMPLED_SET(set))
    {
        //The current timestep 
        uint64_t curr_quanta = perset_mytimer[set] % OPTGEN_VECTOR_SIZE;

        uint32_t sampler_set = (paddr >> 6) % SAMPLER_SETS; 
        uint64_t sampler_tag = CRC(paddr >> 12) % 256;
        assert(sampler_set < SAMPLER_SETS);

        // This line has been used before. Since the right end of a usage interval is always 
        //a demand, ignore prefetches
        if((addr_history[sampler_set].find(sampler_tag) != addr_history[sampler_set].end()) && (type != PREFETCH))
        {
            unsigned int curr_timer = perset_mytimer[set];
            if(curr_timer < addr_history[sampler_set][sampler_tag].last_quanta)
               curr_timer = curr_timer + TIMER_SIZE;
            bool wrap =  ((curr_timer - addr_history[sampler_set][sampler_tag].last_quanta) > OPTGEN_VECTOR_SIZE);
            uint64_t last_quanta = addr_history[sampler_set][sampler_tag].last_quanta % OPTGEN_VECTOR_SIZE;
            //and for prefetch hits, we train the last prefetch trigger PC
            if( !wrap && perset_optgen[set].should_cache(curr_quanta, last_quanta))
            {
                if(addr_history[sampler_set][sampler_tag].prefetched)
                    prefetch_predictor->increment(addr_history[sampler_set][sampler_tag].PC);
                else
                    demand_predictor->increment(addr_history[sampler_set][sampler_tag].PC);
            }
            else
            {
                //Train the predictor negatively because OPT would not have cached this line
                if(addr_history[sampler_set][sampler_tag].prefetched)
                    prefetch_predictor->decrement(addr_history[sampler_set][sampler_tag].PC);
                else
                    demand_predictor->decrement(addr_history[sampler_set][sampler_tag].PC);
            }
            //Some maintenance operations for OPTgen
            perset_optgen[set].add_access(curr_quanta);
            update_addr_history_lru(sampler_set, addr_history[sampler_set][sampler_tag].lru);

            //Since this was a demand access, mark the prefetched bit as false
            addr_history[sampler_set][sampler_tag].prefetched = false;
        }
        // This is the first time we are seeing this line (could be demand or prefetch)
        else if(addr_history[sampler_set].find(sampler_tag) == addr_history[sampler_set].end())
        {
            // Find a victim from the sampled cache if we are sampling
            if(addr_history[sampler_set].size() == SAMPLER_WAYS) 
                replace_addr_history_element(sampler_set);

            assert(addr_history[sampler_set].size() < SAMPLER_WAYS);
            //Initialize a new entry in the sampler
            addr_history[sampler_set][sampler_tag].init(curr_quanta);
            //If it's a prefetch, mark the prefetched bit;
            if(type == PREFETCH)
            {
                addr_history[sampler_set][sampler_tag].mark_prefetch();
                perset_optgen[set].add_prefetch(curr_quanta);
            }
            else
                perset_optgen[set].add_access(curr_quanta);
            update_addr_history_lru(sampler_set, SAMPLER_WAYS-1);
        }
        else //This line is a prefetch
        {
            assert(addr_history[sampler_set].find(sampler_tag) != addr_history[sampler_set].end());
            //if(hit && prefetched[set][way])
            uint64_t last_quanta = addr_history[sampler_set][sampler_tag].last_quanta % OPTGEN_VECTOR_SIZE;
            if (perset_mytimer[set] - addr_history[sampler_set][sampler_tag].last_quanta < 5*NUM_CORE) 
            {
                if(perset_optgen[set].should_cache(curr_quanta, last_quanta))
                {
                    if(addr_history[sampler_set][sampler_tag].prefetched)
                        prefetch_predictor->increment(addr_history[sampler_set][sampler_tag].PC);
                    else
                       demand_predictor->increment(addr_history[sampler_set][sampler_tag].PC);
                }
            }

            //Mark the prefetched bit
            addr_history[sampler_set][sampler_tag].mark_prefetch(); 
            //Some maintenance operations for OPTgen
            perset_optgen[set].add_prefetch(curr_quanta);
            update_addr_history_lru(sampler_set, addr_history[sampler_set][sampler_tag].lru);
        }

        // Get Hawkeye's prediction for this line
        bool new_prediction = demand_predictor->get_prediction (PC);
        if (type == PREFETCH)
            new_prediction = prefetch_predictor->get_prediction (PC);
        // Update the sampler with the timestamp, PC and our prediction
        // For prefetches, the PC will represent the trigger PC
        addr_history[sampler_set][sampler_tag].update(perset_mytimer[set], PC, new_prediction);
        addr_history[sampler_set][sampler_tag].lru = 0;
        //Increment the set timer
        perset_mytimer[set] = (perset_mytimer[set]+1) % TIMER_SIZE;
    }

    bool new_prediction = demand_predictor->get_prediction (PC);
    if (type == PREFETCH)
        new_prediction = prefetch_predictor->get_prediction (PC);

    signatures[set][way] = PC;

    //Set RRIP values and age cache-friendly line
    if(!new_prediction)
        rrpv[set][way] = maxRRPV;
    else
    {
        rrpv[set][way] = 0;
        if(!hit)
        {
            bool saturated = false;
            for(uint32_t i=0; i<LLC_WAYS; i++)
                if (rrpv[set][i] == maxRRPV-1)
                    saturated = true;

            //Age all the cache-friendly  lines
            for(uint32_t i=0; i<LLC_WAYS; i++)
            {
                if (!saturated && rrpv[set][i] < maxRRPV-1)
                    rrpv[set][i]++;
            }
        }
        rrpv[set][way] = 0;
    }
}

// use this function to print out your own stats on every heartbeat 
void PrintStats_Heartbeat() {}

// use this function to print out your own stats at the end of simulation
void Hawkeye_replacement_final_stats() {
    unsigned int hits = 0;
    unsigned int accesses = 0;
    for(unsigned int i=0; i<LLC_SETS; i++) {
        accesses += perset_optgen[i].access;
        hits += perset_optgen[i].get_num_opt_hits();
    }

    std::cout << "OPTgen accesses: " << accesses << std::endl;
    std::cout << "OPTgen hits: " << hits << std::endl;
    std::cout << "OPTgen hit rate: " << 100*(double)hits/(double)accesses << std::endl;

    cout << endl << endl;
    return;
}



//===================================================================================================
//===================================================================================================
//===================================== SHiP++ Cache Replacement ====================================
//===================================================================================================
//===================================================================================================



////////////////////////////////////////////
//                                        //
//     SRRIP [Jaleel et al. ISCA' 10]     //
//     Jinchun Kim, cienlux@tamu.edu      //
//                                        //
////////////////////////////////////////////

#include <algorithm>
#include <iterator>

#include "cache.h"
#include "util.h"

#define NUM_CORE 1
#define MAX_LLC_SETS NUM_CORE*2048
#define LLC_WAYS 16

#define SAT_INC(x,max)  (x<max)?x+1:x
#define SAT_DEC(x)      (x>0)?x-1:x
#define TRUE 1
#define FALSE 0
#define SHIPpp_SAMPLED_SET(set) (bits(set, 0 , 6) == bits(~set, ((unsigned long long)log2(LLC_SETS) - 6), 6) )

#define RRIP_OVERRIDE_PERC   0

// The base policy is SRRIP. SHIP needs the following on a per-line basis
// Usage = (no. of line)*{(rrpv bits) + (is_prefetch bit) + (fill_core bits)} = 16*2048 {2+1+2} = 20KB (8KB)
#define maxRRPV 3
uint32_t line_rrpv[MAX_LLC_SETS][LLC_WAYS];
uint32_t is_prefetch[MAX_LLC_SETS][LLC_WAYS];   // no space if no prefetchers
uint32_t fill_core[MAX_LLC_SETS][LLC_WAYS];     // no space for 1-core

// These two are only for sampled sets (we use 64 sets)
// Usage = (64*16)*(15) = 1.875KB
#define NUM_LEADER_SETS   64
uint32_t line_reuse[MAX_LLC_SETS][LLC_WAYS];    // 1-bit - only for sampled sets
uint64_t line_sig[MAX_LLC_SETS][LLC_WAYS];      // 14-bit - only for sampled sets

// SHCT. Signature History Counter Table
// per-core 16K entry. 14-bit signature = 16k entry. 3-bit per entry
// Usage = (16*1024)*(3) = 6KB
#define maxSHCTR 7                              // 3-bits
#undef SHCT_SIZE
#define SHCT_SIZE (1<<14)
uint32_t SHCT[NUM_CORE][SHCT_SIZE];

// Statistics
uint64_t insertion_distrib[NUM_TYPES][maxRRPV+1];
uint64_t total_prefetch_downgrades;

// initialize replacement state
void SHiPpp_initialize_replacement() {

    cout << "Initialize SRRIP state" << endl;

    for (int i=0; i<MAX_LLC_SETS; i++) {
        for (int j=0; j<LLC_WAYS; j++) {
            line_rrpv[i][j] = maxRRPV;
            line_reuse[i][j] = FALSE;
            is_prefetch[i][j] = FALSE;
            line_sig[i][j] = 0;
        }
    }

    for (int i=0; i<NUM_CORE; i++) {
        for (int j=0; j<SHCT_SIZE; j++) {
            SHCT[i][j] = 1; // Assume weakly re-use start
        }
    }
}

// find replacement victim
// return value should be 0 ~ 15 or 16 (bypass)
uint32_t SHiPpp_find_victim (uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK *current_set, uint64_t PC, uint64_t paddr, uint32_t type) {

    // look for the maxRRPV line
    while (1) {
        for (int i=0; i<LLC_WAYS; i++)
            if (line_rrpv[set][i] == maxRRPV) { // found victim
                return i;
            }
        for (int i=0; i<LLC_WAYS; i++)
            line_rrpv[set][i]++;
    }

    // WE SHOULD NOT REACH HERE
    assert(0);
    return 0;
}

// called on every cache hit and cache fill
void SHiPpp_update_replacement_state (uint32_t cpu, uint32_t set, uint32_t way, uint64_t paddr, uint64_t PC, uint64_t victim_addr, uint32_t type, uint8_t hit) {

    uint32_t sig = line_sig[set][way];
    // update to REREF on hit
    if (hit) { 
        if ( type != WRITEBACK ) {
            if ( (type == PREFETCH) && is_prefetch[set][way] ) {
                if( (SHIPpp_SAMPLED_SET(set)) && ((rand()%100 <5) || (/*get_config_number()*/1==4))) {
                    uint32_t fill_cpu = fill_core[set][way];
                    SHCT[fill_cpu][sig] = SAT_INC(SHCT[fill_cpu][sig], maxSHCTR);
                    line_reuse[set][way] = TRUE;
                }
            } else {
                line_rrpv[set][way] = 0;

                if( is_prefetch[set][way] ) {
                    line_rrpv[set][way] = maxRRPV;
                    is_prefetch[set][way] = FALSE;
                    total_prefetch_downgrades++;
                }

                if( (SHIPpp_SAMPLED_SET(set)) && (line_reuse[set][way]==0) ) {
                    uint32_t fill_cpu = fill_core[set][way];
                    SHCT[fill_cpu][sig] = SAT_INC(SHCT[fill_cpu][sig], maxSHCTR);
                    line_reuse[set][way] = TRUE;
                }
            }
        }
	    return;
    }
    
    //--- All of the below is done only on misses -------
    // remember signature of what is being inserted
    uint64_t use_PC = (type == PREFETCH ) ? ((PC << 1) + 1) : (PC<<1);
    uint32_t new_sig = use_PC%SHCT_SIZE;
    
    if ( SHIPpp_SAMPLED_SET(set) ) {
        uint32_t fill_cpu = fill_core[set][way];
        
        // update signature based on what is getting evicted
        if (line_reuse[set][way] == FALSE) { 
            SHCT[fill_cpu][sig] = SAT_DEC(SHCT[fill_cpu][sig]);
        } else {
            SHCT[fill_cpu][sig] = SAT_INC(SHCT[fill_cpu][sig], maxSHCTR);
        }

        line_reuse[set][way] = FALSE;
        line_sig[set][way]   = new_sig;  
        fill_core[set][way]  = cpu;
    }

    is_prefetch[set][way] = (type == PREFETCH);

    // Now determine the insertion prediciton

    uint32_t priority_RRPV = maxRRPV-1 ; // default SHIP

    if( type == WRITEBACK ) {
        line_rrpv[set][way] = maxRRPV;
    } else if (SHCT[cpu][new_sig] == 0) {
        line_rrpv[set][way] = (rand()%100>=RRIP_OVERRIDE_PERC)?  maxRRPV: priority_RRPV; //LowPriorityInstallMostly
    } else if (SHCT[cpu][new_sig] == 7) {
        line_rrpv[set][way] = (type == PREFETCH) ? 1 : 0; // HighPriority Install
    } else {
        line_rrpv[set][way] = priority_RRPV; // HighPriority Install 
    }

    // Stat tracking for what insertion it was at
    insertion_distrib[type][line_rrpv[set][way]]++;
}

// use this function to print out your own stats on every heartbeat 
void SHiPpp_PrintStats_Heartbeat() {}

string names[] = {"LOAD", "RFO", "PREF", "WRITEBACK", "TRANSLATION"};

// use this function to print out your own stats at the end of simulation
void SHiPpp_replacement_final_stats() {
    cout<<"Insertion Distribution: "<<endl;
    for(uint32_t i=0; i<NUM_TYPES; i++) {
        cout<<"\t"<<names[i]<<" ";
        for(uint32_t v=0; v<maxRRPV+1; v++) {
            cout<<insertion_distrib[i][v]<<" ";
        }
        cout<<endl;
    }
    cout<<"Total Prefetch Downgrades: "<<total_prefetch_downgrades<<endl;
}













//===================================================================================================
//===================================================================================================
//=========================================== Set Dualing ===========================================
//===================================================================================================
//===================================================================================================


// only this counter costs memory
#define SD_MAX 8192
#define SD_INIT 4096
#define SD_LOWER_TH 4096 - 64
#define SD_UPPER_TH 4096 + 64
int sd_counter; // (10-bit)
uint32_t following;  // (1-bit) 1-hawkeye, 0-SHiP++
uint32_t s_count = 0;  // debug
uint32_t h_count = 0;  // debug
uint32_t sm_count = 0;  // debug
uint32_t hm_count = 0;  // debug

// This tells if the set belongs to Hawkeye -> #define SAMPLED_SET(set) 
// This tells if the set belongs to SHiP++ -> #define SHIPpp_SAMPLED_SET(set) 
// Rest are follower sets

void sd_initialize_replacement() {
    sd_counter = SD_INIT;
    if(sd_counter < SD_LOWER_TH) {
        following = 0;
    } else {
        following = 1;
    }
}

uint32_t sd_find_victim(uint32_t set) {
    if(SAMPLED_SET(set)) {
        return 1;
    } else if(SHIPpp_SAMPLED_SET(set)) {
        return 0;
    } else {
        return following;
    }
}

void sd_update_replacement_state(uint32_t set, uint32_t type, uint8_t hit) {
    //debug
    if(following) {
        h_count++;
    } else {
        s_count++;
    }
    if (hit) {
        return ;
    } else {
        if(SAMPLED_SET(set)) {
            hm_count++;
        } else if(SHIPpp_SAMPLED_SET(set)) {
            sm_count++;
        }
    }
    if (hit) {
        return ;
    } else {
        if (type == WRITEBACK) {
            if(SAMPLED_SET(set)) {
                sd_counter -= 1;
            } else if(SHIPpp_SAMPLED_SET(set)) {
                sd_counter += 1;
            }
        } else if (type == PREFETCH) {
            if(SAMPLED_SET(set)) {
                sd_counter -= 2;
            } else if(SHIPpp_SAMPLED_SET(set)) {
                sd_counter += 2;
            }
        } else {
            if(SAMPLED_SET(set)) {
                sd_counter -= 8;
            } else if(SHIPpp_SAMPLED_SET(set)) {
                sd_counter += 8;
            }
        }
        if(sd_counter < 0) {
            sd_counter = 0;
        } else if (sd_counter >= SD_MAX) {
            sd_counter = SD_MAX-1;
        }
        if(sd_counter >= SD_UPPER_TH) {
            following = 1;
        } else if(sd_counter < SD_UPPER_TH) {
            following = 0;
        }
    }
}

void sd_replacement_final_stats() {
    cout << "DIP stats:" << endl;
    cout << "h_count: " << h_count << "(" << (((float)h_count)/(float)(h_count+s_count)) << ")" << endl;
    cout << "s_count: " << s_count << "(" << (((float)s_count)/(float)(h_count+s_count)) << ")" << endl;
    cout << "total: " << (h_count+s_count) << endl;
    cout << "hm_count: " << hm_count << endl;
    cout << "sm_count: " << sm_count << endl;
}



//===================================================================================================
//===================================================================================================
//============================================ Interface ============================================
//===================================================================================================
//===================================================================================================




void CACHE::initialize_replacement() {
    Hawkeye_initialize_replacement();
    SHiPpp_initialize_replacement();
    sd_initialize_replacement();
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK* current_set, uint64_t ip, uint64_t full_addr, uint32_t type) {
    if (sd_find_victim(set)) {
        uint32_t h_victim = Hawkeye_find_victim (cpu, instr_id, set, current_set, ip, full_addr, type);
        return h_victim;
    } else {
        uint32_t s_victim = SHiPpp_find_victim (cpu, instr_id, set, current_set, ip, full_addr, type);
        return s_victim;
    }
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type, uint8_t hit) {
    Hawkeye_update_replacement_state (cpu, set, way, full_addr, ip, victim_addr, type, hit);
    SHiPpp_update_replacement_state (cpu, set, way, full_addr, ip, victim_addr, type, hit);
    sd_update_replacement_state(set, type, hit);
}

void CACHE::replacement_final_stats() {
    Hawkeye_replacement_final_stats();
    SHiPpp_replacement_final_stats();
    sd_replacement_final_stats();
}