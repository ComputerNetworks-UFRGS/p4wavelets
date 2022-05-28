#include <stdint.h>
#include <nfp.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"

#define TABLE_SIZE 	4096
#define NUM_LEVELS	17

typedef struct flow_info {
	uint64_t t0;
	uint64_t last_t;
	uint64_t last_bucket;
	uint64_t last_last_bucket;

	int value;
	int shared_var;

	__mem __addr40 uint64_t* window;
	__mem __addr40 struct pif_header_N 			*N;
	__mem __addr40 struct pif_header_sum 			*sum;
} flow_info;

#include "energy.c"

__declspec(imem shared export ) uint64_t window[TABLE_SIZE * 2 * (NUM_LEVELS+1)];
__declspec(imem shared export aligned(64)) int global_semaphores[TABLE_SIZE];
__declspec(imem shared export aligned(64)) int shared_semaphores[TABLE_SIZE];
__declspec(imem shared export aligned(64)) flow_info flow_table[TABLE_SIZE];

__forceinline uint64_t div1000(uint64_t n) {
	uint64_t q, r, t;
	
	n = n + (n >> 31 & 999);
	t = (n >> 7) + (n >> 8) + (n >> 12);
	q = (n >> 1) + t + (n >> 15) + (t >> 11) + (t >> 14) + (n >> 26) + (t >> 21);
	q = q >> 9;
	r = n - q*1000;
	
	return q + ((r + 24) >> 10);
}

void semaphore_down(volatile __declspec(mem addr40) void * addr) {
	unsigned int addr_hi, addr_lo;
	__declspec(read_write_reg) int xfer;
	SIGNAL_PAIR my_signal_pair;
	addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
	addr_lo = (unsigned long long int)addr & 0xffffffff;

	do {
		xfer = 1;
		__asm {
            		mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
                	sig_done[my_signal_pair];
            		ctx_arb[my_signal_pair]
        	}
	} while (xfer == 0);
}

void semaphore_up(volatile __declspec(mem addr40) void * addr) {
	unsigned int addr_hi, addr_lo;
	__declspec(read_write_reg) int xfer;

	addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
	addr_lo = (unsigned long long int)addr & 0xffffffff;

    	__asm {
        	mem[incr, --, addr_hi, <<8, addr_lo, 1];
    	}
}

void pif_plugin_init() { 
}

void pif_plugin_init_master() {
	int i;
	__mem __addr40 flow_info *ptr;
	
	for(i = 0; i < TABLE_SIZE; i++) {
		ptr = (__mem __addr40 flow_info*) &flow_table[i];

		ptr->t0 = 0;
		ptr->value = 0;
		ptr->last_t = 0;
		ptr->shared_var = 0;
		ptr->last_bucket = 0;
		ptr->last_last_bucket = 0;
		ptr->window = &(window[i * (NUM_LEVELS * 2)]);

		semaphore_up(&global_semaphores[i]);
		semaphore_up(&shared_semaphores[i]);

		ptr->N			   	= (__mem __addr40 struct pif_header_N *)   	&pif_register_N[i];
		ptr->sum		   	= (__mem __addr40 struct pif_header_sum *)   	&pif_register_sum[i * (NUM_LEVELS+1)];
	}
}

/**************************************************************************
**************  W A V E L E T S   P R O C E S S I N G   *******************
**************************************************************************/

int pif_plugin_do_wavelets(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
	uint64_t t;
	uint32_t delta;
	uint32_t index;
	uint64_t last_t;
	uint32_t bucket;
	uint32_t last_bucket;
	uint32_t last_last_bucket;
	uint32_t timeinterval;
	uint32_t ingress_time_in_s;
	uint32_t ingress_time_in_ns;
	__mem __addr40 flow_info *ptr;

	ingress_time_in_s  = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers);
	ingress_time_in_ns = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);

	t  = (uint64_t)ingress_time_in_s;
	t *= 1000000000L;
	t += (uint64_t)ingress_time_in_ns;

	index = pif_plugin_meta_get__intrinsic_metadata__index(headers);

	ptr = (__mem __addr40 flow_info*) &flow_table[index];

	semaphore_down(&global_semaphores[index]);
	if(ptr->t0 == 0) {
		ptr->t0 = t;
		ptr->last_t = t;
		ptr->last_bucket = 0;
	}
	last_t = ptr->last_t;
	last_bucket = ptr->last_bucket;
	semaphore_up(&global_semaphores[index]);
	
	bucket = (div1000(t - ptr->t0)) >> 2;
	if(t < last_t) {
		return PIF_PLUGIN_RETURN_FORWARD;
	}

	delta = (bucket - last_bucket);
	if(delta > 0) {
		semaphore_down(&shared_semaphores[index]);
		if(ptr->shared_var) {
			semaphore_up(&shared_semaphores[index]);
		} else {
			uint32_t leftk;
			uint32_t rightk;
			int rightk_value;

			ptr->shared_var = 1;
			semaphore_up(&shared_semaphores[index]);

			{
				__xwrite uint32_t _pif_xreg[1];
				_pif_xreg[0] = bucket;
				mem_write_atomic(_pif_xreg, ((__mem __addr40 uint8_t *)ptr->N), 4);
			}

			leftk = ptr->last_last_bucket;
			rightk = ptr->last_bucket;
			rightk_value = ptr->value;
			ptr->value = 0;

			if(last_bucket != 0) {
				energy(leftk, rightk, rightk_value, ptr);
			}

			ptr->window[rightk & 1] = rightk_value;

			ptr->last_last_bucket = last_bucket;
			ptr->last_bucket = bucket;

			semaphore_down(&shared_semaphores[index]);
			ptr->shared_var = 0;
			semaphore_up(&shared_semaphores[index]);
		}
	}
	ptr->value++;

	{
		__xwrite uint64_t _pif_xreg[2];
		_pif_xreg[0] = t;
		_pif_xreg[1] = bucket;
		mem_write_atomic(_pif_xreg, (((__mem __addr40 uint8_t *)ptr) + 8), 16);
	}

	return PIF_PLUGIN_RETURN_FORWARD;
}
