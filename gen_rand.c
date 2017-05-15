#include <stdint.h>
#include <stdlib.h>
#include <pif_plugin.h>
#include <pif_plugin_metadata.h>

int first = 1;
int pif_plugin_gen_rand(EXTRACTED_HEADERS_T* headers, ACTION_DATA_T* action_data)
{
    unsigned randval;

    if (first){
        first = 0;
        local_csr_write(local_csr_pseudo_random_number,(local_csr_read(local_csr_timestamp_low) & 0xffff) +1 );
        local_csr_read(local_csr_pseudo_random_number);
    }
    randval = local_csr_read(local_csr_pseudo_random_number) % 10000;

    pif_plugin_meta_set__sampling__rand(headers, randval);

    return PIF_PLUGIN_RETURN_FORWARD;
}
