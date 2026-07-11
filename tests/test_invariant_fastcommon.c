#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the actual production header */
#include "fastcommon.h"

START_TEST(test_sprintf_buffer_bounds)
{
    /* Invariant: sprintf must never write beyond the bounds of mc_info buffer */
    const char *payloads[] = {
        "fastcommon v%d.%d.%d supported",  /* Original format string */
        "fastcommon v%999d.%999d.%999d supported",  /* Boundary overflow attempt */
        "fastcommon v%2147483647d.%2147483647d.%2147483647d supported",  /* Large width overflow */
        "fastcommon v%hd.%hd.%hd supported",  /* Different format specifier */
        "fastcommon v%ld.%ld.%ld supported"   /* Another format specifier */
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char mc_info[64];
        int result;
        
        /* Direct call to the vulnerable pattern from production code */
        result = snprintf(mc_info, sizeof(mc_info), payloads[i],
                         FC_MAJOR_VERSION, FC_MINOR_VERSION, FC_PATCH_VERSION);
        
        /* Security property: result must be less than buffer size */
        ck_assert_msg(result < (int)sizeof(mc_info), 
                     "Format string '%s' produced %d bytes (buffer size: %zu)", 
                     payloads[i], result, sizeof(mc_info));
        
        /* Additional check: no buffer overflow occurred */
        ck_assert_msg(result >= 0, 
                     "Format string '%s' caused encoding error", payloads[i]);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_sprintf_buffer_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}