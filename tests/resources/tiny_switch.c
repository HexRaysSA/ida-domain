/*
 * Switches that compile to jump tables, for testing Instructions.get_switch().
 *
 * Every case calls its own function, which keeps the compiler from turning a
 * switch into a lookup table and lets the tests tell where a value goes from
 * the name of the function its target calls.
 */

void dense_10(void);
void dense_11(void);
void dense_12_14(void);
void dense_15(void);
void dense_16(void);
void dense_17(void);
void dense_19(void);
void dense_default(void);

/* 12 and 14 share a target; 13 and 18 have no case and go to the default. */
void dense(int x)
{
    switch (x) {
    case 10: dense_10(); break;
    case 11: dense_11(); break;
    case 12:
    case 14: dense_12_14(); break;
    case 15: dense_15(); break;
    case 16: dense_16(); break;
    case 17: dense_17(); break;
    case 19: dense_19(); break;
    default: dense_default(); break;
    }
}

void no_default_0(void);
void no_default_1(void);
void no_default_2(void);
void no_default_3(void);
void no_default_4(void);
void no_default_5(void);
void no_default_6(void);
void no_default_7(void);

/* Every value of x & 7 has a case, so the switch has no default. */
void no_default(unsigned x)
{
    switch (x & 7) {
    case 0: no_default_0(); break;
    case 1: no_default_1(); break;
    case 2: no_default_2(); break;
    case 3: no_default_3(); break;
    case 4: no_default_4(); break;
    case 5: no_default_5(); break;
    case 6: no_default_6(); break;
    case 7: no_default_7(); break;
    }
}

void negative_m3(void);
void negative_m2(void);
void negative_m1(void);
void negative_0(void);
void negative_1(void);
void negative_2(void);
void negative_3(void);
void negative_default(void);

/* Cases straddling zero, so the lowest case is negative. */
void negative(int x)
{
    switch (x) {
    case -3: negative_m3(); break;
    case -2: negative_m2(); break;
    case -1: negative_m1(); break;
    case 0: negative_0(); break;
    case 1: negative_1(); break;
    case 2: negative_2(); break;
    case 3: negative_3(); break;
    default: negative_default(); break;
    }
}
