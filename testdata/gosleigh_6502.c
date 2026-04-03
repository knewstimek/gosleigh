void test_6502(unsigned short param_0, unsigned char param_1, unsigned char param_2, unsigned char param_3, unsigned char param_4, unsigned char param_5, unsigned char param_6) {
    unsigned char tmp_0;
    unsigned short tmp_1;
    unsigned short local_0;
    unsigned short local_1;
    unsigned char local_2;
    unsigned char local_3;

    *(param_0 - 1) = 1;
    local_0 = register_22_2 - 2;
    tmp_1 = 2;
    local_2 = 1;
    tmp_0 = 0xff;
    *local_0 = ((((((0xff & 0xffffffffffffff7f | param_1 * 0x80) & 0xffffffffffffffbf | param_2 * 0x40) & 0xffffffffffffffef | 1 * 0x10) & 0xfffffffffffffff7 | param_3 * 8) & 0xfffffffffffffffb | param_4 * 4) & 0xfffffffffffffffd | param_5 * 2) & 0xfffffffffffffffe | param_6;
    local_1 = local_0 - 1;
    local_3 = 1;
    goto **0xfffe;
}
