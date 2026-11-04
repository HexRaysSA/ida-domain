# A sparse switch (value table + jump table), for testing Instructions.get_switch().
#
# Written in smali because d8 compiles a Java switch this small to an if-chain.
# Every case calls its own method, so tests can tell where a value goes from
# the name of the method its target calls.

.class public LTinySwitch;
.super Ljava/lang/Object;

.method static sparse_m5()V
    .registers 0
    return-void
.end method

.method static sparse_1()V
    .registers 0
    return-void
.end method

.method static sparse_100()V
    .registers 0
    return-void
.end method

.method static sparse_1000()V
    .registers 0
    return-void
.end method

.method static sparse_default()V
    .registers 0
    return-void
.end method

.method static sparse(I)V
    .registers 1
    sparse-switch p0, :switch_data
    invoke-static {}, LTinySwitch;->sparse_default()V
    return-void
    :case_m5
    invoke-static {}, LTinySwitch;->sparse_m5()V
    return-void
    :case_1
    invoke-static {}, LTinySwitch;->sparse_1()V
    return-void
    :case_100
    invoke-static {}, LTinySwitch;->sparse_100()V
    return-void
    :case_1000
    invoke-static {}, LTinySwitch;->sparse_1000()V
    return-void
    :switch_data
    .sparse-switch
        -5 -> :case_m5
        1 -> :case_1
        100 -> :case_100
        1000 -> :case_1000
    .end sparse-switch
.end method
