功能介绍：
实现sys_task_info系统调用，可以查询当前正在执行的任务信息，任务信息包括任务控制块相关信息（任务状态）、任务使用的系统调用及调用次数、系统调用时刻距离任务第一次被调度时刻的时长（单位ms）。

简答作业：
1. 程序出错行为是打印[kernel] IllegalInstruction in application, kernel killed it.，然后switch到其他进程，使用的sbi为RustSBI-QEMU Version 0.2.0-alpha.2

2. 
    1.  __restore 有两个主要使用情景：
        从中断或异常返回用户态：当处理完异常或中断时，操作系统通过 __restore 恢复用户态的寄存器状态，并执行 sret 指令返回到用户态。
        从系统调用返回用户态：系统调用完成后，也会通过 __restore 恢复用户态寄存器，并返回用户态继续执行用户程序。

    2.  sstatus：保存了内核模式和用户模式的状态信息。恢复该寄存器的值确保返回用户态时使用正确的特权级别和中断使能状态等。
        sepc：保存了用户态程序执行时的异常或中断发生时的程序计数器（PC）值。恢复后，sepc 指定了返回用户态时应该继续执行的指令地址。
        sscratch：在陷入内核态时存储用户态栈指针。恢复 sscratch 确保返回用户态时栈指针能正确指向用户态栈。

    3.  在 __alltraps 和 __restore 中，跳过了 x2 和 x4（即 sp 和 tp）是因为：
        x2 (sp)：栈指针在陷入内核时被特殊处理，切换到内核栈。返回用户态时会通过 sscratch 和 sp 进行交换处理（见 csrrw sp, sscratch, sp），不需要直接恢复。
        x4 (tp)：线程指针 tp 通常是用户态程序在某些应用中使用，但在陷入内核时并不使用，所以在此无需恢复 tp。

    4. 之前保存的 sscratch 中的值（用户态栈指针）现在赋给了 sp，即 sp 成为用户态的栈指针，原本的 sp（内核态栈指针）现在被保存到了 sscratch 中，供下次陷入内核时使用。

    5.  sret 指令用于从 S-mode 返回 U-mode（用户态）。它会根据 sstatus 寄存器的 SPP 位判断是否返回到用户态，如果 SPP 位设置为用户态（U-mode），则 sret 会切换到用户态，并将 sepc 寄存器中的值加载到 PC 寄存器，继续用户态的程序执行。

    6. 之前保存的 sscratch 中的值（内核态栈指针）现在赋给了 sp，即 sp 成为内核态的栈指针，原本的 sp（用户态栈指针）现在被保存到了 sscratch 中，供后续写入上下文。

    7. ecall

荣誉准则：
1. 在完成本次实验的过程（含此前学习的过程）中，我曾分别与 以下各位 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：
NONE
2. 此外，我也参考了 以下资料 ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：
NONE
3. 我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。

4. 我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。