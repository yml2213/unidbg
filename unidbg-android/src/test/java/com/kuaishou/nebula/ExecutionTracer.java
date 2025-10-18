package com.kuaishou.nebula;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import unicorn.Arm64Const;

import java.util.HashMap;
import java.util.Map;

/**
 * 精确调试工具 - 用于对比真机和unidbg的执行差异
 *
 * 使用方法:
 * ExecutionTracer tracer = new ExecutionTracer(emulator, module);
 * tracer.enableDetailedTrace();  // 启用详细跟踪
 * // ... 执行加密调用 ...
 * tracer.printReport();  // 打印对比报告
 */
public class ExecutionTracer {
    private final AndroidEmulator emulator;
    private final com.github.unidbg.Module module;
    private final Backend backend;

    // 记录关键地址的访问
    private Map<String, Long> memorySnapshot = new HashMap<>();
    private Map<String, Integer> branchCounter = new HashMap<>();

    // 关键内存地址
    private static final long QWORD_70910_OFFSET = 0x70910;
    private static final long BYTE_7091F_OFFSET = 0x7091F;
    private static final long DWORD_70C10_OFFSET = 0x70C10;
    private static final long DWORD_70C14_OFFSET = 0x70C14;

    // 关键执行路径
    private static final long[] CRITICAL_POINTS = {
        0x42bc8,  // GetByteArrayRegion后
        0x42c00,  // 反调试检查
        0x42e08,  // opcode检查
        0x43000,  // 加密逻辑入口
        0x43368   // 错误返回路径
    };

    public ExecutionTracer(AndroidEmulator emulator, com.github.unidbg.Module module) {
        this.emulator = emulator;
        this.module = module;
        this.backend = emulator.getBackend();
    }

    /**
     * 启用详细执行跟踪
     */
    public void enableDetailedTrace() {
        System.out.println("\n[ExecutionTracer] 🔍 启用详细执行跟踪");

        // 1. 快照关键内存地址的初始值
        snapshotMemory("INIT");

        // 2. Hook关键执行点
        for (int i = 0; i < CRITICAL_POINTS.length; i++) {
            final long addr = module.base + CRITICAL_POINTS[i];
            final int index = i;

            backend.hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    String pointName = "POINT_" + index;
                    branchCounter.put(pointName, branchCounter.getOrDefault(pointName, 0) + 1);

                    System.out.println(String.format(
                        "\n[🎯 执行点 #%d] 0x%05x (第%d次)",
                        index,
                        CRITICAL_POINTS[index],
                        branchCounter.get(pointName)
                    ));

                    // 打印寄存器状态
                    printRegisters();

                    // 快照内存
                    snapshotMemory(pointName);
                }

                @Override
                public void onAttach(UnHook unHook) {}

                @Override
                public void detach() {}
            }, addr, addr + 4, null);
        }

        // 3. Hook关键分支指令
        hookCriticalBranches();

        System.out.println("[ExecutionTracer] ✓ 跟踪已启用\n");
    }

    /**
     * 快照关键内存地址的当前值
     */
    private void snapshotMemory(String tag) {
        // qword_70910 (8字节)
        long addr1 = module.base + QWORD_70910_OFFSET;
        byte[] bytes1 = backend.mem_read(addr1, 8);
        long value1 = bytesToLong(bytes1);
        memorySnapshot.put(tag + "_qword_70910", value1);

        // byte_7091F (1字节)
        long addr2 = module.base + BYTE_7091F_OFFSET;
        byte[] bytes2 = backend.mem_read(addr2, 1);
        long value2 = bytes2[0] & 0xFF;
        memorySnapshot.put(tag + "_byte_7091F", value2);

        // dword_70C10 (4字节)
        long addr3 = module.base + DWORD_70C10_OFFSET;
        byte[] bytes3 = backend.mem_read(addr3, 4);
        long value3 = bytesToInt(bytes3);
        memorySnapshot.put(tag + "_dword_70C10", value3);

        // dword_70C14 (4字节)
        long addr4 = module.base + DWORD_70C14_OFFSET;
        byte[] bytes4 = backend.mem_read(addr4, 4);
        long value4 = bytesToInt(bytes4);
        memorySnapshot.put(tag + "_dword_70C14", value4);
    }

    /**
     * 打印当前寄存器状态
     */
    private void printRegisters() {
        long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
        long x2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
        long x3 = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
        long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

        System.out.println(String.format(
            "  寄存器: X0=0x%x X1=0x%x X2=0x%x X3=0x%x LR=0x%x",
            x0, x1, x2, x3, lr
        ));
    }

    /**
     * Hook关键分支指令
     */
    private void hookCriticalBranches() {
        // Hook 0x42e08 处的关键检查: (opcode | 8) == 0x28AE
        long checkAddr = module.base + 0x42e08;
        backend.hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                // 读取opcode (应该在某个寄存器中)
                long w8 = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).longValue() & 0xFFFFFFFF;
                long result = w8 | 8;

                System.out.println(String.format(
                    "\n[⚠️ Opcode检查] 0x42e08: opcode=0x%x, (opcode|8)=0x%x",
                    w8, result
                ));

                if (result == 0x28AE) {
                    System.out.println("  ✅ 检查通过! (0x28AE == 0x28AE)");
                } else {
                    System.out.println(String.format(
                        "  ❌ 检查失败! 期望0x28AE, 实际0x%x",
                        result
                    ));
                }
            }

            @Override
            public void onAttach(UnHook unHook) {}

            @Override
            public void detach() {}
        }, checkAddr, checkAddr + 4, null);
    }

    /**
     * 打印对比报告
     */
    public void printReport() {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("📊 执行跟踪报告");
        System.out.println("=".repeat(80));

        // 1. 执行路径统计
        System.out.println("\n[执行路径统计]");
        for (Map.Entry<String, Integer> entry : branchCounter.entrySet()) {
            System.out.println(String.format("  %s: %d次", entry.getKey(), entry.getValue()));
        }

        // 2. 内存状态变化
        System.out.println("\n[关键内存变化]");
        String[] tags = {"INIT", "POINT_0", "POINT_1", "POINT_2", "POINT_3", "POINT_4"};

        for (String tag : tags) {
            Long qword = memorySnapshot.get(tag + "_qword_70910");
            Long byteval = memorySnapshot.get(tag + "_byte_7091F");
            Long dword1 = memorySnapshot.get(tag + "_dword_70C10");
            Long dword2 = memorySnapshot.get(tag + "_dword_70C14");

            if (qword != null) {
                System.out.println(String.format(
                    "\n  [%s]",
                    tag
                ));
                System.out.println(String.format("    qword_70910 = 0x%016x", qword));
                System.out.println(String.format("    byte_7091F  = 0x%02x", byteval));
                System.out.println(String.format("    dword_70C10 = 0x%08x (%d)", dword1, (int)dword1.longValue()));
                System.out.println(String.format("    dword_70C14 = 0x%08x (%d)", dword2, (int)dword2.longValue()));
            }
        }

        // 3. 与真机对比
        System.out.println("\n[与真机数据对比]");
        System.out.println("  真机:");
        System.out.println("    dword_70C10 = 0x00000000 (0)");
        System.out.println("    dword_70C14 = 0x00000000 (0)");

        Long finalDword1 = memorySnapshot.get("POINT_0_dword_70C10");
        Long finalDword2 = memorySnapshot.get("POINT_0_dword_70C14");
        if (finalDword1 != null) {
            System.out.println("\n  unidbg:");
            System.out.println(String.format("    dword_70C10 = 0x%08x (%d)", finalDword1, (int)finalDword1.longValue()));
            System.out.println(String.format("    dword_70C14 = 0x%08x (%d)", finalDword2, (int)finalDword2.longValue()));

            if (finalDword1 == 0 && finalDword2 == 0) {
                System.out.println("\n  ✅ 反调试变量与真机一致!");
            } else {
                System.out.println("\n  ❌ 反调试变量与真机不一致!");
            }
        }

        System.out.println("\n" + "=".repeat(80) + "\n");
    }

    /**
     * 工具方法: 字节数组转long (小端序)
     */
    private long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result |= ((long)(bytes[i] & 0xFF)) << (i * 8);
        }
        return result;
    }

    /**
     * 工具方法: 字节数组转int (小端序,有符号)
     */
    private int bytesToInt(byte[] bytes) {
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (bytes[i] & 0xFF) << (i * 8);
        }
        return result;
    }
}
