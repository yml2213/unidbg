package com.kuaishou.nebula;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import unicorn.Arm64Const;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import com.github.unidbg.linux.android.dvm.array.ArrayObject; // 导入ArrayObject

public class ksjsbTest extends AbstractJni implements IOResolver {
    private static final String SIG_PAYLOAD = "{\"appver\":\"13.8.40.10657\",\"did\":\"ANDROID_191d74724559169d\",\"uid\":\"4435885561\",\"shell_ver\":\"1.0.0.162.39e5b6cc\",\"platform\":\"Android\",\"interpreter_ver\":\"1.7.3.118\",\"appkey\":\"d7b7d042-d4f2-4012-be60-d97ff2429c17\",\"abi\":\"arm64-v8a\",\"kpn\":\"NEBULA\"}";
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Module coreModule;

    // 指令追踪相关
    private boolean enableTrace = false;
    private PrintWriter traceWriter = null;
    private long traceCount = 0;
    private long maxTraceInstructions = 50000; // 最大追踪指令数
    private UnHook instructionHook;

    // 内存监控相关
    private boolean enableMemoryMonitor = false;
    private long monitorStartAddr = 0;
    private long monitorEndAddr = 0;
    private UnHook memoryReadHook;
    private UnHook memoryWriteHook;

    // 注意：移除了使用不存在 API 的初始化方法
    // Context 对象会在 JNI 方法中按需创建

    public ksjsbTest() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.kuaishou.nebula")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();

        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM(new File("apks/ksjsb/ksjsb_13.8.40.10657.apk"));
        vm.setJni(this);
        vm.setVerbose(true);

        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory);

        emulator.getSyscallHandler().addIOResolver(this);

        // 加载libcore.so
        DalvikModule sgDm = vm.loadLibrary("core", true);
        coreModule = sgDm.getModule();
        System.out.println("[*] libcore.so模块加载完成，基地址: 0x" + Long.toHexString(coreModule.base));
        sgDm.callJNI_OnLoad(emulator);

        // 加载libkwsgmain.so
        DalvikModule dm = vm.loadLibrary("kwsgmain", true);
        module = dm.getModule();
        System.out.println("[*] kwsgmain SO模块加载完成，基地址: 0x" + Long.toHexString(module.base));
        System.out.println("[*] kwsgmain SO模块大小: 0x" + Long.toHexString(module.size));

        dm.callJNI_OnLoad(emulator);
        System.out.println("[*] kwsgmain JNI_OnLoad调用完成");
        
        // 方案 A：直接映射 0x9c00 内存区域
        map0x9c00Memory();
    }
    
    
    /**
     * 方案 C：映射 0x9c00 内存区域并返回有效指针
     * 
     * 关键发现（来自方案 B 测试）：
     * 1. 0x9c00 返回值被程序当作指针使用
     * 2. 程序尝试读取返回值指向的内存（address=0x1）
     * 3. 返回整数 1 导致 UC_ERR_READ_UNMAPPED 错误
     * 
     * 解决方案：
     * - 在 0x9800 分配一个数据结构（256 字节）
     * - 0x9c00 函数返回指向该数据结构的指针
     * - 使用 LDR 指令从 PC 相对位置加载地址
     */
    private void map0x9c00Memory() {
        System.out.println("\n[*] ==================== 映射 0x9c00 内存区域（方案C：返回指针）====================");
        
        Backend backend = emulator.getBackend();
        
        try {
            // 1. 计算页对齐的地址
            long pageSize = 0x1000;  // 4KB 页大小
            long baseAddr = 0x9000;   // 0x9c00 所在页的起始地址
            long dataStructAddr = 0x9800; // 数据结构地址（在同一页内）
            
            System.out.println("[*] 页大小: 0x" + Long.toHexString(pageSize));
            System.out.println("[*] 映射基地址: 0x" + Long.toHexString(baseAddr));
            System.out.println("[*] 函数地址: 0x9c00");
            System.out.println("[*] 数据结构地址: 0x" + Long.toHexString(dataStructAddr));
            
            // 2. 映射内存页（读、写、执行权限）
            backend.mem_map(baseAddr, pageSize, unicorn.UnicornConst.UC_PROT_ALL);
            System.out.println("[✓] 内存页映射成功");
            
            // 3. 分配并初始化数据结构（256 字节，全部初始化为 0）
            byte[] dataStruct = new byte[256];
            // 可以在这里初始化一些特定的值，如果需要的话
            // 例如：dataStruct[0] = 1; // 设置某个标志位
            backend.mem_write(dataStructAddr, dataStruct);
            System.out.println("[✓] 数据结构已分配并初始化 @ 0x" + Long.toHexString(dataStructAddr));
            System.out.println("[*] 数据结构大小: " + dataStruct.length + " 字节");
            
            // 4. 在 0x9c00 位置写入 ARM64 汇编代码
            // LDR X0, [PC, #8]  ; 从 PC+8 位置加载 64 位地址到 X0
            // RET               ; 返回到调用者
            // .quad 0x9800      ; 数据结构的地址（64 位）
            byte[] code = {
                (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x58,  // LDR X0, [PC, #8]
                (byte)0xC0, (byte)0x03, (byte)0x5F, (byte)0xD6,  // RET
                // 数据：0x9800 的 64 位地址（小端序）
                (byte)0x00, (byte)0x98, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            };
            
            backend.mem_write(0x9c00, code);
            System.out.println("[✓] 函数代码已写入 0x9c00");
            System.out.println("[*] 指令: LDR X0, [PC, #8]; RET");
            System.out.println("[*] 返回值: 指向 0x" + Long.toHexString(dataStructAddr) + " 的指针");
            
            // 5. 验证写入
            byte[] verify = backend.mem_read(0x9c00, code.length);
            boolean success = java.util.Arrays.equals(code, verify);
            
            if (success) {
                System.out.println("[✓] 代码验证成功！");
                System.out.println("[✓] 0x9c00 内存区域已准备就绪");
            } else {
                System.out.println("[✗] 代码验证失败！");
            }
            
            // 6. 添加 Hook 拦截 0x9c00 的调用（方案3）
            setupHook0x9c00();
            
            // 7. Hook fopen 函数（地址 module.base + 0x9c30）
            setupHookFopen();
            
            System.out.println("[*] ========================================================\n");
            
        } catch (Exception e) {
            System.err.println("[!] 映射 0x9c00 内存失败: " + e.getMessage());
            e.printStackTrace();
            System.err.println("\n[!] 可能的原因：");
            System.err.println("[!]   1. 内存地址冲突");
            System.err.println("[!]   2. 权限不足");
            System.err.println("[!]   3. 页大小不正确");
        }
    }
    
    /**
     * Hook 0x9c00 地址，拦截调用并直接返回
     * 
     * 方案 3：Hook 拦截
     * - 拦截 0x9c00 的调用
     * - 直接设置返回值并跳过原始代码
     * - 避免无限循环
     */
    private void setupHook0x9c00() {
        System.out.println("[*] 设置 0x9c00 拦截 Hook（方案3）...");
        
        emulator.getBackend().hook_add_new(new CodeHook() {
            private int callCount = 0;
            
            @Override
            public void onAttach(UnHook unHook) {
                // 实现 Detachable 接口要求的方法
            }
            
            @Override
            public void detach() {
                // 实现 Detachable 接口要求的方法
            }
            
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address == 0x9c00) {
                    callCount++;
                    System.out.println("\n[Hook 0x9c00] ========== 第 " + callCount + " 次调用 ==========");
                    RegisterContext ctx = emulator.getContext();
                    
                    // 打印参数寄存器
                    long x0 = ctx.getLongArg(0);
                    long x1 = ctx.getLongArg(1);
                    long x2 = ctx.getLongArg(2);
                    
                    System.out.println("[Hook 0x9c00] X0 = 0x" + Long.toHexString(x0) + " (输入缓冲区?)");
                    System.out.println("[Hook 0x9c00] X1 = 0x" + Long.toHexString(x1));
                    System.out.println("[Hook 0x9c00] X2 = 0x" + Long.toHexString(x2));
                    
                    // 打印调用栈
                    long lr = ctx.getLRPointer().peer;
                    System.out.println("[Hook 0x9c00] LR = 0x" + Long.toHexString(lr) + " (返回地址)");
                    
                    // 尝试填充 X0 指向的缓冲区（如果 X0 是有效地址）
                    if (x0 != 0 && x0 > 0x1000) {
                        try {
                            // 填充一些测试数据
                            byte[] testData = new byte[64];
                            testData[0] = 0x01; // 标志位
                            backend.mem_write(x0, testData);
                            System.out.println("[Hook 0x9c00] 已填充 X0 指向的缓冲区");
                        } catch (Exception e) {
                            System.out.println("[Hook 0x9c00] 无法写入 X0 地址: " + e.getMessage());
                        }
                    }
                    
                    // 设置返回值为 0（成功状态码）
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0L);
                    System.out.println("[Hook 0x9c00] 设置返回值 X0 = 0 (成功)");
                    
                    // 直接返回到调用者，跳过原始代码执行
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, lr);
                    System.out.println("[Hook 0x9c00] 已拦截并返回到 0x" + Long.toHexString(lr));
                    System.out.println("[Hook 0x9c00] ========== Hook 完成 ==========\n");
                }
            }
        }, 0x9c00, 0x9c00 + 4, null);
        
        System.out.println("[✓] 0x9c00 拦截 Hook 设置完成（将直接返回，不执行原始代码）");
    }
    
    /**
     * Hook fopen 函数，拦截文件打开操作
     */
    private void setupHookFopen() {
        System.out.println("[*] 设置 fopen Hook...");
        
        long fopenAddr = module.base + 0x9c30; // fopen PLT 地址
        
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void onAttach(UnHook unHook) {
                // 实现 Detachable 接口要求的方法
            }
            
            @Override
            public void detach() {
                // 实现 Detachable 接口要求的方法
            }
            
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address == fopenAddr) {
                    System.out.println("\n[Hook fopen] ========== 被调用 ==========");
                    RegisterContext ctx = emulator.getContext();
                    
                    long x0 = ctx.getLongArg(0); // filename
                    long x1 = ctx.getLongArg(1); // mode
                    
                    try {
                        // 读取文件名
                        byte[] filenameBytes = backend.mem_read(x0, 256);
                        int nullIndex = 0;
                        for (int i = 0; i < filenameBytes.length; i++) {
                            if (filenameBytes[i] == 0) {
                                nullIndex = i;
                                break;
                            }
                        }
                        String filename = new String(filenameBytes, 0, nullIndex, StandardCharsets.UTF_8);
                        
                        // 读取模式
                        byte[] modeBytes = backend.mem_read(x1, 16);
                        nullIndex = 0;
                        for (int i = 0; i < modeBytes.length; i++) {
                            if (modeBytes[i] == 0) {
                                nullIndex = i;
                                break;
                            }
                        }
                        String mode = new String(modeBytes, 0, nullIndex, StandardCharsets.UTF_8);
                        
                        System.out.println("[Hook fopen] 文件名: " + filename);
                        System.out.println("[Hook fopen] 模式: " + mode);
                        
                    } catch (Exception e) {
                        System.out.println("[Hook fopen] 无法读取参数: " + e.getMessage());
                    }
                    
                    System.out.println("[Hook fopen] ========== Hook 完成 ==========\n");
                }
            }
        }, fopenAddr, fopenAddr + 4, null);
        
        System.out.println("[✓] fopen Hook 设置完成 @ 0x" + Long.toHexString(fopenAddr));
    }
    
    // 移除旧的 Hook 代码
    private void oldHookCode() {
        // Hook 0x9c00 地址（方案B：实现0x9c00 Hook）
        // 尝试Hook绝对地址0x9c00（根据错误信息）
        System.out.println("[*] 正在设置 0x9c00 Hook...");
        System.out.println("[*] Hook地址1: 0x9c00 (绝对地址)");
        System.out.println("[*] Hook地址2: 0x" + Long.toHexString(module.base + 0x9c00) + " (相对地址)");
        
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void onAttach(UnHook unHook) {
                // 实现 Detachable 接口要求的方法
            }
            
            @Override
            public void detach() {
                // 实现 Detachable 接口要求的方法
            }
            
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                // 检查是否是0x9c00（绝对地址）或 module.base + 0x9c00（相对地址）
                if (address == 0x9c00 || address == module.base + 0x9c00) {
                    System.out.println("\n[Hook 0x9c00] ========== 被调用 ==========");
                    System.out.println("[Hook 0x9c00] 触发地址: 0x" + Long.toHexString(address));
                    RegisterContext ctx = emulator.getContext();
                    
                    // 打印所有参数寄存器
                    long x0 = ctx.getLongArg(0);
                    long x1 = ctx.getLongArg(1);
                    long x2 = ctx.getLongArg(2);
                    long x3 = ctx.getLongArg(3);
                    long x4 = ctx.getLongArg(4);
                    long x5 = ctx.getLongArg(5);
                    
                    System.out.println("[Hook 0x9c00] X0 = 0x" + Long.toHexString(x0));
                    System.out.println("[Hook 0x9c00] X1 = 0x" + Long.toHexString(x1));
                    System.out.println("[Hook 0x9c00] X2 = 0x" + Long.toHexString(x2));
                    System.out.println("[Hook 0x9c00] X3 = 0x" + Long.toHexString(x3));
                    System.out.println("[Hook 0x9c00] X4 = 0x" + Long.toHexString(x4));
                    System.out.println("[Hook 0x9c00] X5 = 0x" + Long.toHexString(x5));
                    
                    // 打印调用栈
                    long lr = ctx.getLRPointer().peer;
                    long sp = ctx.getStackPointer().peer;
                    System.out.println("[Hook 0x9c00] LR = 0x" + Long.toHexString(lr) + " (返回地址)");
                    System.out.println("[Hook 0x9c00] SP = 0x" + Long.toHexString(sp));
                    
                    // 尝试读取参数指向的内存
                    if (x0 != 0) {
                        try {
                            byte[] data = backend.mem_read(x0, 64);
                            System.out.println("[Hook 0x9c00] X0 指向的数据 (前64字节):");
                            StringBuilder hex = new StringBuilder();
                            for (int i = 0; i < Math.min(data.length, 64); i++) {
                                hex.append(String.format("%02x ", data[i] & 0xFF));
                                if ((i + 1) % 16 == 0) {
                                    System.out.println("[Hook 0x9c00]   " + hex.toString());
                                    hex.setLength(0);
                                }
                            }
                            if (hex.length() > 0) {
                                System.out.println("[Hook 0x9c00]   " + hex.toString());
                            }
                        } catch (Exception e) {
                            System.out.println("[Hook 0x9c00] X0 不是有效指针或无法读取");
                        }
                    }
                    
                    // 返回成功（假设返回0表示成功）
                    System.out.println("[Hook 0x9c00] 返回值设置为 0 (成功)");
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0L);
                    
                    // 直接返回到调用者
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, lr);
                    System.out.println("[Hook 0x9c00] ========== Hook 完成 ==========\n");
                }
            }
        }, 0x9c00, module.base + 0x9c00 + 4, null);
        System.out.println("[*] 0x9c00 Hook 设置完成 (范围: 0x9c00 到 0x" + Long.toHexString(module.base + 0x9c00 + 4) + ")");
    }

    /**
     * ==================== 指令级追踪功能 ====================
     * 追踪从指定地址开始的所有执行指令
     */
    public void enableInstructionTrace(String outputFile) {
        try {
            traceWriter = new PrintWriter(outputFile, "UTF-8");
            traceWriter.println("=== doCommandNative 指令追踪日志 ===");
            traceWriter.println("模块基地址: 0x" + Long.toHexString(module.base));
            traceWriter.println("追踪开始时间: " + System.currentTimeMillis());
            traceWriter.println("========================================\n");
            enableTrace = true;
            traceCount = 0;

            System.out.println("[*] 指令追踪已启用，输出文件: " + outputFile);
            System.out.println("[*] 最大追踪指令数: " + maxTraceInstructions);
        } catch (Exception e) {
            System.err.println("[!] 启用指令追踪失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void disableInstructionTrace() {
        enableTrace = false;
        if (instructionHook != null) {
            instructionHook.unhook();
            instructionHook = null;
        }
        if (traceWriter != null) {
            traceWriter.println("\n========================================");
            traceWriter.println("追踪结束时间: " + System.currentTimeMillis());
            traceWriter.println("总共追踪指令数: " + traceCount);
            traceWriter.close();
            traceWriter = null;
        }
        System.out.println("[*] 指令追踪已关闭，共追踪 " + traceCount + " 条指令");
    }

    /**
     * 设置指令追踪的hook
     */
    private void setupInstructionHook() {
        if (!enableTrace) {
            return;
        }

        if (instructionHook != null) {
            instructionHook.unhook();
            instructionHook = null;
        }

        Backend backend = emulator.getBackend();

        try {
            backend.hook_add_new(new CodeHook() {
                @Override
                public void onAttach(UnHook unHook) {
                    instructionHook = unHook;
                }

                @Override
                public void detach() {
                    // no-op
                }

                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    if (!enableTrace || traceWriter == null) {
                        return;
                    }

                    if (traceCount >= maxTraceInstructions) {
                        if (traceCount == maxTraceInstructions) {
                            traceWriter.println("\n[!] 达到最大追踪指令数限制，停止追踪");
                            traceWriter.flush();
                            System.out.println("[!] 达到最大追踪指令数限制: " + maxTraceInstructions);
                        }
                        return;
                    }

                    if (address < module.base || address >= module.base + module.size) {
                        return;
                    }

                    try {
                        byte[] insn = backend.mem_read(address, size);
                        StringBuilder insnHex = new StringBuilder(insn.length * 2);
                        for (byte b : insn) {
                            insnHex.append(String.format("%02x", b & 0xFF));
                        }

                        RegisterContext ctx = emulator.getContext();
                        long x0 = ctx != null ? ctx.getLongArg(0) : 0L;
                        long x1 = ctx != null ? ctx.getLongArg(1) : 0L;
                        long x2 = ctx != null ? ctx.getLongArg(2) : 0L;
                        long x22 = ctx != null ? ctx.getLongArg(22) : 0L; // 添加X22寄存器
                        long sp = (ctx != null && ctx.getStackPointer() != null) ? ctx.getStackPointer().peer : 0L;
                        long lr = (ctx != null && ctx.getLRPointer() != null) ? ctx.getLRPointer().peer : 0L;

                        String logLine = String.format(
                                "[%06d] 0x%016x (+0x%x): %s | X0=0x%016x X1=0x%016x X2=0x%016x X22=0x%016x SP=0x%016x LR=0x%016x",
                                traceCount,
                                address,
                                address - module.base,
                                insnHex.toString(),
                                x0, x1, x2, x22, sp, lr
                        );

                        traceWriter.println(logLine);
                        traceCount++;

                        if (traceCount % 100 == 0) {
                            traceWriter.flush();
                            if (traceCount % 1000 == 0) {
                                System.out.println("[*] 已追踪 " + traceCount + " 条指令...");
                            }
                        }
                    } catch (Exception e) {
                        traceWriter.println("[!] 指令追踪异常: " + e.getMessage());
                        traceWriter.flush();
                    }
                }
            }, module.base, module.base + module.size, null);

            System.out.println("[*] 指令追踪hook已设置");
        } catch (BackendException e) {
            System.err.println("[!] 设置指令追踪hook失败: " + e.getMessage());
        }
    }

    /**
     * ==================== 内存监控功能 ====================
     * 监控指定内存范围的读写访问
     */
    public void enableMemoryMonitor(long startAddr, long endAddr) {
        this.monitorStartAddr = startAddr;
        this.monitorEndAddr = endAddr;
        this.enableMemoryMonitor = true;

        System.out.println("[*] 内存监控已启用");
        System.out.println("[*] 监控范围: 0x" + Long.toHexString(startAddr) + " - 0x" + Long.toHexString(endAddr));

        setupMemoryHook();
    }

    public void disableMemoryMonitor() {
        enableMemoryMonitor = false;
        if (memoryReadHook != null) {
            memoryReadHook.unhook();
            memoryReadHook = null;
        }
        if (memoryWriteHook != null) {
            memoryWriteHook.unhook();
            memoryWriteHook = null;
        }
        System.out.println("[*] 内存监控已关闭");
    }

    /**
     * 设置内存访问监控hook
     */
    private void setupMemoryHook() {
        if (!enableMemoryMonitor) {
            return;
        }

        if (memoryReadHook != null) {
            memoryReadHook.unhook();
            memoryReadHook = null;
        }
        if (memoryWriteHook != null) {
            memoryWriteHook.unhook();
            memoryWriteHook = null;
        }

        Backend backend = emulator.getBackend();

        try {
            backend.hook_add_new(new ReadHook() {
                @Override
                public void onAttach(UnHook unHook) {
                    memoryReadHook = unHook;
                }

                @Override
                public void detach() {
                    // no-op
                }

                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    if (!enableMemoryMonitor) {
                        return;
                    }
                    RegisterContext ctx = emulator.getContext();
                    long pc = (ctx != null && ctx.getPCPointer() != null) ? ctx.getPCPointer().peer : 0L;
                    System.out.println(String.format("[MEM-READ] addr=0x%016x size=%d PC=0x%016x", address, size, pc));
                }
            }, monitorStartAddr, monitorEndAddr, null);

            backend.hook_add_new(new WriteHook() {
                @Override
                public void onAttach(UnHook unHook) {
                    memoryWriteHook = unHook;
                }

                @Override
                public void detach() {
                    // no-op
                }

                @Override
                public void hook(Backend backend, long address, int size, long value, Object user) {
                    if (!enableMemoryMonitor) {
                        return;
                    }
                    RegisterContext ctx = emulator.getContext();
                    long pc = (ctx != null && ctx.getPCPointer() != null) ? ctx.getPCPointer().peer : 0L;
                    System.out.println(String.format("[MEM-WRITE] addr=0x%016x size=%d value=0x%016x PC=0x%016x",
                            address, size, value, pc));
                }
            }, monitorStartAddr, monitorEndAddr, null);

            System.out.println("[*] 内存监控hook已设置");
        } catch (BackendException e) {
            System.err.println("[!] 内存监控hook设置失败: " + e.getMessage());
        }
    }

    /**
     * 读取并打印内存内容
     */
    public void dumpMemory(long address, int size, String description) {
        System.out.println("\n[*] ========== 内存转储: " + description + " ==========");
        System.out.println("[*] 地址: 0x" + Long.toHexString(address) + ", 大小: " + size + " 字节");

        try {
            byte[] data = emulator.getBackend().mem_read(address, size);

            // 十六进制显示
            StringBuilder hexLine = new StringBuilder();
            StringBuilder asciiLine = new StringBuilder();
            long lineStart = address;

            for (int i = 0; i < data.length; i++) {
                if (i % 16 == 0) {
                    if (i > 0) {
                        System.out.println(String.format("0x%08x: %-48s | %s",
                                lineStart, hexLine.toString(), asciiLine.toString()));
                        hexLine.setLength(0);
                        asciiLine.setLength(0);
                    }
                    lineStart = address + i;
                }

                hexLine.append(String.format("%02x ", data[i] & 0xFF));

                // ASCII显示
                char c = (char) (data[i] & 0xFF);
                if (c >= 32 && c <= 126) {
                    asciiLine.append(c);
                } else {
                    asciiLine.append('.');
                }
            }

            // 打印最后一行
            if (hexLine.length() > 0) {
                System.out.println(String.format("0x%08x: %-48s | %s",
                        lineStart, hexLine.toString(), asciiLine.toString()));
            }

            System.out.println("[*] ==========================================\n");

        } catch (Exception e) {
            System.err.println("[!] 内存读取失败: " + e.getMessage());
        }
    }

    /**
     * ==================== 增强的doCommandNative调用 ====================
     * 带有完整追踪和监控的版本
     */
    public void callDoCommandNativeWithTrace() {
        System.out.println("\n[*] ==================== 开始追踪doCommandNative ====================");

        // 1. 启用指令追踪
//        enableInstructionTrace("doCommandNative_trace.txt");

        // 2. 启用内存监控 (监控0x40CD4到0x40D30范围)
        long targetAddr = module.base + 0x40CD4;
        enableMemoryMonitor(targetAddr, targetAddr + 0x60);

        // 3. 在调用前转储内存
        System.out.println("\n[*] === 调用前内存状态 ===");
        dumpMemory(module.base + 0x40CD4, 0x60, "doCommandNative入口区域");
        dumpMemory(module.base + 0x40D0C, 0x100, "0x40D0C区域 (可能的真实实现)");

        // 4. 设置断点
        setupBreakpoints();

        // 5. 设置指令追踪hook
        setupInstructionHook();

        // 6. 执行doCommandNative调用
        System.out.println("\n[*] === 开始执行doCommandNative ===");
        callByAddress(); // 调用原有的实现

        // 7. 关闭追踪
        disableInstructionTrace();
        disableMemoryMonitor();

        System.out.println("\n[*] ==================== 追踪完成 ====================");
        System.out.println("[*] 请查看以下文件分析结果：");
        System.out.println("[*]   - doCommandNative_trace.txt (指令追踪日志)");
    }

    /**
     * 设置关键位置的断点
     */
    private void setupBreakpoints() {
        System.out.println("\n[*] === 设置断点 ===");

        // 断点1: doCommandNative入口 (0x40CD4)
        long bp1 = module.base + 0x40CD4;
        emulator.attach().addBreakPoint(bp1, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                System.out.println("\n[BP1] 命中断点 @ 0x" + Long.toHexString(address) + " (doCommandNative入口)");
                RegisterContext ctx = emulator.getContext();
                System.out.println("[BP1] X0 (JNIEnv*) = 0x" + Long.toHexString(ctx.getLongArg(0)));
                System.out.println("[BP1] X1 (jclass) = 0x" + Long.toHexString(ctx.getLongArg(1)));
                System.out.println("[BP1] X2 (参数) = 0x" + Long.toHexString(ctx.getLongArg(2)));
                System.out.println("[BP1] LR = 0x" + Long.toHexString(ctx.getLRPointer().peer));
                return true; // 继续执行
            }
        });
        System.out.println("[*] 断点1已设置 @ 0x" + Long.toHexString(bp1) + " (入口)");

        // 断点2: BR X9指令 (0x40CF8)
        long bp2 = module.base + 0x40CF8;
        emulator.attach().addBreakPoint(bp2, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                System.out.println("\n[BP2] 命中断点 @ 0x" + Long.toHexString(address) + " (BR X9 - 返回前)");
                RegisterContext ctx = emulator.getContext();
                long x9 = ctx.getLongArg(9);
                System.out.println("[BP2] X9 (跳转目标) = 0x" + Long.toHexString(x9));
                System.out.println("[BP2] 这应该是LR，即返回地址");

                // 检查栈上的数据
                long sp = ctx.getStackPointer().peer;
                System.out.println("[BP2] SP = 0x" + Long.toHexString(sp));
                dumpMemory(sp, 0x20, "栈数据");

                return true;
            }
        });
        System.out.println("[*] 断点2已设置 @ 0x" + Long.toHexString(bp2) + " (BR X9)");

        // 断点3: 0x40D0C (可疑的真实实现位置)
        long bp3 = module.base + 0x40D0C;
        emulator.attach().addBreakPoint(bp3, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                System.out.println("\n[BP3] ⚠️ 命中断点 @ 0x" + Long.toHexString(address) + " (0x40D0C - 真实实现？)");
                System.out.println("[BP3] ⚠️ 这个位置被执行了！静态分析是错误的！");
                RegisterContext ctx = emulator.getContext();
                System.out.println("[BP3] X0 = 0x" + Long.toHexString(ctx.getLongArg(0)));
                System.out.println("[BP3] X1 = 0x" + Long.toHexString(ctx.getLongArg(1)));
                System.out.println("[BP3] X2 = 0x" + Long.toHexString(ctx.getLongArg(2)));
                System.out.println("[BP3] LR = 0x" + Long.toHexString(ctx.getLRPointer().peer));
                return true;
            }
        });
        System.out.println("[*] 断点3已设置 @ 0x" + Long.toHexString(bp3) + " (0x40D0C)");

        // 断点4: NullPointerException发生位置 (0x40DA8)
        long bp4 = module.base + 0x40DA8;
        emulator.attach().addBreakPoint(bp4, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                System.out.println("\n[BP4] ⚠️ 命中断点 @ 0x" + Long.toHexString(address) + " (NullPointerException发生位置)");
                RegisterContext ctx = emulator.getContext();
                System.out.println("[BP4] X0 = 0x" + Long.toHexString(ctx.getLongArg(0)));
                System.out.println("[BP4] X1 = 0x" + Long.toHexString(ctx.getLongArg(1)));
                System.out.println("[BP4] X2 = 0x" + Long.toHexString(ctx.getLongArg(2)));
                System.out.println("[BP4] X22 = 0x" + Long.toHexString(ctx.getLongArg(22)));
                System.out.println("[BP4] LR = 0x" + Long.toHexString(ctx.getLRPointer().peer));
                return true;
            }
        });
        System.out.println("[*] 断点4已设置 @ 0x" + Long.toHexString(bp4) + " (NullPointerException发生位置)");

        System.out.println("[*] 所有断点设置完成\n");
    }

    /**
     * ==================== 原始调用方法 ====================
     * 通过地址直接调用doCommandNative
     */
    public void callByAddress() {
        long targetOffset = 0x40CD4; // doCommandNative的偏移地址

        System.out.println("[*] 准备调用doCommandNative @ 0x" + Long.toHexString(module.base + targetOffset));
        System.out.println("[*] 当前JNIEnv* (vm.getJNIEnv()) = " + vm.getJNIEnv());

        // 准备参数
        List<Object> args = new ArrayList<>();
        args.add(vm.getJNIEnv()); // 第一个参数是env
        
        // 第二个参数：实例方法是jobject，静态方法是jclass
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        args.add(vm.addLocalObject(thiz));
        
        args.add(10412); // opcode参数
        
        // 创建参数数组
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        vm.addLocalObject(context);
        
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        
        DvmInteger integerObj = DvmInteger.valueOf(vm, 0);
        vm.addLocalObject(integerObj);
        
        // 构造参数数组：[appkey, null, null, null, context, null, null]
        ArrayObject arrayObject = new ArrayObject(null, appkey, null, null, context, null, null);
        args.add(vm.addLocalObject(arrayObject)); // jobjectArray

        // 调用Native函数 - 使用偏移地址
        Number ret = module.callFunction(emulator, targetOffset, args.toArray());

        System.out.println("[*] doCommandNative返回值: 0x" + Long.toHexString(ret.longValue()));
        
        // 尝试获取返回的对象
        if (ret.intValue() != 0 && ret.intValue() != -1) {
            try {
                DvmObject<?> resultObject = vm.getObject(ret.intValue());
                if (resultObject != null) {
                    Object result = resultObject.getValue();
                    System.out.println("[*] doCommandNative返回对象: " + result);
                }
            } catch (Exception e) {
                System.out.println("[!] 获取返回对象失败: " + e.getMessage());
            }
        }
    }

    /**
     * ==================== IOResolver实现 ====================
     */
    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        System.out.println("[IOResolver] 请求打开文件: " + pathname);
        
        if ("/proc/self/cmdline".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                    "com.kuaishou.nebula".getBytes(StandardCharsets.UTF_8)));
        }
        
        // 处理 APK 文件访问
        if (pathname != null && pathname.contains("/base.apk")) {
            System.out.println("[IOResolver] 拦截 APK 文件访问，重定向到本地文件");
            File apkFile = new File("apks/ksjsb/ksjsb_13.8.40.10657.apk");
            if (apkFile.exists()) {
                System.out.println("[IOResolver] ✓ APK 文件存在: " + apkFile.getAbsolutePath());
                System.out.println("[IOResolver] ✓ APK 文件大小: " + apkFile.length() + " 字节");
                try {
                    // 使用 SimpleFileIO 包装 File 对象
                    return FileResult.success(new SimpleFileIO(oflags, apkFile, pathname));
                } catch (Exception e) {
                    System.out.println("[IOResolver] ✗ 创建 SimpleFileIO 失败: " + e.getMessage());
                    e.printStackTrace();
                }
            } else {
                System.out.println("[IOResolver] ✗ APK 文件不存在: " + apkFile.getAbsolutePath());
            }
        }
        
        return null;
    }

    /**
     * ==================== JNI方法实现 ====================
     */
    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("com/kuaishou/android/security/internal/common/AppContextHolder->a:Landroid/content/Context;".equals(signature)) {
            System.out.println("[Context] 返回 Application Context");
            return vm.resolveClass("android/content/Context").newObject(null);
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if ("android/os/Environment->getExternalStorageDirectory()Ljava/io/File;".equals(signature)) {
            return vm.resolveClass("java/io/File").newObject(new File("/sdcard"));
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "com/yxcorp/gifshow/App->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                return new StringObject(vm, packageName);
            }
            case "com/yxcorp/gifshow/App->getPackageManager()Landroid/content/pm/PackageManager;": {
//                DvmClass clazz = vm.resolveClass("android/content/pm/PackageManager");
//                return clazz.newObject(signature);
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            }
            case "com/yxcorp/gifshow/App->getPackageCodePath()Ljava/lang/String;": {
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");
            }
            case "com/yxcorp/gifshow/App->getAssets()Landroid/content/res/AssetManager;": {
                return new AssetManager(vm, signature);
            }
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;": {
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");
            }
            case "android/content/Context->getAssets()Landroid/content/res/AssetManager;": {
                return new AssetManager(vm, signature);
            }

        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->getProcessName(Landroid/content/Context;)Ljava/lang/String;": {
                return new StringObject(vm, "com.kuaishou.nebula");
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }
    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("java/io/File->getAbsolutePath()Ljava/lang/String;".equals(signature)) {
            File file = (File) dvmObject.getValue();
            return new StringObject(vm, file.getAbsolutePath());
        }
        if ("android/content/Context->getFilesDir()Ljava/io/File;".equals(signature)) {
            return vm.resolveClass("java/io/File").newObject(new File("/data/user/0/com.kuaishou.nebula/files"));
        }
        if ("android/content/Context->getAssets()Landroid/content/res/AssetManager;".equals(signature)) {
            return new AssetManager(vm,"");
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if ("com/kuaishou/android/security/utility/EnvironmentChecker->a()Z".equals(signature)) {
            return false; // 不是root环境
        }
        return super.callStaticBooleanMethod(vm, dvmClass, signature, varArg);
    }
    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        System.out.println("callBooleanMethodV: " + signature);
        switch (signature) {
            case "java/lang/Boolean->booleanValue()Z":
                DvmBoolean dvmBoolean = (DvmBoolean) dvmObject;
                return dvmBoolean.getValue();
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }


    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V": {
                System.out.println("触发了---1:  com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V");
                return;
            }
        }
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    /**
     * ==================== sig3 签名生成方法 ====================
     * 注意：此方法必须在调用 callByAddress() (opcode 10412) 初始化之后才能使用
     */
    public String get_NS_sig3() {
        System.out.println("\n[*] ==================== 开始生成 sig3 签名 ====================");
        
        // ⚠️ 重要：必须先调用 opcode 10412 进行初始化
        System.out.println("[*] 步骤1: 调用 opcode 10412 进行初始化...");
        callByAddress(); // 初始化调用
        System.out.println("[*] 初始化完成");
        
        System.out.println("[*] 步骤2: 开始构造 sig3 签名参数...");
        
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第二个参数，实例方法是jobject
        
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null); // context
        vm.addLocalObject(context);
        
        list.add(10418); // opcode 参数 - sig3 生成
        
        // 创建 payload 字符串数组
        StringObject payloadObj = new StringObject(vm, SIG_PAYLOAD);
        vm.addLocalObject(payloadObj);
        ArrayObject arrayObject = new ArrayObject(payloadObj);
        vm.addLocalObject(arrayObject);
        System.out.println("[*] 创建了字符串数组对象");
        
        // 创建其他参数
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        
        DvmInteger integerObj = DvmInteger.valueOf(vm, -1);
        vm.addLocalObject(integerObj);
        
        DvmBoolean boolObj = DvmBoolean.valueOf(vm, false);
        vm.addLocalObject(boolObj);
        
        DvmBoolean boolObjTrue = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolObjTrue);
        
        StringObject appkey2 = new StringObject(vm, "010a11c6-f2cb-4016-887d-0d958aef1534");
        vm.addLocalObject(appkey2);
        
        // 构造参数数组：[arrayObject, appkey, integerObj, boolObj, context, null, boolObj, null]
        list.add(vm.addLocalObject(new ArrayObject(arrayObject, appkey, integerObj, boolObj, context, null, boolObj, null)));
        
        System.out.println("[*] 参数构造完成，准备调用函数 sig3...");
        System.out.println("[*] 参数列表大小: " + list.size());
        
        try {
            System.out.println("[*] 正在调用函数地址: 0x" + Long.toHexString(0x40cd4));
            System.out.println("[*] 模块基地址: 0x" + Long.toHexString(module.base));
            
            Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
            System.out.println("[*] 函数执行完成，返回值: 0x" + Long.toHexString(numbers.intValue()));
            
            if (numbers.intValue() == -1 || numbers.intValue() == 0) {
                System.err.println("[!] 函数调用失败，返回值为: " + numbers.intValue());
                return null;
            }
            
            DvmObject<?> object = vm.getObject(numbers.intValue());
            if (object == null) {
                System.out.println("[!] 获取返回对象失败");
                return null;
            }
            
            String result = (String) object.getValue();
            System.out.println("[*] sig3 签名结果: " + result);
            return result;
            
        } catch (Exception e) {
            System.err.println("[!] 函数调用发生异常: " + e.getMessage());
            e.printStackTrace();
            
            if (e.getMessage() != null && e.getMessage().contains("UC_ERR_FETCH_UNMAPPED")) {
                System.err.println("[!] 内存访问错误 - 可能需要额外的内存映射或初始化");
            }
            return null;
        }
    }

    /**
     * ==================== sign_64 签名生成方法 ====================
     * 注意：此方法必须在调用 callByAddress() (opcode 10412) 初始化之后才能使用
     */
    public String sign_64() {
        System.out.println("\n[*] ==================== 开始生成 sign_64 签名 ====================");
        
        // ⚠️ 重要：必须先调用 opcode 10412 进行初始化
        System.out.println("[*] 步骤1: 调用 opcode 10412 进行初始化...");
        callByAddress(); // 初始化调用
        System.out.println("[*] 初始化完成");
        
        System.out.println("[*] 步骤2: 开始构造 sign_64 签名参数...");
        
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第二个参数，实例方法是jobject
        
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null); // context
        vm.addLocalObject(context);
        
        list.add(10418); // opcode 参数 - sign_64 生成
        
        // 创建 payload 字符串数组
        StringObject payloadObj = new StringObject(vm, SIG_PAYLOAD);
        vm.addLocalObject(payloadObj);
        ArrayObject arrayObject = new ArrayObject(payloadObj);
        vm.addLocalObject(arrayObject);
        System.out.println("[*] 创建了字符串数组对象");
        
        // 创建其他参数
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        
        DvmInteger integerObj = DvmInteger.valueOf(vm, -1);
        vm.addLocalObject(integerObj);
        
        DvmBoolean boolObj = DvmBoolean.valueOf(vm, false);
        vm.addLocalObject(boolObj);
        
        // ✅ 启用UUID参数（必需！禁用UUID只能生成48位签名）
        // 测试结果：param[6]=false 只生成48位签名，必须使用UUID才能生成64位签名
        DvmBoolean boolObjTrue = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolObjTrue);
        
        StringObject uuidObj = new StringObject(vm, "010a11c6-f2cb-4016-887d-0d958aef1534");
        vm.addLocalObject(uuidObj);
        
        // 参数数组：[arrayObject, appkey, integerObj, boolObj, context, null, boolObjTrue, uuidObj]
        //           param[0]     param[1] param[2]   param[3] param[4] param[5] param[6]     param[7]
        //                                            ↓ false           ↓ null   ↓ true       ↓ UUID
        // param[3]=false: 不使用64位特殊模式
        // param[6]=true:  启用UUID功能（必需！会触发0x9c00调用）
        // param[7]=UUID:  UUID字符串
        list.add(vm.addLocalObject(new ArrayObject(arrayObject, appkey, integerObj, boolObj, context, null, boolObjTrue, uuidObj)));
        
        System.out.println("[*] 参数构造完成，准备调用函数 sign_64...");
        System.out.println("[*] 参数列表大小: " + list.size());
        System.out.println("[*] param3(64位标志): false");
        System.out.println("[*] param6(UUID标志): true (必需！禁用只生成48位)");
        System.out.println("[*] param7(UUID值): 010a11c6-f2cb-4016-887d-0d958aef1534");
        
        try {
            System.out.println("[*] 正在调用函数地址: 0x" + Long.toHexString(0x40cd4));
            System.out.println("[*] 模块基地址: 0x" + Long.toHexString(module.base));
            
            Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
            System.out.println("[*] 函数执行完成，返回值: 0x" + Long.toHexString(numbers.intValue()));
            
            if (numbers.intValue() == -1 || numbers.intValue() == 0) {
                System.err.println("[!] 函数调用失败，返回值为: " + numbers.intValue());
                System.err.println("[!] 错误原因:");
                System.err.println("[!]   - 可能是UUID未初始化或无效");
                System.err.println("[!]   - 可能需要先调用某个初始化函数");
                System.err.println("[!]   - 可能是环境检测失败(错误码: 0x111e5)");
                return null;
            }
            
            DvmObject<?> object = vm.getObject(numbers.intValue());
            if (object == null) {
                System.out.println("[!] 获取返回对象失败");
                return null;
            }
            
            String result = (String) object.getValue();
            System.out.println("[*] ========== sign_64 结果 ==========");
            System.out.println("[*] 64位签名: " + result);
            System.out.println("[*] 签名长度: " + (result != null ? result.length() : 0));
            System.out.println("[*] ====================================");
            return result;
            
        } catch (Exception e) {
            System.err.println("[!] 函数调用发生异常: " + e.getMessage());
            e.printStackTrace();
            
            if (e.getMessage() != null && e.getMessage().contains("UC_ERR_FETCH_UNMAPPED")) {
                System.err.println("[!] 内存访问错误 - 可能需要额外的内存映射或初始化");
            }
            return null;
        }
    }

    /**
     * ==================== JUnit 测试方法 ====================
     */
    @Test // 添加JUnit Test注解
    public void testDoCommandNativeTrace() { // 将main方法改为测试方法
        System.out.println("\n====================================================");
        System.out.println("  libkwsgmain.so doCommandNative 完整追踪分析");
        System.out.println("====================================================\n");

        // 执行带完整追踪的调用
        callDoCommandNativeWithTrace(); // 直接调用本类方法

        System.out.println("\n====================================================");
        System.out.println("  分析完成！");
        System.out.println("====================================================");
    }
    
    @Test
    public void testGetNS_sig3() {
        System.out.println("\n====================================================");
        System.out.println("  测试 sig3 签名生成");
        System.out.println("====================================================\n");
        
        String sig3 = get_NS_sig3();
        
        if (sig3 != null) {
            System.out.println("\n[✓] sig3 签名生成成功！");
            System.out.println("[✓] 签名值: " + sig3);
        } else {
            System.out.println("\n[✗] sig3 签名生成失败");
        }
        
        System.out.println("\n====================================================");
        System.out.println("  测试完成！");
        System.out.println("====================================================");
    }
    
    @Test
    public void testSign64() {
        System.out.println("\n====================================================");
        System.out.println("  测试 sign_64 签名生成");
        System.out.println("====================================================\n");
        
        String sign64 = sign_64();
        
        if (sign64 != null) {
            System.out.println("\n[✓] sign_64 签名生成成功！");
            System.out.println("[✓] 签名值: " + sign64);
            System.out.println("[✓] 签名长度: " + sign64.length());
        } else {
            System.out.println("\n[✗] sign_64 签名生成失败");
        }
        
        System.out.println("\n====================================================");
        System.out.println("  测试完成！");
        System.out.println("====================================================");
    }
}
