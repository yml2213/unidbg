# 🔧 栈修复Hook实现说明

## 📅 修改日期: 2025-10-18

## 🎯 目的

修复APK签名验证失败后在栈上留下的错误标志,使加密流程能够继续执行。

## 📊 问题背景

从执行trace发现:

```assembly
0x042dfc: ldr w11, [sp, #0x30] => w11=0xffffffff  ❌ 错误值!
0x042e04: str w11, [x24, #0xc]                    存储错误值
0x042e08: b.ne #0x12043368                        跳转到错误路径
```

**根本原因**:
1. APK签名验证失败 (错误码 0x111b7, 0x111bc)
2. 虽然Hook了 `sub_3E5C0` 返回成功,但某些内部状态已被破坏
3. 栈偏移 `[sp+0x30]` 被设置为 -1 (0xffffffff)
4. 后续代码读取这个值进行检查,导致失败

## 🔧 解决方案

### 实现位置

**文件**: `KSEmulator.java`
**方法**: `hookSignatureVerification()`
**新增代码**: Line 189-246

### 实现细节

```java
// Hook在 0x042dfc 处 - 读取栈上错误标志之前
final long STACK_FIX_ADDR = module.base + 0x042dfc;

backend.hook_add_new(new CodeHook() {
    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        // 1. 读取SP寄存器
        long sp = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();

        // 2. 读取 [sp+0x30] 的当前值
        byte[] currentBytes = backend.mem_read(sp + 0x30, 4);
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(currentBytes);
        buf.order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int currentValue = buf.getInt();

        // 3. 检查是否为错误标志 (0xffffffff = -1)
        if (currentValue == -1 || currentValue == 0xffffffff) {
            System.out.println("[栈修复]   ⚠️ 检测到签名验证失败标志 (0xffffffff)");
            System.out.println("[栈修复]   🔧 修复为 0 (表示成功)");

            // 4. 写入 0 (表示没有错误)
            byte[] newValue = new byte[]{0, 0, 0, 0};
            backend.mem_write(sp + 0x30, newValue);

            // 5. 验证写入是否成功
            byte[] verifyBytes = backend.mem_read(sp + 0x30, 4);
            java.nio.ByteBuffer verifyBuf = java.nio.ByteBuffer.wrap(verifyBytes);
            verifyBuf.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int verifyValue = verifyBuf.getInt();

            System.out.println(String.format(
                "[栈修复]   ✅ 修复后值 = 0x%08x (%d)",
                verifyValue, verifyValue
            ));
        } else {
            System.out.println("[栈修复]   ✓ 值正常，无需修复");
        }
    }

    @Override
    public void onAttach(UnHook unHook) {
        System.out.println("[栈修复] ✓ Hook 已激活");
    }

    @Override
    public void detach() {}
}, STACK_FIX_ADDR, STACK_FIX_ADDR + 4, null);
```

## 📋 工作原理

### Hook触发时机

```
执行流程:
  ↓
sub_3E5C0 (签名验证)
  ↓ [被Hook,返回成功]
  ↓ [但内部状态被破坏, [sp+0x30] = -1]
  ↓
0x042dfc: ldr w11, [sp, #0x30]  ← ⚠️ 在这里触发Hook!
  ↓ [Hook检测到值为-1]
  ↓ [修复为0]
  ↓
w11 = 0  ✅ 正确值
  ↓
0x042e04: str w11, [x24, #0xc]  存储正确值
  ↓
0x042e08: b.ne #0x12043368       不跳转 (因为之前的比较通过了)
  ↓
继续执行加密逻辑 ✅
```

### 关键点

1. **Hook位置精确**: 在读取指令执行**之前**触发
2. **小端序处理**: 正确处理ARM64的字节序
3. **验证机制**: 读取并显示修复后的值,确保修复成功
4. **条件修复**: 只在检测到错误标志时才修复,避免影响正常流程

## 📊 预期输出

### 场景1: 检测到错误标志并修复

```
[栈修复] Hook 0x042dfc (修复签名验证失败的副作用)
[栈修复] ✓ Hook 已激活

[栈修复] 0x042dfc: [sp+0x30] 当前值 = 0xffffffff (-1)
[栈修复]   ⚠️ 检测到签名验证失败标志 (0xffffffff)
[栈修复]   🔧 修复为 0 (表示成功)
[栈修复]   ✅ 修复后值 = 0x00000000 (0)
```

### 场景2: 值正常无需修复

```
[栈修复] 0x042dfc: [sp+0x30] 当前值 = 0x00000000 (0)
[栈修复]   ✓ 值正常，无需修复
```

## ✅ 预期效果

修复后的执行流程:

```
1. APK签名验证失败 ❌
   错误码: 0x111b7, 0x111bc

2. Hook绕过签名验证 ✅
   sub_3E5C0 返回成功

3. 栈修复Hook生效 ✅
   [sp+0x30] = 0xffffffff → 0x00000000

4. Opcode检查通过 ✅
   (opcode | 8) == 0x28AE

5. 执行路径正确 ✅
   进入 POINT_3 (加密逻辑)
   不进入 POINT_4 (错误路径)

6. 加密成功 🎉
   返回正确的加密数据
```

## ⚠️ 注意事项

### 这是一个绕过方案,不是根本解决

**优点**:
- 快速有效
- 立即可验证
- 不需要深入理解ZIP验证逻辑

**缺点**:
- 只是掩盖症状,不是治本
- 可能还有其他副作用未被发现
- 长期稳定性未知

### 长期解决方案

如果这个方案成功,建议后续:

1. **深入研究ZIP验证失败的根本原因**
   - 使用 strace 跟踪真机的文件访问
   - Hook native open/read/lseek 系统调用
   - 分析SO如何解析ZIP结构

2. **真正修复签名验证**
   - 让签名验证真正通过,而不是绕过
   - 确保所有内部状态正确
   - 避免任何副作用

3. **对比真机和unidbg的完整执行流程**
   - 使用更详细的trace工具
   - 对比内存状态
   - 找出所有差异点

## 🚀 下一步

1. **立即运行测试**
   ```bash
   cd /Users/yml/IdeaProjects/unidbg_1
   # 在IDE中运行 KSEmulator.main()
   ```

2. **观察输出**
   - 查看栈修复是否被触发
   - 确认修复是否成功
   - 检查是否进入加密逻辑 (POINT_3)

3. **验证最终结果**
   - 加密是否成功
   - 加密结果是否与期望匹配

---

**实现完成时间**: 2025-10-18
**位置**: `KSEmulator.java` Line 189-246
**下一步**: 运行测试验证修复效果
