# 🔍 APK签名验证失败根本原因分析

## 📅 日期: 2025-10-18

## 📊 诊断结果总结

### ✅ 好消息
1. **APK文件访问正常**:
   ```
   [🔍 APK诊断] 真实APK文件:
   [🔍 APK诊断]   路径: /Users/yml/IdeaProjects/unidbg_1/unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk
   [🔍 APK诊断]   存在: true
   [🔍 APK诊断]   大小: 87673901 字节
   [🔍 APK诊断]   可读: true
   ```

2. **IOResolver正确返回APK**:
   ```
   [IOResolver] 🔍 APK访问请求:
   [IOResolver]   文件存在: true
   [IOResolver]   文件大小: 87673901 字节
   [IOResolver]   可读权限: true
   [IOResolver] ✅ 返回真实APK文件
   ```

3. **反调试变量完全正确**:
   ```
   ✅ 反调试变量与真机一致!
   dword_70C10 = 0x00000000 (0)
   dword_70C14 = 0x00000000 (0)
   ```

### ❌ 问题所在

**两个签名验证错误仍然发生**:

1. **错误 0x111b7** (ZIP读取/解析错误):
   ```
   [❌ nativeReport] 错误码: 0x111b7 (70071)
   [❌ nativeReport] 消息: 1760752077743:[]
   [❌ 分析] APK签名验证失败 - ZIP读取/解析错误
   ```

2. **错误 0x111bc** (证书链验证失败):
   ```
   [❌ nativeReport] 错误码: 0x111bc (70076)
   [❌ nativeReport] 消息: 1760752077752:[]
   [❌ 分析] 证书链验证失败
   ```

---

## 🔬 深入分析

### 关键执行流程追踪

```
1. APK文件可以打开 ✅
   [IOResolver] ✅ 返回真实APK文件

2. 但是ZIP验证失败 ❌
   错误码: 0x111b7 (ZIP读取/解析错误)

3. 证书验证失败 ❌
   错误码: 0x111bc (证书链验证失败)

4. Opcode检查从栈读取错误值 ❌
   0x042dfc: ldr w11, [sp, #0x30] => w11=0xffffffff
   (应该读取到 opcode=0x28a0)

5. 导致最终失败 ❌
   b.ne #0x12043368  (跳转到错误路径)
```

### 栈偏移 0x30 的问题

在地址 **0x042dfc** 处:
```assembly
ldr w11, [sp, #0x30] => w11=0xffffffff
```

**分析**:
- 栈偏移 `[sp+0x30]` 存储的值是 `0xffffffff` (全1)
- 这个值不是我们传入的 opcode `0x28a0`
- 这个位置可能是**错误标志位**,被签名验证失败设置为 -1

---

## 💡 根本原因假设

### 假设1: SO内部使用了Android系统API进行APK验证

**证据**:
1. 虽然APK文件可以通过IOResolver打开
2. 但是SO可能调用了Android系统API (如 `PackageManager.getPackageInfo`)
3. 这些API在unidbg中可能返回了不完整的签名信息

**验证**:
从日志中没有看到 `PackageManager.getPackageInfo` 的调用,说明**这个假设可能不成立**。

---

### 假设2: SO内部直接解析ZIP结构

**证据**:
1. 错误码 0x111b7 明确指出 "ZIP读取/解析错误"
2. APK文件可以打开,说明路径和权限都正确
3. 问题可能出在ZIP文件的**内部结构解析**上

**可能的原因**:
- SO可能查找特定的ZIP条目 (如 `META-INF/MANIFEST.MF`)
- SO可能验证ZIP Central Directory
- SO可能检查ZIP文件的完整性校验

**进一步验证需要**:
- Hook native `open()` 系统调用,查看具体打开的是哪个文件
- Hook `read()` 系统调用,查看读取的数据
- Hook `lseek()` 系统调用,查看文件偏移量

---

### 假设3: 签名证书提取失败

**证据**:
1. 错误码 0x111bc 明确指出 "证书链验证失败"
2. 我们使用 `vm.getSignatures()` 来提供签名
3. 但签名可能格式不对或数据不完整

**检查点**:
从日志中看,**没有任何关于 `PackageInfo.signatures` 的调用**!

这是一个**重要发现**:
- SO可能没有通过JNI回调获取签名
- SO可能自己从APK文件中提取签名
- 提取过程中遇到了问题

---

## 🎯 关键发现

### 栈布局分析

从trace可以看到栈偏移的使用:

```assembly
0x042be0: sub w10, w8, #1          ; w8 是 dword_70C14 (反调试变量2)
0x042be4: mul w10, w10, w8         ; 计算 (w8-1)*w8
0x042be8: cmp w9, #0xa              ; w9 是 dword_70C10 (反调试变量1)
...
0x042c08: ldr w15, [sp, #0x70]     ; 读取 opcode (0x28a0) ✅ 正确!
...
0x042dfc: ldr w11, [sp, #0x30]     ; 读取??? (0xffffffff) ❌ 错误!
```

**关键观察**:
1. `[sp+0x70]` 存储的是正确的 opcode (0x28a0)
2. `[sp+0x30]` 存储的是错误标志 (0xffffffff)

**推测**:
- `[sp+0x30]` 可能是**签名验证结果标志位**
- 签名验证失败后,这个位置被设置为 -1
- 后续代码使用这个值进行检查,导致加密失败

---

## 🔧 解决方案探索

### 方案A: 真正修复APK签名验证 (推荐)

**步骤**:

1. **Hook ZIP相关的native调用**,查看SO如何解析APK:
   ```java
   // Hook open(), read(), lseek() 等系统调用
   // 记录SO访问APK的哪些部分
   ```

2. **检查ZIP结构完整性**:
   ```bash
   # 使用zip工具检查APK
   unzip -t ksjsb_13.8.40.10657.apk

   # 检查签名块
   apksigner verify --verbose ksjsb_13.8.40.10657.apk
   ```

3. **对比真机的ZIP访问模式**:
   - 使用strace在真机上跟踪SO的文件访问
   - 对比unidbg中的文件访问
   - 找出差异

---

### 方案B: 绕过签名验证的副作用

**当前问题**:
- 我们成功Hook了 `sub_3E5C0`,返回成功
- 但是内部状态 `[sp+0x30]` 仍然被设置为 -1
- 说明**某个子函数仍然执行了,并设置了错误状态**

**解决**:

#### 选项1: Hook更早的阶段

在 `sub_3E5C0` 调用**之前**就设置正确的状态:
```java
// 在调用 sub_3E5C0 之前,预先设置栈上的状态
// 需要找到栈偏移 0x30 的初始化位置
```

#### 选项2: Hook更多的子函数

从 `sub_3E5C0.txt` 分析,可能需要Hook:
- `sub_DDF8` - APK相关验证
- `sub_EDA0` - 签名验证
- 其他设置错误状态的函数

#### 选项3: 修复栈上的错误标志

**最直接的方案**:在 opcode 检查之前,修复栈上的值:

```java
// 在 0x042dfc 之前,修复 [sp+0x30] 的值
long checkAddr = module.base + 0x042dfc;
backend.hook_add_new(new CodeHook() {
    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        // 读取SP
        long sp = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();

        // 读取 [sp+0x30] 当前值
        byte[] currentValue = backend.mem_read(sp + 0x30, 4);
        int value = bytesToInt(currentValue);

        if (value == -1 || value == 0xffffffff) {
            System.out.println("[🔧 修复] 检测到 [sp+0x30] = -1,修复为0");

            // 写入正确的值 (0 表示没有错误)
            byte[] newValue = new byte[]{0, 0, 0, 0};
            backend.mem_write(sp + 0x30, newValue);
        }
    }

    @Override
    public void onAttach(UnHook unHook) {}

    @Override
    public void detach() {}
}, checkAddr, checkAddr + 4, null);
```

---

## 📋 下一步行动计划

### 优先级1: 快速验证 - 修复栈上的错误标志

**操作**: 添加Hook修复 `[sp+0x30]` 的值

**预期结果**:
- opcode 检查应该通过
- 执行路径进入 POINT_3 (加密逻辑)
- 加密成功

**风险**:
- 这只是绕过问题,不是真正解决
- 可能还有其他副作用

---

### 优先级2: 深入分析 - 找出真正的ZIP验证问题

**操作**:
1. 使用 `unzip -t` 和 `apksigner verify` 检查APK
2. Hook native 文件操作,查看SO如何访问APK
3. 对比真机的文件访问模式

**预期结果**:
- 理解SO的ZIP验证逻辑
- 找到为什么会报 0x111b7 错误
- 真正修复签名验证

---

## 🎯 推荐方案

**立即执行**: 方案B选项3 - 修复栈上的错误标志

**原因**:
1. 快速,可以立即验证
2. 如果成功,说明我们的假设正确
3. 如果失败,也能提供更多诊断信息

**如果成功后**:
- 再深入研究真正的签名验证问题
- 确保长期解决方案的稳定性

---

## 📝 总结

**核心问题**:
- APK文件访问正常 ✅
- 反调试变量正确 ✅
- 但签名验证失败 ❌
- 导致栈上 `[sp+0x30]` 被设置为 -1
- opcode检查时读取到错误值
- 最终加密失败

**最可能的解决方案**:
直接修复栈上的错误标志位,让加密流程继续执行。

---

**分析完成时间**: 2025-10-18
**下一步**: 实现栈修复Hook
