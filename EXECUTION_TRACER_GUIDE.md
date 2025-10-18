# 🔧 ExecutionTracer 使用说明

## 📝 已完成的修改

### 1. 创建了 ExecutionTracer.java
位置: `unidbg-android/src/test/java/com/kuaishou/nebula/ExecutionTracer.java`

功能:
- ✅ 追踪关键执行点 (0x42bc8, 0x42c00, 0x42e08, 0x43000, 0x43368)
- ✅ 快照关键内存地址 (qword_70910, byte_7091F, dword_70C10, dword_70C14)
- ✅ 记录寄存器状态 (X0-X3, LR)
- ✅ Hook关键分支指令 (opcode检查)
- ✅ 生成详细对比报告

### 2. 修改了 KSEmulator.java
在main方法中集成了ExecutionTracer:
```java
// 创建tracer
ExecutionTracer tracer = new ExecutionTracer(ksEmulator.emulator, ksEmulator.module);
tracer.enableDetailedTrace();

// ... 执行加密 ...

// 打印报告
tracer.printReport();
```

## 🚀 运行方法

### 方式1: 使用IDE运行
1. 打开 `KSEmulator.java`
2. 右键点击 `main` 方法
3. 选择 "Run 'KSEmulator.main()'"

### 方式2: 使用命令行
```bash
cd /Users/yml/IdeaProjects/unidbg_1
./gradlew :unidbg-android:test --tests com.kuaishou.nebula.KSEmulator
```

### 方式3: 使用Maven
```bash
cd /Users/yml/IdeaProjects/unidbg_1
mvn test -Dtest=KSEmulator
```

## 📊 预期输出

### 执行过程输出
```
========== 启动详细执行跟踪 ==========

[ExecutionTracer] 🔍 启用详细执行跟踪
[ExecutionTracer] ✓ 跟踪已启用

========== 第1步：初始化环境 ==========
[initializeEnvironment] 调用 doCommandNative(opcode=10412)...
...

========== 第2步：加密数据 ==========
[encryptEncData] 开始执行 encData 调用...

[🎯 执行点 #0] 0x42bc8 (第1次)
  寄存器: X0=0x... X1=0x... X2=0x... X3=0x... LR=0x...

[⚠️ Opcode检查] 0x42e08: opcode=0x28a0, (opcode|8)=0x28a8
  ✅ 检查通过! (0x28AE == 0x28AE)
  或
  ❌ 检查失败! 期望0x28AE, 实际0x28a8

[🎯 执行点 #1] 0x42c00 (第1次)
  ...
```

### 最终报告
```
================================================================================
📊 执行跟踪报告
================================================================================

[执行路径统计]
  POINT_0: 1次  ← 表示执行到了0x42bc8
  POINT_1: 0次  ← 如果为0,说明没进入反调试检查
  POINT_2: 1次  ← 表示执行到了opcode检查
  POINT_3: 1次  ← 表示进入了加密逻辑
  POINT_4: 0次  ← 如果为0,说明没进入错误路径(好事!)

[关键内存变化]

  [INIT]
    qword_70910 = 0x0000000000000000
    byte_7091F  = 0x00
    dword_70C10 = 0x00000000 (0)
    dword_70C14 = 0x00000000 (0)

  [POINT_0]  ← 第一个执行点时的状态
    qword_70910 = 0x0001800000000000
    byte_7091F  = 0x20
    dword_70C10 = 0xffffffff (-1)
    dword_70C14 = 0xffffffff (-1)

  [POINT_2]  ← opcode检查时的状态
    ...

[与真机数据对比]
  真机:
    dword_70C10 = 0x00000000 (0)
    dword_70C14 = 0x00000000 (0)

  unidbg:
    dword_70C10 = 0xffffffff (-1)
    dword_70C14 = 0xffffffff (-1)

  ❌ 反调试变量与真机不一致!
```

## 🔍 如何分析报告

### 1. 检查执行路径
```
[执行路径统计]
  POINT_0: 1次  ✅ 正常
  POINT_1: 0次  ✅ 没进入反调试检查
  POINT_2: 1次  ✅ 进入opcode检查
  POINT_3: 0次  ❌ 没进入加密逻辑! 问题在这!
  POINT_4: 1次  ❌ 进入了错误路径!
```

如果 POINT_3 = 0 且 POINT_4 = 1:
- 说明在 opcode 检查后直接跳转到了错误返回路径
- 需要检查 opcode 检查的输出

### 2. 检查 Opcode 检查
```
[⚠️ Opcode检查] 0x42e08: opcode=0x28a0, (opcode|8)=0x28a8
  ❌ 检查失败! 期望0x28AE, 实际0x28a8
```

如果检查失败:
- opcode 值可能不对
- 需要检查传入的 opcode 参数

### 3. 检查内存状态
```
  [POINT_0]
    qword_70910 = 0x0000000000000000  ❌ 应该是 0x1800000000000
```

如果标志位不对:
- `setGlobalFlagsEarly()` 方法可能没生效
- 标志位可能被其他函数重置

### 4. 对比真机数据
```
  ❌ 反调试变量与真机不一致!
```

如果不一致:
- 可能需要调整 `disableAntiDebugBeforeEncryption()` 的逻辑
- 或者真机根本不需要设置这些变量

## 🛠️ 常见问题诊断

### 问题1: 没有任何执行点被触发
```
[执行路径统计]
  (空)
```
**原因**: Hook 可能设置失败
**解决**: 检查模块基址是否正确

### 问题2: POINT_4 被触发(进入错误路径)
```
[执行路径统计]
  ...
  POINT_4: 1次  ❌
```
**原因**: 某个检查失败
**解决**: 查看之前的检查点输出,找出失败的检查

### 问题3: Opcode 检查失败
```
[⚠️ Opcode检查] opcode=0x28a0, (opcode|8)=0x28a8
  ❌ 检查失败! 期望0x28AE, 实际0x28a8
```
**原因**: opcode 值不对,或者检查逻辑理解有误
**解决**:
1. 确认真机使用的 opcode (从 hook 日志看是 10400 = 0x28A0)
2. 计算: 0x28A0 | 8 = 0x28A8 (不等于 0x28AE!)
3. 可能需要调整 opcode 为 10406 或 10414

### 问题4: 内存标志位不对
```
  [POINT_0]
    qword_70910 = 0x0000000000000000  ❌
```
**原因**: `setGlobalFlagsEarly()` 没生效
**解决**: 在调用前添加日志确认是否执行

## 💡 下一步行动

### 根据报告结果:

1. **如果 Opcode 检查失败**:
   ```java
   // 在 encryptEncData 中修改:
   int opcode = 10406;  // 尝试不同的 opcode
   ```

2. **如果内存标志位不对**:
   ```java
   // 在 encryptEncData 开始处再次设置:
   setGlobalFlagsEarly();
   disableAntiDebugBeforeEncryption();
   ```

3. **如果进入错误路径**:
   - 查看之前所有检查点的输出
   - 找出第一个失败的检查
   - 针对性修复

## 📞 获取帮助

运行后,请将完整的输出发给我,包括:
1. 执行路径统计
2. Opcode 检查结果
3. 内存变化
4. 最终是否加密成功

我会根据这些信息帮你精确定位问题!
