# 真机Hook数据分析报告

## 📊 数据来源
文件: `hook_1.txt`
设备: 真实Android设备
APP: 快手极速版 13.8.40.10657

## 🔍 关键发现

### 1. Opcode值 ✅ 正确
```
真机: 10400 (0x28a0) - 加密请求
unidbg: 10400 ✅ 匹配
```

### 2. 初始化调用参数 ❌ **不匹配**

#### 真机数据 (行32-47):
```java
Opcode: 10412 (0x28ac)  // 初始化环境
params = Array[7] {      // ⚠️ 注意:只有7个参数!
  [0] = null             // ❌ 不是ByteArray!
  [1] = String "d7b7d042-d4f2-4012-be60-d97ff2429c17"  // UUID
  [2] = null             // ❌ 不是Integer!
  [3] = null
  [4] = com.yxcorp.gifshow.App  // Context
  [5] = null             // ❌ 不是两个Boolean!
  [6] = null
}

返回值: 1  // ✅ 初始化成功
```

#### unidbg当前实现 (KSEmulator.java:1491):
```java
// ❌ 错误:参数数组不匹配
ArrayObject paramsArray = new ArrayObject(
    null,       // [0]
    appkey,     // [1] String
    zero,       // [2] Integer  ← 真机是null!
    null,       // [3]
    context,    // [4] Context
    null,       // [5]
    null        // [6]
);
```

### 3. 反调试变量状态 ✅ 正确

#### 真机数据 (行115):
```
dword_70C10 = 0  // ✅ 不会触发反调试
dword_70C14 = 0  // ✅ 不会触发反调试
```

#### 反调试触发条件:
```c
if (dword_70C10 >= 10 && ((dword_70C14-1)*dword_70C14 & 1) != 0)
    // 进入反调试分支
```

计算:
- `dword_70C10 >= 10` → `0 >= 10` → **false** ✅
- 第二个条件不需要检查,因为第一个已经false

### 4. APK路径 ✅ 正确

#### 真机数据 (行80):
```
getPackageCodePath返回:
/data/app/~~En8y40Eyt_9SQIpY8tusUw==/com.kuaishou.nebula-94eN8Qsx7c5Ex2tlhTevMQ==/base.apk
```

这是真实的Android 11+的APK路径格式。

### 5. 签名验证调用

#### 真机数据 (行292-295):
```
[→ sub_3E5C0] 签名验证开始
  参数: 0x7e46e1d4c0, 0x15
[← sub_3E5C0] 返回: 0x1  // ✅ 验证通过
```

所有签名验证都返回1(成功)。

### 6. Frida Hook问题

#### 问题描述:
```
TypeError: not a function
    at dumpArray (/frida/repl-2.js:99)
```

导致加密请求(opcode 10400)的参数数组没有完整打印出来。

#### 需要修复的Frida脚本:
`dumpArray` 函数在处理某些特殊对象时报错。

## 🛠️ 修复建议

### 修复1: 初始化调用参数 (优先级:高)

**位置**: `KSEmulator.java:1491` 的 `call_doCommandNative_init` 方法

**当前代码**:
```java
DvmInteger zero = DvmInteger.valueOf(vm, 0);  // ← 删除这行
vm.addLocalObject(zero);

ArrayObject paramsArray = new ArrayObject(
    null,
    appkey,
    zero,      // ← 改为 null
    null,
    context,
    null,
    null
);
```

**修复后**:
```java
// ✅ 根据真机数据,参数[2]应该是null,不是Integer(0)
ArrayObject paramsArray = new ArrayObject(
    null,       // [0] null
    appkey,     // [1] UUID字符串
    null,       // [2] ⚠️ 修改:null (不是Integer!)
    null,       // [3] null
    context,    // [4] App对象
    null,       // [5] null
    null        // [6] null
);
```

### 修复2: 加密调用参数验证

虽然Frida脚本报错没有完整打印,但根据前面的分析,我们已知:
- opcode = 10400 ✅
- 参数数量应该是8个 (需要Frida完整数据确认)

**需要验证的点**:
1. 参数[0]: ByteArray (加密数据)
2. 参数[1]: UUID字符串
3. 参数[2]: Integer 0
4. 参数[3]: ⚠️ **需要确认是否为null**
5. 参数[4]: App对象
6. 参数[5-7]: Boolean/UUID等

### 修复3: 修复Frida脚本

创建简化版的脚本,只打印关键信息:

```javascript
// frida_hook_params_only.js
Java.perform(function() {
    var JNICLibrary = Java.use("com.kuaishou.android.security.internal.dispatch.JNICLibrary");

    JNICLibrary.doCommandNative.implementation = function(opcode, params) {
        if (opcode === 10400) {  // 只关注加密
            console.log("\n[Opcode 10400] 参数数量: " + params.length);
            for (var i = 0; i < params.length; i++) {
                if (params[i] === null) {
                    console.log("  [" + i + "] null");
                } else {
                    console.log("  [" + i + "] " + params[i].$className);
                }
            }
        }
        return this.doCommandNative(opcode, params);
    };
});
```

## 📝 测试计划

### 第1步: 修复初始化参数
1. 修改 `call_doCommandNative_init` 方法
2. 将参数[2]从`Integer(0)`改为`null`
3. 运行unidbg测试
4. 检查初始化是否返回1

### 第2步: 重新Hook完整加密参数
1. 使用简化版Frida脚本
2. 捕获opcode=10400的完整参数
3. 对比unidbg的`encryptEncData`方法

### 第3步: 逐步调试
如果仍然失败:
1. Hook native层的doCommandNative
2. 在关键分支打印寄存器值
3. 对比真机和unidbg的执行路径

## 🎯 优先行动

### 立即修改:
1. **修改 call_doCommandNative_init** - 参数[2]改为null
2. **重新测试unidbg**
3. **如果初始化成功,再测试加密**

### 如果还是失败:
运行简化版Frida脚本获取10400的完整参数。

## 📌 结论

从真机数据看,最关键的问题是:
1. **初始化参数不匹配** - 参数[2]应该是null
2. 反调试变量值是正确的(都是0)
3. Opcode值是正确的(10400)
4. 签名验证通过(返回1)

**建议先修复初始化参数,这很可能就是问题的根源!**
