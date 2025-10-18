# 快手极速版加密分析 - Frida Hook使用指南

## 📱 环境准备

### 1. 手机端
- Android手机(已root或使用支持Frida的模拟器)
- 安装快手极速版 APK: `ksjsb_13.8.40.10657.apk`
- 开启USB调试

### 2. 电脑端
```bash
# 安装Frida
pip install frida-tools

# 验证安装
frida --version

# 检查手机连接
adb devices

# 查看手机上的进程
frida-ps -U
```

## 🎯 使用方法

### 方法一: 启动时附加(推荐)
```bash
# 完整版脚本 - 详细信息
frida -U -f com.kuaishou.nebula -l frida_hook_ksjsb.js --no-pause

# 简化版脚本 - 核心参数
frida -U -f com.kuaishou.nebula -l frida_hook_simple.js --no-pause
```

### 方法二: 附加到运行中的进程
```bash
# 先启动快手极速版APP
# 然后执行:
frida -U com.kuaishou.nebula -l frida_hook_ksjsb.js
```

### 方法三: 使用spawn模式(调试模式)
```bash
frida -U -f com.kuaishou.nebula -l frida_hook_ksjsb.js
# 然后在Frida控制台输入: %resume
```

## 📊 捕获数据

### 1. 触发加密操作
在手机上操作快手极速版APP,触发以下操作:
- 启动APP (会调用初始化 opcode=10412)
- 浏览视频 (可能触发加密请求 opcode=10400/10408)
- 点赞/评论 (会触发加密)

### 2. 保存输出
```bash
# 将输出保存到文件
frida -U -f com.kuaishou.nebula -l frida_hook_simple.js --no-pause > frida_output.txt
```

## 🔍 重点关注的数据

### doCommandNative调用
```
[doCommandNative] Opcode: 10400
[参数数组] 长度: 8
  [0] byte[xxx]  <--- ⭐ 加密的原始数据
      Hex: 7B22617070496E666F...
  [1] String: "d7b7d042-d4f2-4012-be60-d97ff2429c17"  <--- UUID
  [2] Integer: 0
  [3] null  <--- ⚠️ 注意是否为null
  [4] com.yxcorp.gifshow.App  <--- Context对象
  [5] Boolean: true
  [6] Boolean: true
  [7] String: "95147564-9763-4413-a937-6f0e3c12caf1"

[返回] byte[xxx]  <--- ⭐ 加密结果
  Hex: 5A54EECDE4D4EA6193F79DB96E3254547C68770002477963...
```

### 需要对比的关键点

#### 1. Opcode值
- unidbg使用: `10400`
- 真机使用: `????` (需要从日志确认)

#### 2. 参数[3]的值
- unidbg使用: `null`
- 真机使用: `????` (可能是某个对象)

#### 3. Context对象
- unidbg使用: `com.yxcorp.gifshow.App`
- 真机使用: `????`

#### 4. getSecEnvValue返回值
- unidbg返回: `0`
- 真机返回: `????`

#### 5. canRun返回值
- unidbg返回: `1`
- 真机返回: `????`

## 🛠️ 对比分析步骤

### 第1步: 捕获真机数据
```bash
# 运行简化版脚本
frida -U -f com.kuaishou.nebula -l frida_hook_simple.js --no-pause > real_device_log.txt

# 在手机上触发加密操作
# 等待日志输出
```

### 第2步: 运行unidbg测试
```bash
cd /Users/yml/IdeaProjects/unidbg_1
# 运行你的KSEmulator
# 保存输出到文件
```

### 第3步: 对比差异
重点对比:
1. **Opcode**: 确认真机使用的是10400还是10408还是其他
2. **参数数量**: 是否都是8个参数
3. **参数类型**: 每个参数的类型是否一致
4. **参数值**: UUID、Boolean等值是否一致
5. **参数[0]数据**: 加密原始数据的长度和内容
6. **参数[3]**: 是否为null还是某个对象
7. **返回值**: 是否返回byte数组还是null

### 第4步: 定位问题
根据差异修改 `KSEmulator.java`:

```java
// 如果真机使用不同的opcode
int opcode = 10408; // 修改为真机的值

// 如果参数[3]不是null
DvmObject<?> param3 = ...; // 创建真实对象

// 如果参数顺序不同
ArrayObject paramsArray = new ArrayObject(
    param0,  // 按真机顺序调整
    param1,
    // ...
);
```

## ❗ 常见问题

### Q1: frida-server无法启动
```bash
# 下载对应架构的frida-server
# https://github.com/frida/frida/releases

# 上传到手机
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

# 启动
adb shell "/data/local/tmp/frida-server &"
```

### Q2: 找不到进程
```bash
# 确认包名
adb shell pm list packages | grep kuaishou

# 应该看到: com.kuaishou.nebula
```

### Q3: Hook失败
```bash
# 检查frida-server版本和frida-tools版本是否一致
frida --version
adb shell "/data/local/tmp/frida-server --version"

# 版本不一致的话需要下载匹配的版本
```

### Q4: 没有输出
- 确认APP是否真的调用了目标函数
- 尝试在APP中进行更多操作(点赞、评论等)
- 检查包名是否正确: `com.kuaishou.nebula`

## 📝 预期输出示例

```
[*] Frida Hook Script Loaded - 快手极速版加密分析
[*] 目标：捕获 doCommandNative 的完整调用链
[✓] 找到 libkwsgmain.so
  Base: 0x7a12345000
  Size: 0x73000

================================================================================
[🎯 doCommandNative 调用] Opcode: 10400 (0x28a0)
================================================================================
[Opcode] 类型: 加密请求 (ByteArray)

[参数详情]
params = Array[8] {
  [0] = [B
      长度=627, Hex=7B22617070496E666F223A7B226170704964223A226B75616973...
  [1] = java.lang.String
      值="d7b7d042-d4f2-4012-be60-d97ff2429c17"
  [2] = java.lang.Integer
      值=0
  [3] = null
  [4] = com.yxcorp.gifshow.App
  [5] = java.lang.Boolean
      值=true
  [6] = java.lang.Boolean
      值=true
  [7] = java.lang.String
      值="95147564-9763-4413-a937-6f0e3c12caf1"
}

[← 返回值] 耗时: 45ms
  返回: byte[1234]
  Hex: 5A54EECDE4D4EA6193F79DB96E3254547C68770002477963...
================================================================================
```

## 🎯 下一步行动

1. **运行Frida脚本捕获真机数据**
2. **对比unidbg输出和真机输出**
3. **找出关键差异点**
4. **修改KSEmulator.java**
5. **重新测试验证**

## 📞 调试技巧

### 实时查看内存
```javascript
// 在Frida脚本中添加
var addr = libkwsgmain.base.add(0x70910); // qword_70910
console.log("qword_70910 = 0x" + addr.readU64().toString(16));
```

### Hook更多函数
```javascript
// Hook任意地址的函数
Interceptor.attach(libkwsgmain.base.add(0x3E5C0), {
    onEnter: function(args) {
        console.log("sub_3E5C0 called");
    }
});
```

### 修改返回值
```javascript
JNICLibrary.getSecEnvValue.implementation = function() {
    return 0; // 强制返回0
};
```

---

💡 **提示**: 先用简化版脚本(`frida_hook_simple.js`)快速验证,确认能捕获到数据后,再用完整版脚本(`frida_hook_ksjsb.js`)获取详细信息。
