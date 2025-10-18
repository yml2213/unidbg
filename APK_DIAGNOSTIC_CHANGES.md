# APK访问和签名验证诊断修改

## 📅 修改日期: 2025-10-18

## 🎯 目的

添加详细的诊断信息,定位APK签名验证失败(错误码0x111b7和0x111bc)的根本原因。

## 🔧 修改内容

### 1. 临时禁用签名错误拦截

**文件**: `KSEmulator.java` Line 1165

**修改前**:
```java
if (code == 0x111b7 || code == 0x111bc || code == 0x11180) {
    // 直接拦截,不显示错误
    return;
}
```

**修改后**:
```java
if (false && (code == 0x111b7 || code == 0x111bc || code == 0x11180)) {
    // 临时禁用拦截,让错误完整显示
    return;
}
```

**原因**: 虽然拦截了错误报告,但内部状态可能已经损坏,需要看完整的错误信息才能诊断。

---

### 2. 增强签名错误码解析

**文件**: `KSEmulator.java` Line 1179-1192

**添加内容**:
```java
case 0x111b7: // 70071
    System.out.println("[❌ 分析] 0x111b7 (70071) = APK签名验证失败 - ZIP读取/解析错误");
    System.out.println("[❌ 提示] 可能原因:");
    System.out.println("[❌ 提示]   1. APK文件路径不正确或文件不存在");
    System.out.println("[❌ 提示]   2. APK文件无法打开或读取");
    System.out.println("[❌ 提示]   3. ZIP格式损坏或不完整");
    break;
case 0x111bc: // 70076
    System.out.println("[❌ 分析] 0x111bc (70076) = 证书链验证失败");
    System.out.println("[❌ 提示] 可能原因:");
    System.out.println("[❌ 提示]   1. 签名证书格式不正确");
    System.out.println("[❌ 提示]   2. 证书过期或无效");
    System.out.println("[❌ 提示]   3. PackageInfo.signatures 未正确设置");
    break;
```

---

### 3. 添加APK文件存在性检查

**文件**: `KSEmulator.java` Line 1274-1292

**在 `App->getPackageCodePath()` 方法中添加**:
```java
case "com/yxcorp/gifshow/App->getPackageCodePath()Ljava/lang/String;": {
    String apkPath = "/data/app/.../base.apk";
    System.out.println("[🔍 getPackageCodePath] 返回虚拟路径: " + apkPath);

    // ⚠️ 诊断：检查真实APK文件是否存在
    File realApk = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
    System.out.println("[🔍 APK诊断] 真实APK文件:");
    System.out.println("[🔍 APK诊断]   路径: " + realApk.getAbsolutePath());
    System.out.println("[🔍 APK诊断]   存在: " + realApk.exists());
    if (realApk.exists()) {
        System.out.println("[🔍 APK诊断]   大小: " + realApk.length() + " 字节");
        System.out.println("[🔍 APK诊断]   可读: " + realApk.canRead());
    } else {
        System.out.println("[🔍 APK诊断]   ❌ 文件不存在!");
    }

    return new StringObject(vm, apkPath);
}
```

---

### 4. 增强IOResolver的APK访问日志

**文件**: `KSEmulator.java` Line 415-442

**修改前**:
```java
System.out.println("检测到文件打开 File open request: " + pathname);

if (pathname != null && pathname.contains("base.apk")) {
    File realApk = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
    if (realApk.exists()) {
        System.out.println("[IOResolver] ✓ 返回真实APK文件: ...");
        return FileResult.success(...);
    }
}
```

**修改后**:
```java
System.out.println("[IOResolver] 文件打开请求: " + pathname +
                  " (flags=0x" + Integer.toHexString(oflags) + ")");

if (pathname != null && pathname.contains("base.apk")) {
    File realApk = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
    System.out.println("[IOResolver] 🔍 APK访问请求:");
    System.out.println("[IOResolver]   请求路径: " + pathname);
    System.out.println("[IOResolver]   真实路径: " + realApk.getAbsolutePath());
    System.out.println("[IOResolver]   文件存在: " + realApk.exists());

    if (realApk.exists()) {
        System.out.println("[IOResolver]   文件大小: " + realApk.length() + " 字节");
        System.out.println("[IOResolver]   可读权限: " + realApk.canRead());

        try {
            System.out.println("[IOResolver] ✅ 返回真实APK文件");
            return FileResult.success(new SimpleFileIO(oflags, realApk, pathname));
        } catch (Exception e) {
            System.out.println("[IOResolver] ❌ 打开APK文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    } else {
        System.out.println("[IOResolver] ❌ APK文件不存在: " + realApk.getAbsolutePath());
    }
}
```

---

## 📊 预期诊断信息

运行测试后,将会看到以下详细信息:

### 场景1: APK文件存在且可访问
```
[🔍 getPackageCodePath] 返回虚拟路径: /data/app/.../base.apk
[🔍 APK诊断] 真实APK文件:
[🔍 APK诊断]   路径: /Users/yml/IdeaProjects/unidbg_1/unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk
[🔍 APK诊断]   存在: true
[🔍 APK诊断]   大小: 123456789 字节
[🔍 APK诊断]   可读: true

[IOResolver] 文件打开请求: /data/app/.../base.apk (flags=0x0)
[IOResolver] 🔍 APK访问请求:
[IOResolver]   请求路径: /data/app/.../base.apk
[IOResolver]   真实路径: /Users/yml/IdeaProjects/unidbg_1/unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk
[IOResolver]   文件存在: true
[IOResolver]   文件大小: 123456789 字节
[IOResolver]   可读权限: true
[IOResolver] ✅ 返回真实APK文件
```

### 场景2: APK文件不存在
```
[🔍 APK诊断] 真实APK文件:
[🔍 APK诊断]   路径: /Users/yml/IdeaProjects/unidbg_1/unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk
[🔍 APK诊断]   存在: false
[🔍 APK诊断]   ❌ 文件不存在!
```

### 场景3: 签名验证错误
```
[❌ nativeReport] 错误码: 0x111b7 (70071)
[❌ nativeReport] 消息: APK signature verification failed
[❌ 分析] 0x111b7 (70071) = APK签名验证失败 - ZIP读取/解析错误
[❌ 提示] 可能原因:
[❌ 提示]   1. APK文件路径不正确或文件不存在
[❌ 提示]   2. APK文件无法打开或读取
[❌ 提示]   3. ZIP格式损坏或不完整
```

---

## 🔍 下一步诊断步骤

根据输出的诊断信息:

1. **如果APK文件不存在**:
   - 检查文件路径是否正确
   - 确认APK文件是否已下载到指定位置

2. **如果APK文件存在但无法打开**:
   - 检查文件权限
   - 验证文件是否损坏(可以手动用解压工具打开)

3. **如果文件正常但仍然有0x111b7错误**:
   - SO库可能使用了特殊的ZIP解析方法
   - 可能需要检查ZIP Central Directory等内部结构

4. **如果有0x111bc错误**:
   - 检查VM的签名数据是否正确(vm.getSignatures())
   - 验证签名证书格式
   - 确认PackageInfo是否正确返回signatures字段

---

## 🎯 成功标准

如果修复成功,应该看到:
- ✅ APK文件存在且可读
- ✅ 没有0x111b7和0x111bc错误
- ✅ opcode检查通过
- ✅ 执行路径进入POINT_3(加密逻辑)而不是POINT_4(错误路径)

---

**修改完成时间**: 2025-10-18
**下一步**: 运行测试,查看详细的诊断输出
