# 🎯 目标加密调用完整分析

## 📋 数据来源
文件: `2025-10-18_09_12_59.log`
时间: 2025-10-18 09:11:54
类名: `com.kuaishou.android.security.internal.dispatch.JNICLibrary`
方法: `doCommandNative(int, Object[])`

---

## 🔑 核心参数解析

### 参数1: Opcode
```
类型: java.lang.Integer
值: 10400
十六进制: 0x28A0
```
✅ **与unidbg一致**

### 参数2: Object数组 (关键!)
```
类型: [Ljava.lang.Object;
元素数量: 8个
```

#### 完整参数列表解析:

```java
params[0] = (JSON字符串的byte数组或字符串)
内容: {"appInfo":{"appId":"kuaishou_nebula","name":"快手极速版",...}}
说明: 这是要加密的原始数据

params[1] = "d7b7d042-d4f2-4012-be60-d97ff2429c17"
类型: String (UUID-1)

params[2] = 0
类型: Integer

params[3] = null
说明: ⚠️ 这里是null,不是其他对象!

params[4] = com.yxcorp.gifshow.App@7182043
类型: Application对象

params[5] = true
类型: Boolean

params[6] = true
类型: Boolean

params[7] = "95147564-9763-4413-a937-6f0e3c12caf1"
类型: String (UUID-2)
```

---

## 📦 加密原始数据 (JSON)

从参数值中提取的JSON数据:

```json
{
  "appInfo": {
    "appId": "kuaishou_nebula",
    "name": "快手极速版",
    "packageName": "com.kuaishou.nebula",
    "version": "13.8.40.10657",
    "versionCode": -1
  },
  "deviceInfo": {
    "oaid": "c4148177550a80b2e",
    "osType": 1,
    "osVersion": "11",
    "language": "zh",
    "deviceId": "ANDROID_191d747245591669d",
    "screenSize": {
      "width": 1080,
      "height": 2206
    },
    "ftt": "",
    "supportGyroscope": true
  },
  "networkInfo": {
    "ip": "10.0.0.132",
    "connectionType": 100
  },
  "geoInfo": {
    "latitude": 0,
    "longitude": 0
  },
  "userInfo": {
    "userId": "94942574",
    "age": 0,
    "gender": ""
  },
  "impInfo": [
    {
      "pageId": 11101,
      "subPageId": 100026367,
      "action": 0,
      "width": 0,
      "height": 0,
      "browseType": 3,
      "requestSceneType": 1,
      "lastReceiveAmount": 0,
      "impExtData": "{\"openH5AdCount\":0,\"sessionLookedCompletedCount\":\"0\",\"sessionType\":\"1\",\"neoParams\":\"eyJwYWdlSWQiOjExMTAxLCJzdWJQYWdlSWQiOjEwMDAyNjM2NywicG9zSWQiOjAsImJ1c2luZXNzSWQiOjY3MiwiZXh0UGFyYW1zIjoiODA5M2E4M2M1M2YzNzM0OThmMWJjM2JhN2FjYTU3M2I3ZGM5YWUyYjI2NWU4ZjgwOTdkMTgyNjkxOTI0MmVkNzUxNzQzNDg4MzI1MjZhNDFlYmExM2UzYWUxYzA3MTIxZmM1NTYzMmY0MjdmNWE2ZmJjMWEzNmFiMTk1NTMyNGYwMWY0NjE4ZTg4OWEwMmFlODRhMDc3YzI2NzA2M2ZhY2U1MmY4NDdmNTU4M2NkNDc5NjEzZmYwMzQzYTRlMWMiLCJjdXN0b21EYXRhIjp7ImV4aXRJbmZvIjp7InRvYXN0RGVzYyI6bnVsbCwidG9hc3RJbWdVcmwiOm51bGx9fSwicGVuZGFudFR5cGUiOjEsImRpc3BsYXlUeXBlIjoyLCJzaW5nbGVQYWdlSWQiOjAsInNpbmdsZVN1YlBhZ2VJZCI6MCwiY2hhbm5lbCI6MCwiY291bnRkb3duUmVwb3J0IjpmYWxzZSwidGhlbWVUeXBlIjowLCJtaXhlZEFkIjpmYWxzZSwiZnVsbE1peGVkIjp0cnVlLCJhdXRvUmVwb3J0Ijp0cnVlLCJmcm9tVGFza0NlbnRlciI6ZmFsc2UsInNlYXJjaEluc3BpcmVTY2hlbWVJbmZvIjpudWxsLCJhbW91bnQiOjB9In0=",
      "mediaExtData": "{}",
      "session": "{\"id\":\"adNeo-94942574-100026367-1760749914338\"}"
    }
  ],
  "adClientInfo": "{\"ipdxIP\":\"123.133.149.43\"}",
  "recoReportContext": "{\"adClientInfo\":{\"shouldShowAdProfileSectionBanner\":null,\"profileAuthorId\":0,\"xiaomiCustomMarketInfo\":{\"support\":true,\"detailStyle\":\"1,2,3,5,100,101,102\"}}}"
}
```

### 🔍 关键字段对比

#### 与unidbg中的差异:

| 字段 | 真机值 | unidbg (ENC_DATA_REQUEST_HEX) |
|------|--------|-------------------------------|
| deviceId | ANDROID_191d747245591669d | ANDROID_b744234d6e59878b |
| oaid | c4148177550a80b2e | 700ED686350EF49ECB686B2AAA9994C1Dca31c779ee5acb7d4c3b0333759a591 |
| userId | 94942574 | 1579452490 |
| ip | 10.0.0.132 | 192.168.50.214 |
| screenSize | 1080x2206 | 1080x2208 |
| subPageId | 100026367 | 100024064 |
| osVersion | 11 | 15 |

**⚠️ 重要发现**: 这些是业务数据的差异,不影响加密流程!

---

## 🎁 加密返回值

```
类型: java.lang.Object (实际是byte数组的Base64编码)
长度: ~3800字符

Base64值:
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
```

将Base64转为Hex应该就是目标的 `ENC_DATA_EXPECTED_HEX`!

---

## ✅ unidbg实现对比

### 当前unidbg实现 (encryptEncData方法)

```java
int opcode = 10400;  // ✅ 正确

ArrayObject paramsArray = new ArrayObject(
    requestParam,      // [0] ByteArray ✅
    uuid1,             // [1] UUID-1 ✅
    intZero,           // [2] Integer 0 ✅
    null,              // [3] null ✅
    appObject,         // [4] Application ✅
    boolTrue1,         // [5] Boolean true ✅
    boolTrue2,         // [6] Boolean true ✅
    uuid2              // [7] UUID-2 ✅
);
```

### ⚠️ 发现的问题

#### 问题1: 原始数据不匹配
unidbg中使用的是 `ENC_DATA_REQUEST_HEX` (旧数据),而真机使用的是新的JSON数据。

但这**不应该影响**加密流程本身!加密算法应该对任何数据都有效。

#### 问题2: UUID值
- UUID-1: ✅ 都是 `d7b7d042-d4f2-4012-be60-d97ff2429c17`
- UUID-2: ✅ 都是 `95147564-9763-4413-a937-6f0e3c12caf1`

#### 问题3: 参数顺序和类型
✅ 完全匹配!8个参数,类型顺序完全一致!

---

## 🎯 核心结论

### ✅ 参数结构完全正确!

unidbg的 `encryptEncData` 方法的参数结构与真机**完全匹配**:
- Opcode: 10400 ✅
- 参数数量: 8个 ✅
- 参数类型: ByteArray, String, Integer, null, App, Boolean, Boolean, String ✅
- UUID值: 完全一致 ✅

### ❌ 但加密仍然失败的原因

既然参数正确,问题一定出在**SO内部的状态检查**:

1. **全局标志位检查** (`qword_70910`, `byte_7091F`)
   - 必须在正确的时机设置
   - 可能被其他函数重置

2. **签名验证状态**
   - Hook显示虽然绕过了验证,但内部状态可能仍有问题

3. **反调试检查** (`dword_70C10`, `dword_70C14`)
   - 虽然设置为-1,但可能还有其他检查点

4. **环境检测** (`getSecEnvValue`)
   - 返回0是正确的,但可能还有其他环境检查

---

## 🛠️ 下一步调试策略

### 策略1: 使用真机JSON数据测试
虽然数据不同不应该影响算法,但可以用真机的JSON测试:
```java
String realDeviceJson = "{\"appInfo\":{\"appId\":\"kuaishou_nebula\",...}}";
byte[] requestBytes = realDeviceJson.getBytes(StandardCharsets.UTF_8);
```

### 策略2: 对比内存状态
在真机和unidbg中分别在关键位置读取:
- `qword_70910`
- `byte_7091F`
- `dword_70C10`
- `dword_70C14`

### 策略3: Hook更多检查点
根据IDA分析,在这些地址设置hook:
- 0x42c00: 反调试检查
- 0x42e08: opcode检查
- 0x43368: 错误返回路径

### 策略4: 逐步执行对比
使用Frida在真机上hook native层,记录执行路径,与unidbg对比。

---

## 📝 推荐修复顺序

1. ✅ **参数已经正确** - 无需修改
2. 🔧 **添加更详细的执行日志** - 找出失败的确切位置
3. 🔧 **对比真机和unidbg的内存状态** - 找出差异
4. 🔧 **修复状态问题** - 根据差异调整

