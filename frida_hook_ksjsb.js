/**
 * Frida Hook脚本 - 快手极速版加密分析
 * 目标：捕获真实设备上的所有关键调用和参数
 * 使用方法：
 *   1. 手机连接电脑，开启USB调试
 *   2. frida -U -f com.kuaishou.nebula -l frida_hook_ksjsb.js
 *   或者附加到运行中的进程：
 *   3. frida -U com.kuaishou.nebula -l frida_hook_ksjsb.js
 */

console.log("[*] Frida Hook Script Loaded - 快手极速版加密分析");
console.log("[*] 目标：捕获 doCommandNative 的完整调用链");

// ============ 工具函数 ============

/**
 * 字节数组转十六进制字符串
 */
function bytes2hex(array) {
    if (!array || array.length === 0) return "";
    var result = "";
    for (var i = 0; i < array.length; i++) {
        var hex = (array[i] & 0xFF).toString(16);
        if (hex.length === 1) hex = '0' + hex;
        result += hex;
    }
    return result.toUpperCase();
}

/**
 * 打印Java对象的详细信息
 */
function dumpObject(obj, name, depth) {
    depth = depth || 0;
    if (depth > 3) return "..."; // 防止递归过深

    if (obj === null || obj === undefined) {
        return name + " = null";
    }

    var indent = "  ".repeat(depth);
    var result = indent + name + " = " + obj.$className + " {\n";

    try {
        // 获取对象的所有方法
        var methods = obj.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var method = methods[i];
            var methodName = method.getName();

            // 只调用简单的getter方法
            if (methodName.startsWith("get") && method.getParameterTypes().length === 0) {
                try {
                    method.setAccessible(true);
                    var value = method.invoke(obj, []);
                    result += indent + "  " + methodName + "() = " + value + "\n";
                } catch (e) {
                    // 忽略调用失败的方法
                }
            }
        }
    } catch (e) {
        result += indent + "  (无法获取方法列表)\n";
    }

    result += indent + "}";
    return result;
}

/**
 * 打印数组内容
 */
function dumpArray(arr, name) {
    if (!arr) return name + " = null";

    var result = name + " = Array[" + arr.length + "] {\n";
    for (var i = 0; i < arr.length; i++) {
        var item = arr[i];
        if (item === null) {
            result += "  [" + i + "] = null\n";
        } else if (item.$className) {
            // Java对象
            result += "  [" + i + "] = " + item.$className + "\n";

            // 特殊处理某些类型
            if (item.$className === "[B") {
                // byte数组
                var bytes = [];
                for (var j = 0; j < Math.min(item.length, 100); j++) {
                    bytes.push(item[j]);
                }
                var hex = bytes2hex(bytes);
                result += "      长度=" + item.length + ", Hex=" + hex;
                if (item.length > 100) result += "...";
                result += "\n";
            } else if (item.$className === "java.lang.String") {
                result += "      值=\"" + item.toString() + "\"\n";
            } else if (item.$className === "java.lang.Integer") {
                result += "      值=" + item.intValue() + "\n";
            } else if (item.$className === "java.lang.Boolean") {
                result += "      值=" + item.booleanValue() + "\n";
            }
        } else {
            result += "  [" + i + "] = " + item + "\n";
        }
    }
    result += "}";
    return result;
}

/**
 * 打印栈轨迹
 */
function printStackTrace() {
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("trace");
    var straces = ins.getStackTrace();
    if (straces != undefined && straces != null) {
        var result = "调用栈:\n";
        for (var i = 0; i < straces.length; i++) {
            result += "    " + straces[i].toString() + "\n";
        }
        return result;
    }
    return "";
}

// ============ 开始Hook ============

Java.perform(function() {
    console.log("\n[*] ========== 开始Hook Java层 ==========\n");

    // ===== 1. Hook doCommandNative 主函数 =====
    try {
        var JNICLibrary = Java.use("com.kuaishou.android.security.internal.dispatch.JNICLibrary");
        console.log("[✓] 找到类: JNICLibrary");

        // Hook doCommandNative 方法
        JNICLibrary.doCommandNative.implementation = function(opcode, params) {
            console.log("\n" + "=".repeat(80));
            console.log("[🎯 doCommandNative 调用] Opcode: " + opcode + " (0x" + opcode.toString(16) + ")");
            console.log("=".repeat(80));

            // 解析opcode类型
            var opcodeDesc = "";
            switch(opcode) {
                case 10400: opcodeDesc = "加密请求 (ByteArray)"; break;
                case 10408: opcodeDesc = "加密请求 (HexString)"; break;
                case 10412: opcodeDesc = "初始化环境"; break;
                case 10414: opcodeDesc = "未知操作"; break;
                case 10418: opcodeDesc = "签名验证"; break;
                default: opcodeDesc = "未知opcode";
            }
            console.log("[Opcode] 类型: " + opcodeDesc);

            // 打印参数数组
            console.log("\n[参数详情]");
            console.log(dumpArray(params, "params"));

            // 打印调用栈
            console.log("\n" + printStackTrace());

            // 调用原始方法
            console.log("\n[→] 调用原始 doCommandNative...");
            var startTime = Date.now();
            var result = this.doCommandNative(opcode, params);
            var endTime = Date.now();

            // 打印返回值
            console.log("\n[← 返回值] 耗时: " + (endTime - startTime) + "ms");
            if (result === null) {
                console.log("  返回: null");
            } else if (result.$className === "[B") {
                // byte数组
                var bytes = [];
                for (var i = 0; i < Math.min(result.length, 200); i++) {
                    bytes.push(result[i]);
                }
                var hex = bytes2hex(bytes);
                console.log("  返回: byte[" + result.length + "]");
                console.log("  Hex: " + hex);
                if (result.length > 200) {
                    console.log("  (仅显示前200字节)");
                }
            } else {
                console.log("  返回: " + result);
            }

            console.log("=".repeat(80) + "\n");

            return result;
        };
        console.log("[✓] Hook doCommandNative 成功");

    } catch (e) {
        console.log("[✗] Hook doCommandNative 失败: " + e);
    }

    // ===== 2. Hook getSecEnvValue (关键：环境检测) =====
    try {
        var JNICLibrary = Java.use("com.kuaishou.android.security.internal.dispatch.JNICLibrary");
        JNICLibrary.getSecEnvValue.implementation = function() {
            var result = this.getSecEnvValue();
            console.log("\n[🔍 getSecEnvValue] 返回: " + result);
            console.log("  说明: 0=正常环境, 1=检测到异常");
            return result;
        };
        console.log("[✓] Hook getSecEnvValue 成功");
    } catch (e) {
        console.log("[✗] Hook getSecEnvValue 失败: " + e);
    }

    // ===== 3. Hook canRun (关键：运行权限检查) =====
    try {
        var JNICLibrary = Java.use("com.kuaishou.android.security.internal.dispatch.JNICLibrary");
        JNICLibrary.canRun.implementation = function(param) {
            var result = this.canRun(param);
            console.log("\n[🔍 canRun] 参数: " + param + ", 返回: " + result);
            console.log("  说明: 1=允许运行, 0=禁止运行");
            return result;
        };
        console.log("[✓] Hook canRun 成功");
    } catch (e) {
        console.log("[✗] Hook canRun 失败: " + e);
    }

    // ===== 4. Hook ExceptionProxy.nativeReport (捕获错误) =====
    try {
        var ExceptionProxy = Java.use("com.kuaishou.android.security.internal.common.ExceptionProxy");
        ExceptionProxy.nativeReport.implementation = function(code, message) {
            console.log("\n[❌ nativeReport] 错误报告:");
            console.log("  错误码: " + code + " (0x" + code.toString(16) + ")");
            console.log("  消息: " + message);

            // 解析错误码
            var errorDesc = "";
            switch(code) {
                case 0x111b7: errorDesc = "APK签名验证失败 - ZIP读取/解析错误"; break;
                case 0x111bc: errorDesc = "证书链验证失败"; break;
                case 0x11180: errorDesc = "包名/签名不在白名单"; break;
                case 0x11178: errorDesc = "初始化相关错误"; break;
                case 0x11172: errorDesc = "环境检测失败"; break;
                case 0x1117e: errorDesc = "加密前置条件未满足"; break;
                case 0x111e5: errorDesc = "全局标志位检查失败"; break;
            }
            if (errorDesc) {
                console.log("  说明: " + errorDesc);
            }

            console.log("\n" + printStackTrace());

            // 调用原方法
            this.nativeReport(code, message);
        };
        console.log("[✓] Hook nativeReport 成功");
    } catch (e) {
        console.log("[✗] Hook nativeReport 失败: " + e);
    }

    // ===== 5. Hook PackageManager.getPackageInfo (签名获取) =====
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            console.log("\n[🔍 getPackageInfo] 包名: " + packageName + ", flags: 0x" + flags.toString(16));
            console.log("  GET_SIGNATURES: " + ((flags & 0x40) !== 0));
            console.log("  GET_SIGNING_CERTIFICATES: " + ((flags & 0x8000000) !== 0));

            var result = this.getPackageInfo(packageName, flags);

            // 打印签名信息
            if (result.signatures && result.signatures.value) {
                console.log("  签名数量: " + result.signatures.value.length);
                for (var i = 0; i < result.signatures.value.length; i++) {
                    var sig = result.signatures.value[i];
                    var bytes = sig.toByteArray();
                    console.log("  签名[" + i + "] 长度: " + bytes.length);

                    // 计算MD5
                    var MessageDigest = Java.use("java.security.MessageDigest");
                    var md = MessageDigest.getInstance("MD5");
                    var hash = md.digest(bytes);
                    console.log("  签名[" + i + "] MD5: " + bytes2hex(hash));
                }
            }

            return result;
        };
        console.log("[✓] Hook getPackageInfo 成功");
    } catch (e) {
        console.log("[✗] Hook getPackageInfo 失败: " + e);
    }

    // ===== 6. Hook Context相关方法 =====
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");

        // getPackageName
        ContextWrapper.getPackageName.implementation = function() {
            var result = this.getPackageName();
            console.log("[🔍 getPackageName] 返回: " + result);
            return result;
        };

        // getPackageCodePath
        ContextWrapper.getPackageCodePath.implementation = function() {
            var result = this.getPackageCodePath();
            console.log("[🔍 getPackageCodePath] 返回: " + result);
            return result;
        };

        console.log("[✓] Hook Context方法 成功");
    } catch (e) {
        console.log("[✗] Hook Context方法 失败: " + e);
    }

    console.log("\n[*] ========== Java层Hook完成 ==========\n");
});

// ============ Hook Native层 ============

console.log("\n[*] ========== 开始Hook Native层 ==========\n");

// 等待libkwsgmain.so加载
var libkwsgmain = null;
var checkInterval = setInterval(function() {
    libkwsgmain = Process.findModuleByName("libkwsgmain.so");
    if (libkwsgmain) {
        clearInterval(checkInterval);
        console.log("[✓] 找到 libkwsgmain.so");
        console.log("  Base: " + libkwsgmain.base);
        console.log("  Size: 0x" + libkwsgmain.size.toString(16));

        // Hook JNI_OnLoad
        hookJNIOnLoad();

        // Hook doCommandNative native实现
        hookDoCommandNative();

        // Hook 关键反调试检查点
        hookAntiDebugChecks();

        // Hook 签名验证函数
        hookSignatureVerification();

        console.log("\n[*] ========== Native层Hook完成 ==========\n");
    }
}, 100);

/**
 * Hook JNI_OnLoad
 */
function hookJNIOnLoad() {
    try {
        var JNI_OnLoad = libkwsgmain.base.add(0x45670); // 根据IDA分析的偏移
        console.log("\n[Hook] JNI_OnLoad @ " + JNI_OnLoad);

        Interceptor.attach(JNI_OnLoad, {
            onEnter: function(args) {
                console.log("\n[→ JNI_OnLoad] JavaVM: " + args[0]);
            },
            onLeave: function(retval) {
                console.log("[← JNI_OnLoad] 返回: " + retval);
            }
        });
    } catch (e) {
        console.log("[✗] Hook JNI_OnLoad 失败: " + e);
    }
}

/**
 * Hook doCommandNative native实现
 */
function hookDoCommandNative() {
    try {
        var doCommandNative = libkwsgmain.base.add(0x40cd4); // 从你的代码中看到的偏移
        console.log("\n[Hook] doCommandNative @ " + doCommandNative);

        Interceptor.attach(doCommandNative, {
            onEnter: function(args) {
                // JNI函数签名: jint doCommandNative(JNIEnv* env, jobject thiz, jint opcode, jobjectArray params)
                this.env = args[0];
                this.thiz = args[1];
                this.opcode = args[2].toInt32();
                this.params = args[3];

                console.log("\n[→ Native doCommandNative]");
                console.log("  Opcode: " + this.opcode + " (0x" + this.opcode.toString(16) + ")");
                console.log("  JNIEnv: " + this.env);
                console.log("  jobject: " + this.thiz);
                console.log("  params: " + this.params);
            },
            onLeave: function(retval) {
                console.log("[← Native doCommandNative] 返回: " + retval);
            }
        });
    } catch (e) {
        console.log("[✗] Hook doCommandNative 失败: " + e);
    }
}

/**
 * Hook 反调试检查点
 */
function hookAntiDebugChecks() {
    try {
        // 监控 dword_70C10 和 dword_70C14 的读写
        var dword_70C10 = libkwsgmain.base.add(0x70C10);
        var dword_70C14 = libkwsgmain.base.add(0x70C14);

        console.log("\n[Monitor] 反调试变量:");
        console.log("  dword_70C10 @ " + dword_70C10);
        console.log("  dword_70C14 @ " + dword_70C14);

        // 读取初始值
        var value1 = dword_70C10.readS32();
        var value2 = dword_70C14.readS32();
        console.log("  初始值: dword_70C10=" + value1 + ", dword_70C14=" + value2);

        // 设置内存断点 (仅在支持的平台上)
        if (Process.arch === 'arm64') {
            // 注意：Frida的内存访问监控在某些设备上可能不稳定
            console.log("  (内存断点需要root权限，当前仅记录初始值)");
        }

    } catch (e) {
        console.log("[✗] Hook 反调试检查 失败: " + e);
    }
}

/**
 * Hook 签名验证函数 sub_3E5C0
 */
function hookSignatureVerification() {
    try {
        var sub_3E5C0 = libkwsgmain.base.add(0x3E5C0);
        console.log("\n[Hook] 签名验证函数 sub_3E5C0 @ " + sub_3E5C0);

        Interceptor.attach(sub_3E5C0, {
            onEnter: function(args) {
                console.log("\n[→ sub_3E5C0] 签名验证开始");
                console.log("  参数: " + args[0] + ", " + args[1]);
            },
            onLeave: function(retval) {
                console.log("[← sub_3E5C0] 返回: " + retval);
                if (retval.toInt32() === 0) {
                    console.log("  ⚠️ 签名验证失败！");
                } else {
                    console.log("  ✓ 签名验证通过");
                }
            }
        });
    } catch (e) {
        console.log("[✗] Hook 签名验证 失败: " + e);
    }
}

console.log("\n[*] ========== 所有Hook设置完成 ==========");
console.log("[*] 等待应用调用目标函数...\n");
