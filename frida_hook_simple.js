/**
 * Frida Hook脚本 - 简化版
 * 专注于捕获加密调用的核心参数
 */

console.log("[*] 快手极速版加密分析 - 简化版");

Java.perform(function() {

    // 字节数组转Hex
    function bytes2hex(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            var hex = (array[i] & 0xFF).toString(16);
            if (hex.length === 1) hex = '0' + hex;
            result += hex;
        }
        return result.toUpperCase();
    }

    // Hook doCommandNative
    var JNICLibrary = Java.use("com.kuaishou.android.security.internal.dispatch.JNICLibrary");

    JNICLibrary.doCommandNative.implementation = function(opcode, params) {
        console.log("\n" + "=".repeat(60));
        console.log("[doCommandNative] Opcode: " + opcode);

        // 只关注加密相关的opcode
        if (opcode === 10400 || opcode === 10408 || opcode === 10412) {
            console.log("\n[参数数组] 长度: " + params.length);

            for (var i = 0; i < params.length; i++) {
                var param = params[i];
                if (param === null) {
                    console.log("  [" + i + "] null");
                } else if (param.$className === "[B") {
                    console.log("  [" + i + "] byte[" + param.length + "]");
                    if (param.length < 1000) {
                        console.log("      Hex: " + bytes2hex(param));
                    } else {
                        var preview = [];
                        for (var j = 0; j < 100; j++) preview.push(param[j]);
                        console.log("      Hex(前100): " + bytes2hex(preview) + "...");
                    }
                } else if (param.$className === "java.lang.String") {
                    console.log("  [" + i + "] String: \"" + param.toString() + "\"");
                } else if (param.$className === "java.lang.Integer") {
                    console.log("  [" + i + "] Integer: " + param.intValue());
                } else if (param.$className === "java.lang.Boolean") {
                    console.log("  [" + i + "] Boolean: " + param.booleanValue());
                } else {
                    console.log("  [" + i + "] " + param.$className);
                }
            }
        }

        // 调用原方法
        var result = this.doCommandNative(opcode, params);

        // 打印返回值
        if (result === null) {
            console.log("\n[返回] null");
        } else if (result.$className === "[B") {
            console.log("\n[返回] byte[" + result.length + "]");
            if (result.length < 1000) {
                console.log("  Hex: " + bytes2hex(result));
            } else {
                var preview = [];
                for (var i = 0; i < 200; i++) preview.push(result[i]);
                console.log("  Hex(前200): " + bytes2hex(preview) + "...");
            }
        } else {
            console.log("\n[返回] " + result);
        }

        console.log("=".repeat(60) + "\n");

        return result;
    };

    console.log("[✓] Hook完成，等待调用...");
});
