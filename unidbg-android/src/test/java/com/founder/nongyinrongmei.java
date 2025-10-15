package com.founder;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory; // 用于指定使用 Unicorn2 后端
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
// import com.github.unidbg.file.linux.LinuxFileSystem; // 如果你直接继承这个了，就不需要
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.dvm.api.ApplicationInfo;
import com.github.unidbg.linux.file.ByteArrayFileIO; // 用来1返回内存中的文件内容
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets; // 用于字符串到字节数组的转换
import java.util.ArrayList;
import java.util.List;

public class nongyinrongmei extends AbstractJni implements IOResolver<AndroidFileIO> {
    private static final String SIG_PAYLOAD = "{uid=33127442，uType=2}";
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
//    private final Module coreModule; // 新增core模块

    nongyinrongmei() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.founder.nongyinrongmei")
                .addBackendFactory(new Unicorn2Factory(true)) // 使用Unicorn2后端
                .build();
        // 获取模拟器内存接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库
        memory.setLibraryResolver(new AndroidResolver(23)); // Android API level 23

        // 创建VM并加载APK
        vm = emulator.createDalvikVM(new File("unidbg-android/apks/nycm/nycm_1.4.3.apk"));
        vm.setJni(this);
        vm.setVerbose(true);

        // 注册虚拟模块，提供一些JNI函数
        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory); // 模拟一些Android系统级JNI函数

        // 将当前类作为 IOResolver 添加到 SyscallHandler
        // 这样 `/dev/__properties__` 和 `/proc/stat` 的文件打开请求就会被 `resolve` 方法捕获
        emulator.getSyscallHandler().addIOResolver(this);

        // 加载目标SO libtiger_tally.so
        DalvikModule dm = vm.loadLibrary("tiger_tally", true); // 直接通过名称加载，APK内部会找到
        module = dm.getModule();

        System.out.println("[*] libtiger_tally.so SO模块加载完成，基地址: 0x" + Long.toHexString(module.base));
        System.out.println("[*] libtiger_tally.so SO模块大小: 0x" + Long.toHexString(module.size));

        dm.callJNI_OnLoad(emulator);
        System.out.println("[*] libtiger_tally.so JNI_OnLoad调用完成");


    }

    public static void main(String[] args) throws FileNotFoundException {
        nongyinrongmei ny = new nongyinrongmei();
        
        // 先调用 genericNt1 初始化
        System.out.println("\n[*] 调用 genericNt1 进行初始化...");
        ny.genericNt1();
        
        // 再调用 genericNt2 初始化
        System.out.println("\n[*] 调用 genericNt2 进行初始化...");
        ny.genericNt2();
        
        // 最后调用 genericNt3 进行签名
        System.out.println("\n[*] 调用 genericNt3...");
        ny.genericNt3();
        
        System.out.println("\nSimulation finished.");
    }


    /**
     * genericNt1 初始化函数
     * JNI签名: genericNt1(ILjava/lang/String;)I
     * 参数1: int - 类型标识 (根据 Frida hook 结果使用 0)
     * 参数2: String - Base64 编码的密钥
     */
    public int genericNt1() {
        System.out.println("[*] 开始调用 genericNt1 初始化...");
        
        // 根据 Frida hook 获取的真实参数
        int paramType = 0;
        String base64Key = "4X_zC41RfHBB7s9FeanZ-_KNcAl-aL94a6nIZ2exvzE3puaq96Lar2Yum1INEGZI3cFcuhC7JqKEhVKLCLy70pW5VXodS7mrDgcwK8ZlrPT7wOixHzzrX-VAPiWB-bD7_aYlxiLtPXOvaxg6IAOXFDKg2c7oY-E5xalntLN3r5s=";
        
        List<Object> list = new ArrayList<>(10);
        
        // 参数1: JNIEnv* env
        list.add(vm.getJNIEnv());
        
        // 参数2: jobject thiz
        DvmObject<?> thiz = vm.resolveClass("com.aliyun.TigerTally.t.B").newObject(null);
        list.add(vm.addLocalObject(thiz));
        
        // 参数3: jint (int类型参数 - 使用 0)
        list.add(paramType);
        
        // 参数4: jstring (String类型参数 - Base64 密钥)
        StringObject strObj = new StringObject(vm, base64Key);
        list.add(vm.addLocalObject(strObj));
        
        System.out.println("[*] genericNt1 参数: int=" + paramType + ", key=" + base64Key);
        
        try {
            // 调用 genericNt1 函数地址: 0xa7be4
            Number result = module.callFunction(emulator, 0xa7be4, list.toArray());
            int returnValue = result.intValue();
            System.out.println("[*] genericNt1 返回值: " + returnValue);
            
            if (returnValue == 0) {
                System.out.println("[*] genericNt1 初始化成功");
            } else {
                System.err.println("[!] genericNt1 返回值异常: " + returnValue);
            }
            
            return returnValue;
        } catch (Exception e) {
            System.err.println("[!] genericNt1 调用异常: " + e.getMessage());
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * genericNt2 初始化函数
     * JNI签名: genericNt2(ILjava/lang/String;)I
     * 参数1: int - 类型标识 (根据 Frida hook 结果使用 2)
     * 参数2: String - Base64 编码的密钥
     */
    public int genericNt2() {
        System.out.println("[*] 开始调用 genericNt2 初始化...");
        
        // 根据 Frida hook 获取的真实参数
        int paramType = 2;
        String base64Key = "7YUXCHMJHa8kxxOknQi1J/GApoBPC/Q+wkYv4Q4ot2LJq3bKzbExKD4XyLbOxiEsxTr8CmZfdOn0l34EaC4HSg==";
        
        List<Object> list = new ArrayList<>(10);
        
        // 参数1: JNIEnv* env
        list.add(vm.getJNIEnv());
        
        // 参数2: jobject thiz
        DvmObject<?> thiz = vm.resolveClass("com.aliyun.TigerTally.t.B").newObject(null);
        list.add(vm.addLocalObject(thiz));
        
        // 参数3: jint (int类型参数 - 使用 2)
        list.add(paramType);
        
        // 参数4: jstring (String类型参数 - Base64 密钥)
        StringObject strObj = new StringObject(vm, base64Key);
        list.add(vm.addLocalObject(strObj));
        
        System.out.println("[*] genericNt2 参数: int=" + paramType + ", key=" + base64Key);
        
        try {
            // 调用 genericNt2 函数 (需要找到对应地址，暂时使用 genericNt1 的地址尝试)
            Number result = module.callFunction(emulator, 0xf304c, list.toArray());
            int returnValue = result.intValue();
            System.out.println("[*] genericNt2 返回值: " + returnValue);
            
            if (returnValue == 0) {
                System.out.println("[*] genericNt2 初始化成功");
            } else {
                System.err.println("[!] genericNt2 返回值异常: " + returnValue);
            }
            
            return returnValue;
        } catch (Exception e) {
            System.err.println("[!] genericNt2 调用异常: " + e.getMessage());
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * genericNt3 函数
     * JNI签名: genericNt3(I[B)Ljava/lang/String;
     * 参数1: int - 签名类型（根据 Frida hook 结果使用 1）
     * 参数2: byte[] - 要签名的数据（Base64 编码格式）
     */
    public String genericNt3() throws FileNotFoundException {
        System.out.println("[*] 开始调用 genericNt3...");

        // 根据 Frida hook 获取的真实数据
        // 原始 Base64 字符串（这是要签名的数据）
        String base64Data = "c2lkPWN4anJiJmNpZD01MTc5MyZ1aWQ9MCZkZXZpY2VJRD1iZGM5Y2MwN2MwZWRhY2E2NTdlMjg3NTBjOGViOGEzYSZzb3VyY2U9NCZzaWduPVlGWFVCZHozR0piaTdnTU5aRGJqQ1U4c3l4VEd3OXgremVWYnBkK0phbmpNaENicjBnZkp4anlRM0tiUlZ5YkIxMUIvamY0UW5MUTZkRTQzMHJFYksvVFBmcWlMNU9FUVRDaEx6NjhXTmVJcnRrcENvcHROQ0dNU1pZUEdOdklRdDFBcUw1T2phUnM4bm05RXFTMnpqNUw0M25jMmRnNjZzd1M0UGVCSnJrUnd6MXpka3RraXFpZXlkclVIMytzSQ==";
        int signType = 1; // 签名类型参数

        List<Object> list = new ArrayList<>(10);

        // 1. JNIEnv* env (JNI固定参数)
        list.add(vm.getJNIEnv());

        // 2. jobject thiz (实例方法的this对象)
        DvmObject<?> thiz = vm.resolveClass("com.aliyun.TigerTally.t.B").newObject(null);
        list.add(vm.addLocalObject(thiz));

        // 3. jint - 第一个业务参数 (对应签名中的 I) - 签名类型标识，使用 1
        list.add(signType);

        // 4. jbyteArray - 第二个业务参数 (对应签名中的 [B) - 要签名的数据
        // 注意：传入的是 Base64 字符串的字节，不是解码后的数据
        byte[] payloadBytes = base64Data.getBytes(StandardCharsets.UTF_8);
        ByteArray byteArray = new ByteArray(vm, payloadBytes);
        list.add(vm.addLocalObject(byteArray));

        System.out.println("[*] genericNt3 参数: signType=" + signType + ", data.length=" + payloadBytes.length);
        System.out.println("[*] genericNt3 数据预览: " + base64Data.substring(0, Math.min(50, base64Data.length())) + "...");

        try {
            // 调用函数
            Number numbers = module.callFunction(emulator, 0xf3248, list.toArray());

            if (numbers.intValue() == -1) {
                System.err.println("[!] 函数调用失败，返回值为-1");
                return null;
            }

            DvmObject<?> object = vm.getObject(numbers.intValue());
            if (object == null) {
                System.out.println("[!] 获取返回对象失败");
                return null;
            }

            String result = (String) object.getValue();
            System.out.println("[*] genericNt3 签名结果: " + result);
            return result;
        } catch (Exception e) {
            System.err.println("[!] genericNt3 调用异常: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    /**
     * 字节数组转字符串工具方法
     */
    private String bytesToString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(b & 0xFF).append(",");
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1); // 移除最后一个逗号
        }
        return sb.toString();
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/aliyun/TigerTally/A->ct()Landroid/content/Context;":
                DvmObject<?> dvmObject = vm.resolveClass("android/content/Context").newObject(null);
                return dvmObject;
            case "com/aliyun/TigerTally/A->pb(Ljava/lang/String;[B)Ljava/lang/String;":
                StringObject stringObject = new StringObject(vm, "");
                return stringObject;
            case "com/aliyun/TigerTally/A->bt()Landroid/content/Intent;":
                DvmObject<?> dvmObject1 = vm.resolveClass("android/content/Intent").newObject(null);
                return dvmObject1;

            case "com/aliyun/TigerTally/s/A->ct()Landroid/content/Context;":
                DvmObject<?> dvmObject2 = vm.resolveClass("android/content/Context").newObject(null);
                return dvmObject2;


        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "com/aliyun/TigerTally/s/A$AA-><init>()V":
                return vm.resolveClass("com/aliyun/TigerTally/s/A$AA").newObject(signature);
            case "com/aliyun/TigerTally/s/A$BB-><init>()V":
                return vm.resolveClass("com/aliyun/TigerTally/s/A$BB").newObject(signature);

        }
        return super.newObjectV(vm,dvmClass,signature,vaList);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/os/Build$VERSION->SDK_INT:I".equals(signature)) {
            return 30;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }


    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("android/content/Intent->getIntExtra(Ljava/lang/String;I)I".equals(signature)) {
            return 262;
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        System.out.println("callObjectMethod");
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "android/os/Build->BRAND:Ljava/lang/String;":
                StringObject stringObject = new StringObject(vm, "Xiaomi");
                return stringObject;
            case "android/os/Build->MODEL:Ljava/lang/String;":
                StringObject brandObj = new StringObject(vm, "MI 9");
                return brandObj;
            case "android/os/Build$VERSION->RELEASE:Ljava/lang/String;":
                StringObject stringObject1 = new StringObject(vm, "11");
                return stringObject1;
            case "android/os/Build->DEVICE:Ljava/lang/String;":
                StringObject stringObject2 = new StringObject(vm, "cepheus");
                return stringObject2;
            case "android/os/Build->PRODUCT:Ljava/lang/String;":
                StringObject stringObject3 = new StringObject(vm, "cepheus");
                return stringObject3;
            case "android/os/Build->HOST:Ljava/lang/String;":
                StringObject stringObject4 = new StringObject(vm, "");
                return stringObject4;
            case "android/os/Build->HARDWARE:Ljava/lang/String;":
                StringObject stringObject8 = new StringObject(vm, "qcom");
                return stringObject8;
            case "android/os/Build->TAGS:Ljava/lang/String;":
                StringObject stringObject5 = new StringObject(vm, "release-keys");
                return stringObject5;
            case "android/os/Build->FINGERPRINT:Ljava/lang/String;":
                StringObject stringObject6 = new StringObject(vm, "keys");
                return stringObject6;
            case "android/os/Build->MANUFACTURER:Ljava/lang/String;":
                StringObject stringObject7 = new StringObject(vm, "Xiaomi");
                return stringObject7;
            case "android/os/Build->SUPPORTED_ABIS:[Ljava/lang/String;":
                StringObject stringObject9 = new StringObject(vm, "arm64-v8a");
                ArrayObject arrayObject = new ArrayObject(stringObject9);
                return arrayObject;

        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/content/pm/PackageManager->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
            case "android/content/pm/PackageManager->getApplicationLabel(Landroid/content/pm/ApplicationInfo;)Ljava/lang/CharSequence;":
                StringObject stringObject = new StringObject(vm, "iBox");
                return stringObject;
            case "android/content/Context->getFilesDir()Ljava/io/File;":
                File file = new File("/unidbg-master_0.97/unidbg-android/src/test/java/com/ibox/files");
                DvmObject<?> dvmObject1 = vm.resolveClass("java/io/File").newObject(file);
                return dvmObject1;
            case "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                DvmObject<?> dvmObject2 = vm.resolveClass("android/content/SharedPreferences").newObject(null);
                return dvmObject2;
//            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
//                System.out.println("getString " + vaList.getObjectArg(0).toString());
//                DvmObject<?> objectArg = vaList.getObjectArg(0);
//                if (objectArg.getValue().toString().equals("tt_ak")) {
//                    long currentTimeMillis = System.currentTimeMillis();
//                    StringObject stringObject1 = new StringObject(vm, "^" + currentTimeMillis+"^86400");
//                    return stringObject1;
//                } else if (objectArg.getValue().toString().equals("TT_COOKIEID")) {
//                    StringObject stringObject1 = new StringObject(vm, "TDluNPJxJtm0/u6f9OKjjGbqudrxW1wN4wftIv5Mu6wKhOsbK3Vu7GcO+fn4SaxwlzfGqH0ZPmf7z0ZGc5by6g==");
//                    return stringObject1;
//                }
//                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
            case "android/content/SharedPreferences->edit()Landroid/content/SharedPreferences$Editor;":
                DvmObject<?> dvmObject3 = vm.resolveClass("android/content/SharedPreferences$Editor").newObject(null);
                return dvmObject3;
            case "android/content/SharedPreferences$Editor->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;":
                Object value = dvmObject.getValue();
                DvmObject<?> dvmObject4 = vm.resolveClass("android/content/SharedPreferences$Editor").newObject(value);
                return dvmObject4;
            case "com/aliyun/TigerTally/s/A$AA->en(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"eb32139f977b4e12abca93113c3d8486557dfeb");
            case "com/aliyun/TigerTally/s/A$BB->en(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"eb32139f977b4e12abca93113c3d8486557dfeb");
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");

            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                return vm.resolveClass("Landroid/content/SharedPreferences;");
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }


    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("android/content/SharedPreferences$Editor->commit()Z".equals(signature)) {
            return true;
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->firstInstallTime:J".equals(signature)) {
            return 1653742840932L;
        } else if ("android/content/pm/PackageInfo->lastUpdateTime:J".equals(signature)) {
            long currentTimeMillis = System.currentTimeMillis();
            return currentTimeMillis;
        }
        return super.getLongField(vm, dvmObject, signature);
    }

//    public static void main(String[] args) {
//        IboxTest iboxTest = new IboxTest();
//        iboxTest.init();
//        iboxTest.getWtoken("{\"albumId\":100513930}");
//    }
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println(pathname);
        if ("/proc/self/maps".equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, new File("/Users/maps"), pathname));
        } else if ("/proc/stat".equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, new File("/Users/yml/IdeaProjects/unidbg_1/unidbg-android/src/test/java/com/rootfs/stat"), pathname));
        }
        return null;
    }

}
