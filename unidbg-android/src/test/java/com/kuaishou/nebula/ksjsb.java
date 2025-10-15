package com.kuaishou.nebula;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import unicorn.Arm64Const;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ksjsb extends AbstractJni implements IOResolver {
    private static final String SIG_PAYLOAD = "{\"appver\":\"13.8.40.10657\",\"did\":\"ANDROID_191d74724559169d\",\"uid\":\"4435885561\",\"shell_ver\":\"1.0.0.162.39e5b6cc\",\"platform\":\"Android\",\"interpreter_ver\":\"1.7.3.118\",\"appkey\":\"d7b7d042-d4f2-4012-be60-d97ff2429c17\",\"abi\":\"arm64-v8a\",\"kpn\":\"NEBULA\"}";
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Module coreModule; // 新增core模块

    ksjsb() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.kuaishou.nebula")
                .addBackendFactory(new Unicorn2Factory(true)) // 使用Unicorn2后端
                .build();
        // 获取模拟器内存接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库
        memory.setLibraryResolver(new AndroidResolver(23)); // Android API level 23

        // 创建VM并加载APK
//        vm = emulator.createDalvikVM(new File("unidbg-android/apks/ksjsb/ksjsb_12.7.20.8502.apk"));
        vm = emulator.createDalvikVM(new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk"));
        vm.setJni(this);
        vm.setVerbose(true);

        // 注册虚拟模块，提供一些JNI函数
        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory); // 模拟一些Android系统级JNI函数

        // 将当前类作为 IOResolver 添加到 SyscallHandler
        // 这样 `/dev/__properties__` 和 `/proc/stat` 的文件打开请求就会被 `resolve` 方法捕获
        emulator.getSyscallHandler().addIOResolver(this);

        // 加载目标SO

        // 加载libcore.so
        DalvikModule sgDm = vm.loadLibrary("core", true);
        coreModule = sgDm.getModule();

        System.out.println("[*] libcore.so模块加载完成，基地址: 0x" + Long.toHexString(coreModule.base));
        System.out.println("[*] libcore.so模块大小: 0x" + Long.toHexString(coreModule.size));

        sgDm.callJNI_OnLoad(emulator);
        System.out.println("[*] libcore.so JNI_OnLoad调用完成");


        DalvikModule dm = vm.loadLibrary("kwsgmain", true); // 直接通过名称加载，APK内部会找到
        module = dm.getModule();

        System.out.println("[*] kwsgmain SO模块加载完成，基地址: 0x" + Long.toHexString(module.base));
        System.out.println("[*] kwsgmain SO模块大小: 0x" + Long.toHexString(module.size));

        dm.callJNI_OnLoad(emulator);
        System.out.println("[*] kwsgmain JNI_OnLoad调用完成");

        // 添加0x9c00内存映射和Hook
        map0x9c00Memory();
        System.out.println("[*] 0x9c00内存映射和Hook已设置");
    }

    public static void main(String[] args) throws FileNotFoundException {
        ksjsb ks = new ksjsb();
        System.out.println("Calling callByAddress...");
        ks.callByAddress();
        System.out.println("\nCalling get_NS_sig3 to initialize environment...");
        ks.get_NS_sig3();

        // 在调用 sign_64 之前,先调用初始化函数
        System.out.println("\nCalling initialization functions before sign_64...");
        ks.call_gKSF();
        ks.call_gDBF();

        System.out.println("\nCalling sign_64...");
        ks.sign_64();
//        System.out.println("\nTesting libcore.so functions...");
//        ks.getSig();
        System.out.println("\nSimulation finished.");
    }

    public void callByAddress() {
        List<Object> list = new ArrayList<>(4);
        list.add(vm.getJNIEnv()); // 第⼀个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。
        DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null); // context
        vm.addLocalObject(context);
        list.add(10412); // opcode参数
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        DvmInteger intergetobj = DvmInteger.valueOf(vm, 0);
        vm.addLocalObject(intergetobj);
        list.add(vm.addLocalObject(new ArrayObject(null, appkey, null, null, context, null, null)));
        // 直接通过地址调⽤
        Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
        System.out.println("numbers:" + numbers);
        DvmObject<?> object = vm.getObject(numbers.intValue());
        String result = (String) object.getValue();
        System.out.println("result:" + result);
    }

    public String get_NS_sig3() throws FileNotFoundException {
        // 确保 traceCode 在调用目标函数前被调用
//        traceCode();

        System.out.println("[*] 开始构造参数...");
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第⼀个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。
        DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null); // context com.yxcorp.gifshow.App
        vm.addLocalObject(context);
        list.add(10418); //参数1
        StringObject payloadObj = new StringObject(vm, SIG_PAYLOAD);
        vm.addLocalObject(payloadObj);
        ArrayObject arrayObject = new ArrayObject(payloadObj);
        vm.addLocalObject(arrayObject);
        System.out.println("[*] 创建了字符串数组对象");
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        DvmInteger intergetobj = DvmInteger.valueOf(vm, -1);
        vm.addLocalObject(intergetobj);
        DvmBoolean boolobj = DvmBoolean.valueOf(vm, false);
        vm.addLocalObject(boolobj);

        DvmBoolean boolobjTrue = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolobjTrue);
        StringObject appkey2 = new StringObject(vm, "010a11c6-f2cb-4016-887d-0d958aef1534");
        vm.addLocalObject(appkey2);
        list.add(vm.addLocalObject(new ArrayObject(arrayObject, appkey, intergetobj, boolobj, context, null, boolobj, null)));
        System.out.println("[*] 参数构造完成，准备调用函数...");
        System.out.println("[*] 参数列表大小: " + list.size());

        try {
            // 添加更多调试信息
            System.out.println("[*] 正在调用函数地址: 0x" + Long.toHexString(0x40cd4));
            System.out.println("[*] 模块基地址: 0x" + Long.toHexString(module.base));

            Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
            System.out.println("numbers:" + numbers);
            System.out.println("[*] 函数执行完成，返回值: " + numbers.intValue());

            if (numbers.intValue() == -1) {
                System.err.println("[!] 函数调用失败，返回值为-1");
                System.err.println("[!] 这可能是由于环境检测、文件访问或系统调用失败导致的");
                System.err.println("[!] 但根据Frida hook，真实环境下函数是成功的");
                return null;
            }

            DvmObject<?> object = vm.getObject(numbers.intValue());
            if (object == null) {
                System.out.println("获取返回对象失败");
                return null;
            }
            String result = (String) object.getValue();
            System.out.println("result:" + result);
            return result;
        } catch (Exception e) {
            System.err.println("[!] 函数调用发生异常: " + e.getMessage());
            e.printStackTrace();

            // 尝试从异常中获取更多信息
            if (e.getMessage().contains("UC_ERR_FETCH_UNMAPPED")) {
                System.err.println("[!] 内存访问错误 - 可能需要额外的内存映射或初始化");
            }
            return null;
        }
    }

    /**
     * 调用 gKSF() 初始化函数 - 可能用于初始化64位签名所需的函数指针表
     * 根据 RegisterNative 日志:
     * - RegisterNative(com/kuaishou/android/security/internal/dispatch/JNICLibrary, gKSF()J, RX@0x123807f0[libkwsgmain.so]0x407f0)
     */
    public long call_gKSF() {
        System.out.println("[*] 调用 gKSF() 初始化函数...");
        List<Object> list = new ArrayList<>(2);
        list.add(vm.getJNIEnv());
        list.add(0); // 静态方法，jclass参数

        try {
            Number result = module.callFunction(emulator, 0x407f0, list.toArray());
            long value = result.longValue();
            System.out.println("[*] gKSF() 返回值: " + value + " (0x" + Long.toHexString(value) + ")");
            return value;
        } catch (Exception e) {
            System.err.println("[!] gKSF() 调用失败: " + e.getMessage());
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * 调用 gDBF() 初始化函数 - 可能用于初始化设备指纹
     * 根据 RegisterNative 日志:
     * - RegisterNative(com/kuaishou/android/security/internal/dispatch/JNICLibrary, gDBF()J, RX@0x123808a4[libkwsgmain.so]0x408a4)
     */
    public long call_gDBF() {
        System.out.println("[*] 调用 gDBF() 初始化函数...");
        List<Object> list = new ArrayList<>(2);
        list.add(vm.getJNIEnv());
        list.add(0); // 静态方法，jclass参数

        try {
            Number result = module.callFunction(emulator, 0x408a4, list.toArray());
            long value = result.longValue();
            System.out.println("[*] gDBF() 返回值: " + value + " (0x" + Long.toHexString(value) + ")");
            return value;
        } catch (Exception e) {
            System.err.println("[!] gDBF() 调用失败: " + e.getMessage());
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * 获取64位签名 - 参考sig3的逻辑，但param6设置为true，并增加uuid参数
     * 根据Frida脚本:
     * - opcode: 10418
     * - payload: null 或空字符串数组
     * - deviceId: "d7b7d042-d4f2-4012-be60-d97ff2429c17"
     * - param2: -1
     * - param3: false
     * - param5: null
     * - param6: true  (关键：改为true以获取64位签名)
     * - uuid: "010a11c6-f2cb-4016-887d-0d958aef1534"
     * <p>
     * 注意: 根据get_NS_sig3的成功执行，第7个参数应该是UUID而不是null
     * get_NS_sig3使用的第7个参数是: "95147564-9763-4413-a937-6f0e3c12caf1"
     * sign_64可能需要使用不同的UUID或者需要先调用初始化方法
     */
    public String sign_64() throws FileNotFoundException {
        System.out.println("[*] 开始构造sign_64参数...");
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。
        DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null); // context com.yxcorp.gifshow.App
        vm.addLocalObject(context);
        list.add(10418); //参数1
        StringObject payloadObj = new StringObject(vm, SIG_PAYLOAD);
        vm.addLocalObject(payloadObj);
        ArrayObject arrayObject = new ArrayObject(payloadObj);
        vm.addLocalObject(arrayObject);
        System.out.println("[*] 创建了字符串数组对象");
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        DvmInteger intergetobj = DvmInteger.valueOf(vm, -1);
        vm.addLocalObject(intergetobj);
        DvmBoolean boolobj = DvmBoolean.valueOf(vm, false);
        vm.addLocalObject(boolobj);

        DvmBoolean boolobjTrue = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolobjTrue);
        StringObject appkey2 = new StringObject(vm, "010a11c6-f2cb-4016-887d-0d958aef1534");
        vm.addLocalObject(appkey2);
        // 关键变化: 第6位使用 boolobjTrue (true)，第7位使用 appkey2 (UUID字符串)
        list.add(vm.addLocalObject(new ArrayObject(arrayObject, appkey, intergetobj, boolobjTrue, context, null, boolobjTrue, appkey2)));

        System.out.println("[*] 参数构造完成，准备调用函数...");
        System.out.println("[*] 参数列表大小: " + list.size());
        System.out.println("[*] param6(64位标志): true");
        System.out.println("[*] uuid: 010a11c6-f2cb-4016-887d-0d958aef1534");
        System.out.println("[*] 参数数组: [payload, deviceId, -1, false, context, null, true, uuid]");

        try {
            System.out.println("[*] 正在调用函数地址: 0x" + Long.toHexString(0x40cd4));
            System.out.println("[*] 模块基地址: 0x" + Long.toHexString(module.base));

            Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
            System.out.println("numbers:" + numbers);
            System.out.println("[*] 函数执行完成，返回值: " + numbers.intValue());

            if (numbers.intValue() == -1) {
                System.err.println("[!] 函数调用失败，返回值为-1");
                System.err.println("[!] 错误原因:");
                System.err.println("[!]   - 可能是UUID未初始化或无效");
                System.err.println("[!]   - 可能需要先调用某个初始化函数");
                System.err.println("[!]   - 可能是环境检测失败(错误码: 0x111e5)");
                System.err.println("[!] 建议:");
                System.err.println("[!]   1. 检查UUID是否需要通过其他接口获取");
                System.err.println("[!]   2. 尝试在调用前先执行get_NS_sig3初始化环境");
                System.err.println("[!]   3. 检查是否需要额外的JNI hook来处理某些调用");
                return null;
            }

            DvmObject<?> object = vm.getObject(numbers.intValue());
            if (object == null) {
                System.out.println("[!] 获取返回对象失败");
                return null;
            }

            String result = (String) object.getValue();
            System.out.println("[*] ========== sign_64 结果 ==========");
            System.out.println("[*] 64位签名: " + result);
            System.out.println("[*] 签名长度: " + (result != null ? result.length() : 0));
            System.out.println("[*] ====================================");
            return result;

        } catch (Exception e) {
            System.err.println("[!] 函数调用发生异常: " + e.getMessage());
            e.printStackTrace();

            if (e.getMessage().contains("UC_ERR_FETCH_UNMAPPED")) {
                System.err.println("[!] 内存访问错误 - 可能需要额外的内存映射或初始化");
                System.err.println("[!] 内存访问地址: 0x9c00");
                System.err.println("[!] 这个地址看起来是一个很小的偏移量，可能是:");
                System.err.println("[!]   1. 空指针解引用");
                System.err.println("[!]   2. UUID字符串未正确初始化");
                System.err.println("[!]   3. 需要hook额外的JNI方法");
            }
            return null;
        }
    }


    /**
     * 测试libcore.so的getClock功能 - 根据主动调用日志
     */
    public void getClock_bak() {
        System.out.println("[*] 开始测试libcore.so的getClock功能...");
        // 尝试直接通过地址调用
        try {
            System.out.println("[*] 尝试通过地址直接调用...");

            List<Object> list = new ArrayList<>(5);
            list.add(vm.getJNIEnv()); // JNIEnv参数
            list.add(0); // 静态方法，jclass参数

            // 添加三个参数：context, byte[], int
            DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null);
            list.add(vm.addLocalObject(context));

            // 使用主动调用日志中的参数: "codeooo"
            String testData = "test123";
            byte[] dataBytes = testData.getBytes(StandardCharsets.UTF_8);
            System.out.println("[*] 字节数组内容: " + bytesToString(dataBytes));
            System.out.println("[*] 字节数组内容换为字符串: " + testData);

            // 创建字节数组对象 - 使用ByteArray而不是ArrayObject
            ByteArray byteArray = new ByteArray(vm, dataBytes);
            list.add(vm.addLocalObject(byteArray));

            int paramInt = 30; // 对应日志中的参数i: 30
            list.add(paramInt);

            System.out.println("[*] 参数i: " + paramInt);
            System.out.println("[*] 上下文: " + context);

            System.out.println("[*] core模块基地址: 0x" + Long.toHexString(coreModule.base));

            // 使用实际的函数地址 0x2030 (从RegisterNative日志中获取)
            Number result = coreModule.callFunction(emulator, 0x2030, list.toArray());
            System.out.println("[*] 直接调用结果: " + result);

            if (result.intValue() != 0) {
                DvmObject<?> resultObj = vm.getObject(result.intValue());
                if (resultObj != null) {
                    System.out.println("[*] getClock结果字符串: " + resultObj.getValue());
                    System.out.println("========================");
                }
            }

        } catch (Exception e) {
            System.err.println("[!] 直接调用也失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void getSig() {
        System.out.println("[*] 开始测试libcore.so的getClock功能...");
        // 尝试直接通过地址调用
        try {
            System.out.println("[*] 尝试通过地址直接调用...");

            List<Object> list = new ArrayList<>(5);
            list.add(vm.getJNIEnv()); // JNIEnv参数
            list.add(0); // 静态方法，jclass参数

            // 添加三个参数：context, byte[], int
            DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null);
            list.add(vm.addLocalObject(context));

            // 使用主动调用日志中的参数: "codeooo"
            String testData = "abi=arm64androidApiLevel=30android_os=0app=0apptype=22appver=12.7.20.8502boardPlatform=konabottom_navigation=truebrowseType=3c=XIAOMIcdid_tag=2client_key=2ac2a76dcold_launch_time_ms=1755229442413country_code=cncs=falsedarkMode=falseddpi=440deviceBit=0device_abi=arm64did=ANDROID_191d74724559169ddid_gt=1705684377782did_tag=0earphoneMode=1egid=DFP1ADA4ADDF3D13CD6651C089E1E268F6997B7D77B43479CD4B2C742735AE50encData=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ftt=grant_browse_type=AUTHORIZEDhotfix_ver=icaver=1is_background=0isp=CUCCiuid=kcv=1599keyconfig_state=2kpf=ANDROID_PHONEkpn=NEBULAkuaishou.api_st=Cg9rdWFpc2hvdS5hcGkuc3QSoAGWgKBvKwEvyNAtVENGtkYvXDok-M9D71FAHx7rfdRvIe59bnNA3qPsdUyyNZCiwl6xeDcH6TqHvc7HSEiwN7JzbmJT1DIlvSzUPHJU08WXoN3XMEKSciQiBp0oJoMFepdOZBLeXsF8H2ds9gc8ksZGdLy7cBKm9JL8VTVyw4rwWUFIYkmZ-UiPfxuDDdHTMQRG-mgNbF1NvFBzOFIJxX6YGhLs1J4yL3FOXJxWhbfIVnwvpekiIA4eyQaeV_TvFBPhnLZ-pgJi96SrOUSa7mR7na5i7QhgKAUwAQlanguage=zh-cnmax_memory=256mod=Xiaomi(M2102J2SC)nbh=44net=WIFInewOc=XIAOMIoDid=ANDROID_93cb288f321199cfoc=XIAOMIos=androidrdid=ANDROID_1ea880a26e31b5d8sbh=90sh=2340sign=5a54eecde4d4ea61513a6d39ad28f76ee40d1665174bb0bfe890e14107772c39slh=0socName=Qualcomm Snapdragon 8250sw=1080sys=ANDROID_11thermal=10000token=Cg9rdWFpc2hvdS5hcGkuc3QSoAGWgKBvKwEvyNAtVENGtkYvXDok-M9D71FAHx7rfdRvIe59bnNA3qPsdUyyNZCiwl6xeDcH6TqHvc7HSEiwN7JzbmJT1DIlvSzUPHJU08WXoN3XMEKSciQiBp0oJoMFepdOZBLeXsF8H2ds9gc8ksZGdLy7cBKm9JL8VTVyw4rwWUFIYkmZ-UiPfxuDDdHTMQRG-mgNbF1NvFBzOFIJxX6YGhLs1J4yL3FOXJxWhbfIVnwvpekiIA4eyQaeV_TvFBPhnLZ-pgJi96SrOUSa7mR7na5i7QhgKAUwAQtotalMemory=11598uQaTag=1##swLdgl:-9#ecPp:89#cmNt:-1ud=4435885561userRecoBit=0ver=12.7videoModelCrowdTag=1_5";
            byte[] dataBytes = testData.getBytes(StandardCharsets.UTF_8);
            System.out.println("[*] 字节数组内容: " + bytesToString(dataBytes));
            System.out.println("[*] 字节数组内容换为字符串: " + testData);

            // 创建字节数组对象 - 使用ByteArray而不是ArrayObject
            ByteArray byteArray = new ByteArray(vm, dataBytes);
            list.add(vm.addLocalObject(byteArray));

            int paramInt = 30; // 对应日志中的参数i: 30
            list.add(paramInt);

            System.out.println("[*] 参数i: " + paramInt);
            System.out.println("[*] 上下文: " + context);

            System.out.println("[*] core模块基地址: 0x" + Long.toHexString(coreModule.base));

            // 使用实际的函数地址 0x2030 (从RegisterNative日志中获取)
            Number result = coreModule.callFunction(emulator, 0x2030, list.toArray());
            System.out.println("[*] 直接调用结果: " + result);

            if (result.intValue() != 0) {
                DvmObject<?> resultObj = vm.getObject(result.intValue());
                if (resultObj != null) {
                    System.out.println("[*] getClock结果字符串: " + resultObj.getValue());
                    System.out.println("========================");
                }
            }

        } catch (Exception e) {
            System.err.println("[!] 直接调用也失败: " + e.getMessage());
            e.printStackTrace();
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


    /**
     * 实现 IOResolver 接口，处理文件打开请求
     * This method is crucial for handling file accesses like /dev/__properties__ and /proc/stat
     */
    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        System.out.println("[IOResolver] 请求打开文件: " + pathname);

        // 处理空路径或无效路径
        if (pathname == null || pathname.trim().isEmpty()) {
            System.out.println("[*] 拒绝空文件路径访问");
            return null;
        }

        // 处理 /proc/self/cmdline - 返回进程名称
        if ("/proc/self/cmdline".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                    "com.kuaishou.nebula".getBytes(StandardCharsets.UTF_8)));
        }

        // 处理 APK 文件访问 - 使用 SimpleFileIO 包装
        if (pathname != null && pathname.contains("/base.apk")) {
            File apkFile = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
            if (apkFile.exists()) {
                try {
                    System.out.println("[IOResolver] ✓ 找到APK文件，使用SimpleFileIO包装");
                    return FileResult.success(new SimpleFileIO(oflags, apkFile, pathname));
                } catch (Exception e) {
                    System.out.println("[IOResolver] ✗ 创建 SimpleFileIO 失败: " + e.getMessage());
                }
            } else {
                System.out.println("[IOResolver] ✗ APK文件不存在: " + apkFile.getAbsolutePath());
            }
        }

        switch (pathname) {
            case "/dev/__properties__":
                // 对于 /dev/__properties__，通常返回一个空文件或者非常简单的内容
                // 这是为了避免应用因找不到此文件而崩溃或触发反调试
                String properties_content = ""; // 你可以根据需要添加一些特定字节
                System.out.println("[*] Intercepted /dev/__properties__ open. Returning empty content.");
                return FileResult.success(new ByteArrayFileIO(oflags, pathname, properties_content.getBytes(StandardCharsets.UTF_8)));

            case "/proc/stat":
                // /proc/stat 提供了系统统计信息，应用程序可能解析它
                // 提供一个简单的、看起来合理的 CPU 统计数据，格式必须正确
                String stat_content =
                        "cpu  200000 0 100000 5000000 0 0 0 0 0 0\n" +
                                "cpu0 100000 0 50000 2500000 0 0 0 0 0 0\n" +
                                "cpu1 100000 0 50000 2500000 0 0 0 0 0 0\n" +
                                "intr 1234567\n" +
                                "ctxt 8901234\n" +
                                "btime 1678886400\n" + // boot time in seconds (example)
                                "processes 12345\n" +
                                "procs_running 2\n" +
                                "procs_blocked 0\n" +
                                "softirq 1234 567 890 123 456 789\n";
                System.out.println("[*] Intercepted /proc/stat open. Returning dummy content.");
                return FileResult.success(new ByteArrayFileIO(oflags, pathname, stat_content.getBytes(StandardCharsets.UTF_8)));

            // 处理一些常见的Android系统文件
            case "/proc/version":
                String version_content = "Linux version 4.14.186-android (build@hostname) (gcc version 4.9.x) #1 SMP PREEMPT Mon Jan 1 00:00:00 UTC 2024\n";
                System.out.println("[*] Intercepted /proc/version open.");
                return FileResult.success(new ByteArrayFileIO(oflags, pathname, version_content.getBytes(StandardCharsets.UTF_8)));

            case "/proc/cpuinfo":
                String cpuinfo_content = "processor\t: 0\nmodel name\t: ARMv8 Processor rev 0 (v8l)\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n";
                System.out.println("[*] Intercepted /proc/cpuinfo open.");
                return FileResult.success(new ByteArrayFileIO(oflags, pathname, cpuinfo_content.getBytes(StandardCharsets.UTF_8)));

            default:
                // 对于其他所有未明确处理的文件，返回 null。
                // 这将告诉 Unidbg 的 SyscallHandler 继续尝试后续的 IOResolver，
                // 如果没有其他 resolver 能处理，会按照默认行为处理（例如，如果文件在 rootfs 中则打开，否则返回 ENOENT）。
                return null;
        }
    }


    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "com/yxcorp/gifshow/App->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                return new StringObject(vm, packageName);
            }
            case "com/yxcorp/gifshow/App->getPackageManager()Landroid/content/pm/PackageManager;": {
//                DvmClass clazz = vm.resolveClass("android/content/pm/PackageManager");
//                return clazz.newObject(signature);
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            }
            case "com/yxcorp/gifshow/App->getPackageCodePath()Ljava/lang/String;": {
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");
            }
            case "com/yxcorp/gifshow/App->getAssets()Landroid/content/res/AssetManager;": {
                return new AssetManager(vm, signature);
            }
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;": {
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->getProcessName(Landroid/content/Context;)Ljava/lang/String;": {
                return new StringObject(vm, "com.kuaishou.nebula");
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V": {
                System.out.println("触发了---1:  com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V");
                return;
            }
        }
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        System.out.println("callBooleanMethodV: " + signature);
        switch (signature) {
            case "java/lang/Boolean->booleanValue()Z":
                DvmBoolean dvmBoolean = (DvmBoolean) dvmObject;
                return dvmBoolean.getValue();
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    /**
     * 0x9c00内存映射 - 关键修复
     * 这个方法创建0x9c00地址的内存映射，解决UC_ERR_FETCH_UNMAPPED错误
     */
    private void map0x9c00Memory() {
        System.out.println("[*] 开始设置0x9c00内存映射...");
        Backend backend = emulator.getBackend();

        long pageSize = 0x1000;  // 4KB页面
        long baseAddr = 0x9000;   // 基地址
        long dataStructAddr = 0x9800;  // 数据结构地址

        // 映射内存页面
        backend.mem_map(baseAddr, pageSize, unicorn.UnicornConst.UC_PROT_ALL);
        System.out.println("[*] 已映射内存: 0x" + Long.toHexString(baseAddr) + " - 0x" + Long.toHexString(baseAddr + pageSize));

        // 初始化数据结构
        byte[] dataStruct = new byte[256];
        backend.mem_write(dataStructAddr, dataStruct);
        System.out.println("[*] 已初始化数据结构在: 0x" + Long.toHexString(dataStructAddr));

        // 写入ARM64汇编代码到0x9c00
        // LDR X0, [PC, #8]  ; 加载0x9800地址到X0
        // RET               ; 返回
        // .quad 0x9800      ; 数据：0x9800地址
        byte[] code = {
                (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x58,  // LDR X0, [PC, #8]
                (byte) 0xC0, (byte) 0x03, (byte) 0x5F, (byte) 0xD6,  // RET
                (byte) 0x00, (byte) 0x98, (byte) 0x00, (byte) 0x00,  // .quad 0x9800 (低位)
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00   // .quad 0x9800 (高位)
        };
        backend.mem_write(0x9c00, code);
        System.out.println("[*] 已写入ARM64代码到: 0x9c00");

        // 设置Hook
        setupHook0x9c00();
        setupHookFopen();
    }

    /**
     * Hook 0x9c00地址的执行
     */
    private UnHook hook0x9c00;

    private void setupHook0x9c00() {
        System.out.println("[*] 设置0x9c00 Hook...");
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void onAttach(UnHook unHook) {
                hook0x9c00 = unHook;
            }

            @Override
            public void detach() {
                // 实现 Detachable 接口要求的方法
            }

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                System.out.println("[Hook-0x9c00] 执行地址: 0x" + Long.toHexString(address));
            }
        }, 0x9c00, 0x9c00, null);
        System.out.println("[*] 0x9c00 Hook已设置");
    }

    /**
     * Hook fopen调用 - 用于调试文件访问
     */
    private void setupHookFopen() {
        System.out.println("[*] 设置fopen Hook...");
        long fopenAddr = module.base + 0x9c30;

        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void onAttach(UnHook unHook) {
                // 实现 Detachable 接口要求的方法
            }

            @Override
            public void detach() {
                // 实现 Detachable 接口要求的方法
            }

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address == fopenAddr) {
                    System.out.println("[Hook-fopen] 被调用");
                    RegisterContext ctx = emulator.getContext();

                    long x0 = ctx.getLongArg(0); // filename
                    long x1 = ctx.getLongArg(1); // mode

                    try {
                        // 读取文件名 - 手动读取C字符串
                        byte[] filenameBytes = backend.mem_read(x0, 256);
                        int nullIndex = 0;
                        for (int i = 0; i < filenameBytes.length; i++) {
                            if (filenameBytes[i] == 0) {
                                nullIndex = i;
                                break;
                            }
                        }
                        String filename = new String(filenameBytes, 0, nullIndex, StandardCharsets.UTF_8);

                        // 读取模式 - 手动读取C字符串
                        byte[] modeBytes = backend.mem_read(x1, 16);
                        nullIndex = 0;
                        for (int i = 0; i < modeBytes.length; i++) {
                            if (modeBytes[i] == 0) {
                                nullIndex = i;
                                break;
                            }
                        }
                        String mode = new String(modeBytes, 0, nullIndex, StandardCharsets.UTF_8);

                        System.out.println("[Hook-fopen] 文件名: " + filename);
                        System.out.println("[Hook-fopen] 模式: " + mode);

                    } catch (Exception e) {
                        System.out.println("[Hook-fopen] 无法读取参数: " + e.getMessage());
                    }
                }
            }
        }, fopenAddr, fopenAddr + 4, null);

        System.out.println("[*] fopen Hook已设置 @ 0x" + Long.toHexString(fopenAddr));
    }

}
