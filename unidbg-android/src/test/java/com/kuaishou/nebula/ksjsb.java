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
        vm.setVerbose(false);

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
        sgDm.callJNI_OnLoad(emulator);

        DalvikModule dm = vm.loadLibrary("kwsgmain", true);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);

        initializeMemoryMapping();
    }

    public static void main(String[] args) throws FileNotFoundException {
        ksjsb ks = new ksjsb();
        ks.initializeEnvironment();
        ks.getNebulaSig3();
        ks.generateSign64();
        ks.getSig();
    }

    public void initializeEnvironment() {
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
        Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
        DvmObject<?> object = vm.getObject(numbers.intValue());
        String result = (String) object.getValue();
        System.out.println("[initializeEnvironment] 结果: " + result);
    }

    public String getNebulaSig3() throws FileNotFoundException {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第⼀个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。
        DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null); // context com.yxcorp.gifshow.App
        vm.addLocalObject(context);
        list.add(10418);
        StringObject payloadObj = new StringObject(vm, SIG_PAYLOAD);
        vm.addLocalObject(payloadObj);
        ArrayObject arrayObject = new ArrayObject(payloadObj);
        vm.addLocalObject(arrayObject);
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

        Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
        if (numbers.intValue() == -1) {
            return null;
        }

        DvmObject<?> object = vm.getObject(numbers.intValue());
        if (object == null) {
            return null;
        }
        System.out.println("[getNebulaSig3] 结果: " + object.getValue());
        return (String) object.getValue();
    }


    public String generateSign64() throws FileNotFoundException {
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。
        DvmObject<?> context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null); // context com.yxcorp.gifshow.App
        vm.addLocalObject(context);
        list.add(10418);
        StringObject payloadObj = new StringObject(vm, SIG_PAYLOAD);
        vm.addLocalObject(payloadObj);
        ArrayObject arrayObject = new ArrayObject(payloadObj);
        vm.addLocalObject(arrayObject);
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
        list.add(vm.addLocalObject(new ArrayObject(arrayObject, appkey, intergetobj, boolobjTrue, context, null, boolobjTrue, appkey2)));

        Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
        if (numbers.intValue() == -1) {
            return null;
        }

        DvmObject<?> object = vm.getObject(numbers.intValue());
        if (object == null) {
            return null;
        }
        System.out.println("[generateSign64] 结果: " + object.getValue());
        return (String) object.getValue();
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
//            System.out.println("[*] 字节数组内容: " + bytesToString(dataBytes));
//            System.out.println("[*] 字节数组内容换为字符串: " + testData);

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
//                    System.out.println("========================");
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
    private void initializeMemoryMapping() {
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

        // 启用Hook - 参考ksjsbTest.java的成功实现
        setupHook0x9c00();
//        setupHookFopen();
    }

    /**
     * Hook 0x9c00地址的执行
     * 关键：拦截并直接返回，避免无限循环
     */
    private UnHook hook0x9c00;
    private int hook0x9c00Count = 0;

    private void setupHook0x9c00() {
        System.out.println("[*] 设置 0x9c00 拦截 Hook（参考ksjsbTest成功方案）...");

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
                if (address == 0x9c00) {
                    hook0x9c00Count++;
                    System.out.println("\n[Hook 0x9c00] ========== 第 " + hook0x9c00Count + " 次调用 ==========");
                    RegisterContext ctx = emulator.getContext();

                    // 打印参数寄存器
                    long x0 = ctx.getLongArg(0);
                    long x1 = ctx.getLongArg(1);
                    long x2 = ctx.getLongArg(2);

                    System.out.println("[Hook 0x9c00] X0 = 0x" + Long.toHexString(x0) + " (输入缓冲区?)");
                    System.out.println("[Hook 0x9c00] X1 = 0x" + Long.toHexString(x1));
                    System.out.println("[Hook 0x9c00] X2 = 0x" + Long.toHexString(x2));

                    // 打印调用栈
                    long lr = ctx.getLRPointer().peer;
                    System.out.println("[Hook 0x9c00] LR = 0x" + Long.toHexString(lr) + " (返回地址)");

                    // ✅ 关键1：尝试填充 X0 指向的缓冲区（如果 X0 是有效地址）
                    if (x0 != 0 && x0 > 0x1000) {
                        try {
                            // 填充一些测试数据
                            byte[] testData = new byte[64];
                            testData[0] = 0x01; // 标志位
                            backend.mem_write(x0, testData);
                            System.out.println("[Hook 0x9c00] 已填充 X0 指向的缓冲区");
                        } catch (Exception e) {
                            System.out.println("[Hook 0x9c00] 无法写入 X0 地址: " + e.getMessage());
                        }
                    }

                    // ✅ 关键2：设置返回值为 0（成功状态码）而不是 0x9800
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0L);
                    System.out.println("[Hook 0x9c00] 设置返回值 X0 = 0 (成功)");

                    // ✅ 关键3：直接返回到调用者，跳过原始代码执行
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, lr);
                    System.out.println("[Hook 0x9c00] 已拦截并返回到 0x" + Long.toHexString(lr));
                    System.out.println("[Hook 0x9c00] ========== Hook 完成 ==========\n");
                }
            }
        }, 0x9c00, 0x9c00 + 4, null);

        System.out.println("[✓] 0x9c00 拦截 Hook 设置完成（将直接返回0，不执行原始代码）");
    }


}
