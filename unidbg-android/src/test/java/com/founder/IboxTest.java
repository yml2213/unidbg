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
//
//public class test {
//}
public class IboxTest extends AbstractJni implements IOResolver<AndroidFileIO> {

    private final AndroidEmulator androidEmulator;
    private final Module module;
    private final VM dalvikVM;

    private static final String KEY = "EWA40T3eMNVkLmj8Ur9CuQExbcOti8c3yd-I8xDkLhvphNMuRujkY7V6lKbvAtE2qXa4kTWSnXmo0HXfuUXRgyFNXYwhwvvf7yUYQ-DjWjAa34fjA9yJCam4Llddmcu3D8BQKw4gR-nkYzzOx0uGj9OkfgUHoFxF00akZNyeMrs=";

    public IboxTest() {
        androidEmulator = AndroidEmulatorBuilder.for64Bit().
                addBackendFactory(new Unicorn2Factory(false))
                .setProcessName("com.box.art")
                .build();
        Memory memory = androidEmulator.getMemory();
        androidEmulator.getSyscallHandler().setEnableThreadDispatcher(true);
        androidEmulator.getBackend().registerEmuCountHook(1000);
        androidEmulator.getSyscallHandler().addIOResolver(this);
        memory.setLibraryResolver(new AndroidResolver(23));
        dalvikVM = androidEmulator.createDalvikVM(new File("com.boxart.apk"));
        dalvikVM.setVerbose(true);
        dalvikVM.setJni(this);
        new AndroidModule(androidEmulator, dalvikVM).register(memory);
        DalvikModule dalvikModule = dalvikVM.loadLibrary(new File("ibox/libtiger_tally.so"), false);
        module = dalvikModule.getModule();
        dalvikVM.callJNI_OnLoad(androidEmulator, module);
    }

    private void init() {
        List<Object> params = new ArrayList<Object>();
        params.add(dalvikVM.getJNIEnv());
        params.add(0);
        params.add(1);
        params.add(dalvikVM.addLocalObject(new StringObject(dalvikVM, KEY)));
        Number number = module.callFunction(androidEmulator, 0x5ecb0, params.toArray());
        DvmObject<?> object = dalvikVM.getObject(number.intValue());
        if (object != null) {
            Integer integer = (Integer) object.getValue();
            System.out.println("初始化结束 ;" + object);
        }
    }

    private String getWtoken(String args) {
        List<Object> params = new ArrayList<Object>();
        params.add(dalvikVM.getJNIEnv());
        params.add(0);
        params.add(1);
        ByteArray byteArray = new ByteArray(dalvikVM, args.getBytes(StandardCharsets.UTF_8));
        params.add(dalvikVM.addLocalObject(byteArray));
        Number number = module.callFunction(androidEmulator, 0x5f008, params.toArray());
        DvmObject<?> object = dalvikVM.getObject(number.intValue());
        if (object != null) {
            Object value = object.getValue();
            System.out.println(" ;" + value.toString());
            return value.toString();
        }
        return "";
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
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
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
            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                System.out.println("getString " + vaList.getObjectArg(0).toString());
                DvmObject<?> objectArg = vaList.getObjectArg(0);
                if (objectArg.getValue().toString().equals("tt_ak")) {
                    long currentTimeMillis = System.currentTimeMillis();
                    StringObject stringObject1 = new StringObject(vm, "^" + currentTimeMillis+"^86400");
                    return stringObject1;
                } else if (objectArg.getValue().toString().equals("TT_COOKIEID")) {
                    StringObject stringObject1 = new StringObject(vm, "TDluNPJxJtm0/u6f9OKjjGbqudrxW1wN4wftIv5Mu6wKhOsbK3Vu7GcO+fn4SaxwlzfGqH0ZPmf7z0ZGc5by6g==");
                    return stringObject1;
                }
                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
            case "android/content/SharedPreferences->edit()Landroid/content/SharedPreferences$Editor;":
                DvmObject<?> dvmObject3 = vm.resolveClass("android/content/SharedPreferences$Editor").newObject(null);
                return dvmObject3;
            case "android/content/SharedPreferences$Editor->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;":
                Object value = dvmObject.getValue();
                DvmObject<?> dvmObject4 = vm.resolveClass("android/content/SharedPreferences$Editor").newObject(value);
                return dvmObject4;
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

    public static void main(String[] args) {
        IboxTest iboxTest = new IboxTest();
        iboxTest.init();
        iboxTest.getWtoken("{\"albumId\":100513930}");
    }
    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        System.out.println(pathname);
        if ("/proc/self/maps".equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, new File("/Users/maps"), pathname));
        } else if ("/proc/stat".equals(pathname)) {
            return FileResult.success(new SimpleFileIO(oflags, new File("/Users/Downloads/unidbg-master_0.97/unidbg-android/src/test/java/com/rootfs/stat"), pathname));
        }
        return null;
    }
}