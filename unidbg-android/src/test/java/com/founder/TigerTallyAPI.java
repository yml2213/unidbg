package com.founder;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;

import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DumpFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ThreadLocalRandom;


public class TigerTallyAPI extends AbstractJni implements IOResolver<AndroidFileIO> {
    private final AndroidEmulator emulator;
    private final VM vm;
    AndroidEmulatorBuilder androidEmulatorBuilder = new AndroidEmulatorBuilder(false) {
        @Override
        public AndroidEmulator build() {
            return new AndroidARMEmulator("com.nike.snkrs",rootDir,backendFactories) {
                @Override
                protected UnixSyscallHandler createSyscallHandler(SvcMemory svcMemory) {
                    return new PddArmSysCallHand(svcMemory);
                }
            };
        }
    };
    public class PddArmSysCallHand extends com.github.unidbg.linux.ARM32SyscallHandler {
        public PddArmSysCallHand(SvcMemory svcMemory) {
            super(svcMemory);
        }
        @Override
        protected boolean handleUnknownSyscall(Emulator emulator, int NR) {
            switch (NR) {
                case 190:
                    vfork(emulator);
                    return true;
                case 359:
                    pipe2(emulator);
                    return true;
            }

            return super.handleUnknownSyscall(emulator, NR);
        }
        private void vfork(Emulator<?> emulator) {
            EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
            int childPid = emulator.getPid() + ThreadLocalRandom.current().nextInt(256);
            int r0 = 0;
            r0 = childPid;
            System.out.println("vfork pid=" + r0);
            context.setR0(r0);
        }


        @Override
        protected int pipe2(Emulator<?> emulator) {
            EditableArm32RegisterContext context = (EditableArm32RegisterContext) emulator.getContext();
            Pointer pipefd = context.getPointerArg(0);
            int flags = context.getIntArg(1);
            int write = getMinFd();
            this.fdMap.put(write, new DumpFileIO(write));
            int read = getMinFd();
            String stdout = "2a6dffba-811a-43e5-96ee-638e71784cb7";
            this.fdMap.put(read, new ByteArrayFileIO(0, "pipe2_read_side", stdout.getBytes()));
            pipefd.setInt(0, read);
            pipefd.setInt(4, write);
            System.out.println("pipe2 pipefd=" + pipefd + ", flags=0x" + flags + ", read=" + read + ", write=" + write + ", stdout=" + stdout);
            context.setR0(0);
            return 0;
        }
    }
    public TigerTallyAPI(String apkPath) {
        emulator = androidEmulatorBuilder.build();
        SyscallHandler<AndroidFileIO> syscallHandler =
                emulator.getSyscallHandler();
        syscallHandler.setVerbose(true);
        syscallHandler.addIOResolver(this);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File(apkPath));
        vm.setJni(this);
        vm.setVerbose(true);


    }
    public static void main(String[] args) {
        TigerTallyAPI tigerTallyAPI = new TigerTallyAPI("F:\\Project\\WTOKEN\\nike.apk");
        AndroidEmulator emulator = tigerTallyAPI.emulator;
        DalvikModule dalvikModule = tigerTallyAPI.vm.loadLibrary(new File("F:\\Project\\WTOKEN\\libtiger_tally.so"), true);
        dalvikModule.callJNI_OnLoad(emulator);
        VM vm = tigerTallyAPI.vm;
        DvmClass dvmClass = vm.resolveClass("com/aliyun/TigerTally/t/B");
        dvmClass.callStaticJniMethodObject(emulator,"genericNt1(ILjava/lang/String;)I",1,new StringObject(vm,"j0m4PjXNgOX_A_ZJXjBNgJ0DRtp_VQWwEMS5DkAJUJsKPR-0r8PqOkWMrhwymjZCoyOzBW2aqkrY8Tw9Cbwyl9fMOlOMPTC7_sOho2t_mOpdhkcQrWAc8fv_EATLX5DSrlve4QlMpMZtIuTfry6bm4VRSapMNRLn_dOCZ06VbLQ="));
        dvmClass.callStaticJniMethodObject(emulator,"genericNt2(ILjava/lang/String;)I",2,new StringObject(vm,"F5ulsYPu9bEb+ZoPdcd/wZxh7LGkq2jguP1rn2f5KYoOwggyQCbyJWB5xvZB1Z/vPiRsAIRa9iwncJmK0dO/xQ=="));
        DvmObject<?> dvmObject = dvmClass.callStaticJniMethodObject(emulator,"genericNt3(I[B)Ljava/lang/String;",1,new ByteArray(vm,"2a6dffba-811a-43e5-96ee-638e71784cb7".getBytes(StandardCharsets.UTF_8)));
        System.out.println(dvmObject.getValue().toString());
        tigerTallyAPI.destroy();

    }
    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature){
            case "com/aliyun/TigerTally/s/A->ct()Landroid/content/Context;":
                return vm.resolveClass("android/app/Application",vm.resolveClass("android/content/ContextWrapper",vm.resolveClass("android/content/Context"))).newObject(signature);
            case "com/aliyun/TigerTally/A->pb(Ljava/lang/String;[B)Ljava/lang/String;":
                return new StringObject(vm,"F5ulsYPu9bEb+ZoPdcd/wZxh7LGkq2jguP1rn2f5KYoOwggyQCbyJWB5xvZB1Z/vPiRsAIRa9iwncJmK0dO/xQ==");
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "android/content/pm/PackageManager->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;":
                return vm.resolveClass("Landroid/content/pm/ApplicationInfo;").newObject(signature);
            case "android/content/pm/PackageManager->getApplicationLabel(Landroid/content/pm/ApplicationInfo;)Ljava/lang/CharSequence;":
                return new StringObject(vm,"Ljava/lang/CharSequence;");
            case "android/app/Application->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("Ljava/io/File;");
            case "java/lang/String->getAbsolutePath()Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "android/app/Application->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                return vm.resolveClass("Landroid/content/SharedPreferences;");
            case "java/lang/Class->getAbsolutePath()Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "java/lang/Class->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "android/app/Application->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "com/aliyun/TigerTally/s/A$AA->en(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"eb32139f977b4e12abca93113c3d8486557dfeb");
            case "com/aliyun/TigerTally/s/A$BB->en(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm,"eb32139f977b4e12abca93113c3d8486557dfeb");

        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }
    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature){
            case "android/os/Build->BRAND:Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "android/os/Build->MODEL:Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "android/os/Build$VERSION->RELEASE:Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
            case "android/os/Build->DEVICE:Ljava/lang/String;":
                return new StringObject(vm,"Ljava/lang/String;");
        }
        return super.getStaticObjectField(vm,dvmClass,signature);
    }
    public void destroy() {
        try {
            emulator.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
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
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        return null;
    }

}