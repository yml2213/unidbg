package com.kuaishou.nebula;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.unix.UnixEmulator;
import unicorn.UnicornConst;
import unicorn.Arm64Const;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.android.dvm.api.PackageInfo;
import com.github.unidbg.linux.android.dvm.api.Signature;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import net.dongliu.apk.parser.bean.CertificateMeta;
import com.github.unidbg.file.linux.AndroidFileIO;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class KSEmulator extends AbstractJni {
    private final AndroidEmulator emulator;
    private final Module module;
    private final VM vm;
    private final DvmObject<?> context;  // 共享的Context对象
    private static final String ENC_DATA_REQUEST_HEX;
    private static final String ENC_DATA_EXPECTED_HEX;
    private static final String PACKAGE_NAME = "com.kuaishou.nebula\0";

    static {
        ENC_DATA_REQUEST_HEX = "7B22617070496E666F223A7B226170704964223A226B75616973686F755F6E6562756C61222C226E616D65223A22E5BFABE6898BE69E81E9809FE78988222C227061636B6167654E616D65223A22636F6D2E6B75616973686F752E6E6562756C61222C2276657273696F6E223A2231332E382E34302E3130363537222C2276657273696F6E436F6465223A2D317D2C22646576696365496E666F223A7B226F616964223A2237303045443638363530454634394543423638364232414141393939344331446361333163373739656535616362376434633362303333333735393961353931222C226F7354797065223A312C226F7356657273696F6E223A223135222C226C616E6775616765223A227A68222C226465766963654964223A22414E44524F49445F62373434323334643665353938373862222C2273637265656E53697A65223A7B227769647468223A313038302C22686569676874223A323230387D2C22667474223A22222C22737570706F72744779726F73636F7065223A747275657D2C226E6574776F726B496E666F223A7B226970223A223139322E3136382E35302E323134222C22636F6E6E656374696F6E54797065223A3130307D2C2267656F496E666F223A7B226C61746974756465223A302C226C6F6E676974756465223A307D2C2275736572496E666F223A7B22757365724964223A2231353739343532343930222C22616765223A302C2267656E646572223A22227D2C22696D70496E666F223A5B7B22706167654964223A31313130312C22737562506167654964223A3130303032343036342C22616374696F6E223A302C227769647468223A302C22686569676874223A302C2262726F77736554797065223A332C22726571756573745363656E6554797065223A312C226C61737452656365697665416D6F756E74223A302C22696D7045787444617461223A227B5C226F70656E48354164436F756E745C223A302C5C2273657373696F6E4C6F6F6B6564436F6D706C65746564436F756E745C223A5C22305C222C5C2273657373696F6E547970655C223A5C22315C222C5C226E656F506172616D735C223A5C2265794A775957646C535751694F6A45784D5441784C434A7A64574A515957646C535751694F6A45774D4441794E4441324E4377696347397A535751694F6A4173496D4A3163326C755A584E7A535751694F6A59774E6977695A586830554746795957317A496A6F694F545930597A59324D575131593255785A44517A4D6D497A4D544A69596A686A4E4755795A47457A4F47497A4E4755304D4445354E7A67344D5459774F4749784F5751325A44497A4F5745784D444D794F444D324F574A6A4E47526D4D4467344E7A5A6A4D4451324E44466A5A44417A4D574935595455355A475A695A6A59334D324E6A4E3249344F4449344D7A67334D6A55784E7A566B5932466A4D7A67314D6A63355A5751315A5759334E7A4A6B5A5467305954497A4F546C695A5463324F545269595452694F544E6A4E6A59334F4455334D6D466C4D444E6D597A51354D5441304D6D49344D7A686C4D474A6A4D6D55315A474E68597A46684E444D77496977695933567A64473974524746305953493665794A6C65476C305357356D6279493665794A306232467A6445526C63324D694F6D353162477773496E527659584E305357316E56584A73496A70756457787366583073496E426C626D5268626E52556558426C496A6F784C434A6B61584E776247463556486C775A5349364D69776963326C755A32786C5547466E5A556C6B496A6F774C434A7A6157356E6247565464574A515957646C535751694F6A4173496D4E6F595735755A5777694F6A4173496D4E76645735305A473933626C4A6C63473979644349365A6D467363325573496E526F5A57316C56486C775A5349364D43776962576C345A5752425A4349365A6D467363325573496D5A316247784E6158686C5A43493664484A315A5377695958563062314A6C634739796443493664484A315A5377695A6E4A7662565268633274445A5735305A5849694F6D5A6862484E6C4C434A7A5A5746795932684A626E4E7761584A6C55324E6F5A57316C5357356D62794936626E5673624377695957317664573530496A6F7766515C227D222C226D6564696145787444617461223A227B7D222C2273657373696F6E223A227B5C2269645C223A5C2261644E656F2D313537393435323439302D3130303032343036342D313736303538333837353938385C227D227D5D2C226164436C69656E74496E666F223A227B5C226970647849505C223A5C223138332E34322E3136342E345C227D222C227265636F5265706F7274436F6E74657874223A227B5C226164436C69656E74496E666F5C223A7B5C2273686F756C6453686F77416450726F66696C6553656374696F6E42616E6E65725C223A6E756C6C2C5C2270726F66696C65417574686F7249645C223A307D7D227D";
        ENC_DATA_EXPECTED_HEX = "5A54EECDE4D4EA6193F79DB96E3254547C68770002477963823030FAD0F3D666690F63A1247249634A4A77BB399B1F3E5CC4518BB302137052CB534DC48E9BCB0850B9E265E1857C40336C08E36E308EE6E7D5D7EEBC9CAD7CF964F6CE6CC0452E9DB776A205F3A0E8E7701B177BB80DDD95B24FB50739215088EE729036819EA0F37EDFE56CF5F5C9B3FF8654822F88841C1939E8F9B8000A6ECF4E88740103CFE2F190F5B68C480F432EF2EA5EB43CC373C0621AE864858F76355FED5400369518C21F92BCD3ACEE033C77E18753C485CC238C44BE2F7AD24AC78C2691998121EE0508DD4F7EE82CB6E7D059F3FA086312BC4094AF2A88C32D523DC50DFCEF84916D4A537ED2679CAE5904C1D6CE9C5A4374DC9B17231528D83226629A2D7375F6C17B632C0687FDACDB393BAA046830C6E24A458F162375C090F13B3B8433F3AC417BA55E012A8FEF579B4D896533E7C75B29AC470C564209581B5AB1FC6ACDC814D4E11EAC839009E9B4D44990140E3BCA24993DFCB02E0FE5B1710F996AB09EEFFD3BEE79C44705B89269F6925410B4223A94274194932AF795E15DF0854946EE1E4A836F98A515506C73AC59A763E305EEA6BABBD3B20F4A5D3FC981749D4F45EAE1F01A83C21C919CF86732235D1D25E897BCD90547BED8835FD7ACF312FBC151096FD7AEC5935D61601DDE57D87D38C43D75BE2ED75C3221185FF4AA616C8EEB3399E22A2F4732C12D7731B1DD843E87BED94E49CA739D220C97831BF900580711280DBC50110B81B9F932C3C86B43293C1FDA6428DFF9827D3D423919A581FAD0BD63DB32B16A3A53B7892B035816B71EA4D50FCD916D5FA34652923D8BB9EA33A92AFBC069BB6704A1C09FFE6C70FEAEB6D50228C7D4EE5CEE2F29F5F858E0C93D5A413BCBBC35996B89062EAD174922577B276F46DC607F27A38E8AF17D1DECB6853DB0ACA12909153EAE4071443E23EA6119B5D08DC7C9AF03481BF40D0BAEB489B18ED83B1ED17BEA830E344690089712FAC76E3FD294DC62AF2106BF9FF81EC0452F6AA10FC3450D5392F76611B6529146CB85BA025D49E9EB0A95E7010C27EE108F2875899F29D21C62F568FE759B2B3FBE95E7DEE292D3C60906DF2F757837B8A3904C95AB2D80E7F006D8318E2EB817C10410194FD79908D1EC5A72C4F21FA0BC096A622F8CE6EEE4C90880EAE43D0FE267C6D75CAC5EA4514E4E0B54F943CBBE654E6ECFB61C792DF9E0EE6373F1C63D6E3810563D80A3CF22A7C42FE32BA5F577337CD9349921C59A033ACAFBE4EB6C098CCEDD19A7A23E4A7BD3FA3A7740B6B7A94CEF9247A9C3F5D5346337C54626372C262357826ECDA163820B82D9B07B24E3CC57777BA06061D74B5D5276DDE3D3FA8E5C8BA711E8EAB68314DA70D70BE132925763BFF61E4E32556EC5C916E550EDAD2CA4443F173D0F316C28511A3318EB98863C3260A1261DDA4B628834C03FD567792BD034D5B9B7384828F4D86E0042583A428118D535CDB0C27CBF3778EA7CD40BA95970046AA826E26237F57B36D2C13BF7EC6FE489E181FC8F311CB1272C507EECD9E244326D220CE6DD3DE5B9CEA2AF03A58E9B0DFB5AE112733E9DEDD0F76A4948F4ACFDCE0E9C0AD7577E0F16C66950E1A0AFD4F53763298B3EE89251FFD32F7DC107E4841AED8924DCD2AD7B6A45121D02A1EFF35D1ED48C72C01E18CE4BC7F82CE45B27AE3D7E46990C20F5FCA7CD5577F5CD4BAA89708360A154BD2AA25C52891362196ACB782F0C980D0ECD2EF21C9B7AEE8E72EC4597D7248EB17F9198B10983034412DCAB1C0701907E603EFFC61BF5870F20272855C5FF0419FEC93FB7FB4632B1AB6B7474A11E114F79E2BB13BD63C7A8FB1E9E7C031B2FABC26F6C072D10C30D48031F6A3BCC02126BFECB9660F9AE55AF85FC0149E5BEA6E1FD5A9DE68C6CF233AE01C1FA39F8FCEA6EE5B83670E3AD9E1C553B9F1BBCA2F27CDB1BC7CC4D3AA9FC4E4362FEE8BE06BEDE4A5795D074E8A4B73745149F12B76636D83BBB99B7A921AD618EBC49C02C4E77E6BC1AF00798C71707117C81555E50A46910114624AF92B1195586228D5EE8E8FCE8FA9974922283156A87547CA80098EBF5D0C965CBE1441B7F653AC88F8568D704EACB5A27F57D1B6C803A7991ED474D4FB8148399A6A6EE2ED7969FC2013DDAC6C320B51F6A4BDF517B7871F8C030FD214E10E5D072CC0F9423A02E9444CAF9B8AE09ABB027D025405DC81F191AC39B41F5B09D48F70851A3FA7E7F685DD52AB4E756F15E4AA97700F5D9CF0A052BD05B74533FF85E92BAA7BE9ADBA5C9FBF9F87AFB3210457AF4C3BCA96B2EEEF082F24C72DFB5B3272FD130258C1A836A2B7FD74AFDF928E2A90F9EC94EA1DDB3DF76CC03F9A3191FDEDFAE731C9879B077CB26CBC62F579D56BF301244ECCADB7137D1D97231960ECCB5E7BEAF632A62CE30ED76BA2AD8152FF55D8769DD4D89C5F489687F4AB3D07FE0E08A734E0135770F2D0985DCC5B646E66A25EC8D16BC1E0F6D5C1FC0BD9E4F8971FDA7A88762178B698CE809113F5DF6D224DACF9B9472A3B376092F48C602F16FD2687468A90D884D79835D7585A1D8";
    }

    public KSEmulator() {
        File apkFile = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.kuaishou.nebula")  // 使用真实包名
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));


        vm = emulator.createDalvikVM(apkFile);
        vm.setJni(this);
        vm.setVerbose(true);

        int pid = emulator.getPid();
        System.out.println("pid = " + pid);

        // 添加IOResolver - 必须在加载库之前
        emulator.getSyscallHandler().addIOResolver(new BiliIOResolver());


        // 注册AndroidModule - 必须在加载库之前
        new AndroidModule(emulator, vm).register(memory);

        // 创建共享的Context对象
        context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null);
        vm.addGlobalObject(context);  // 添加为全局对象，防止被回收

        System.out.println("[初始化] 开始加载 SO 库...");  // libkwsgmain.so
        DalvikModule dm = vm.loadLibrary("kwsgmain", true);
        module = dm.getModule();
        System.out.println("[初始化] SO base: 0x" + Long.toHexString(module.base));
        System.out.println("[初始化] SO size: 0x" + Long.toHexString(module.size));

        System.out.println("[初始化] 调用 JNI_OnLoad...");
        dm.callJNI_OnLoad(emulator);

        // 🔍 添加反调试变量监控
        setupAntiDebugMonitoring();

        // 启用GOT修复 - 将GOT表项指向AndroidModule的真实实现
        fixGotTable();

        // ⚠️ 关键：在初始化阶段就设置全局标志位
        System.out.println("[初始化] 🔧 设置全局安全标志位（提前到初始化阶段）...");
        setGlobalFlagsEarly();

        // 🔍 额外调试：Hook签名校验相关函数
        hookSignatureVerification();

        System.out.println("[初始化] ✓ 初始化完成\n");


    }

    /**
     * 🎯 Hook关键验证函数 - 绕过白名单检查和APK完整性校验（终极版）
     *
     * 根据sub_3E5C0.txt分析，该函数执行包名/签名白名单验证：
     * 1. 调用 sub_3DDB0、sub_DDF8、sub_EDA0 检查签名和包名
     * 2. 执行白名单字符串匹配（按逗号分割、小写转换、memcmp比较）
     * 3. 根据验证结果设置全局标志位：
     *    - 失败：qword_70910 |= 0x8000000000000uLL (Line 414)
     *    - 成功：qword_70910 &= ~0x8000000000000uLL (Line 429)
     *    - 成功：qword_70910 |= 0x1000000000000uLL (Line 490)
     * 4. 验证失败返回 0，成功返回 1
     *
     * 🔥 终极策略：Hook APK校验子函数（sub_DDF8, sub_EDA0），直接跳过验证
     */
    private void hookSignatureVerification() {
        System.out.println("\n[签名绕过] 🎯 Hook签名验证函数（入口拦截策略）");
        Backend backend = emulator.getBackend();

        // ⚠️ 新策略：直接在 sub_3E5C0 入口处拦截，跳过所有子函数调用
        final long SUB_3E5C0_ADDR = module.base + 0x3E5C0;
        System.out.println("[签名绕过] Hook sub_3E5C0 (主验证函数) @ 0x" + Long.toHexString(SUB_3E5C0_ADDR));

        backend.hook_add_new(new CodeHook() {
            private int callCount = 0;

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                // ⭐ 在函数入口处直接拦截
                if (address == SUB_3E5C0_ADDR) {
                    callCount++;
                    System.out.println("\n[🔧 签名绕过] sub_3E5C0 被调用 (调用#" + callCount + ")，直接跳过");

                    // 1. 设置返回值为成功
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 1);

                    // 2. 修复全局标志位 qword_70910
                    long qword_70910_addr = module.base + 0x70910;
                    byte[] flagBytes = backend.mem_read(qword_70910_addr, 8);
                    java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(flagBytes);
                    buf.order(java.nio.ByteOrder.LITTLE_ENDIAN);
                    long currentFlag = buf.getLong();

                    System.out.println("[签名绕过]   当前 qword_70910: 0x" + Long.toHexString(currentFlag));

                    // 设置正确的标志位
                    long newFlag = currentFlag;
                    newFlag &= ~0x8000000000000L;   // 清除失败标志
                    newFlag |= 0x1800000000000L;    // 设置两个成功标志

                    byte[] newFlagBytes = new byte[8];
                    for (int i = 0; i < 8; i++) {
                        newFlagBytes[i] = (byte) ((newFlag >> (i * 8)) & 0xFF);
                    }
                    backend.mem_write(qword_70910_addr, newFlagBytes);

                    System.out.println("[签名绕过]   修复后 qword_70910: 0x" + Long.toHexString(newFlag));

                    // 🔧 关键修复：修正调用者栈上的[sp+0x30]值
                    // sub_3E5C0如果失败会设置[sp+0x30]为-1，我们跳过了它，需要手动设置正确值
                    long sp = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();

                    // 注意：这里的SP是sub_3E5C0的栈帧，调用者的SP在外层
                    // 我们需要修改调用者栈帧中的[sp+0x30]
                    // 根据ARM64调用约定，被调用函数的SP = 调用者SP - 栈帧大小
                    // 从反汇编看，sub_3E5C0的栈帧很小，调用者的值应该在返回后的SP+0x30

                    // 读取LR（返回地址）来确定调用位置
                    long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

                    // 🎯 策略：在返回后，调用者会继续执行，此时它的SP已经恢复
                    // 我们直接修改当前SP附近的栈空间，尝试覆盖可能的[sp+0x30]位置
                    // 根据日志，0x42dfc处读取的是sp=0xe4fff470，所以[sp+0x30] = 0xe4fff4a0

                    // 由于我们不知道确切的调用者SP，使用一个启发式方法：
                    // sub_3E5C0被调用时，通常调用者SP = 当前SP + sub_3E5C0的栈帧大小
                    // 从反汇编可以看出sub_3E5C0的栈帧不大，假设约0x20-0x40字节

                    // 尝试修正多个可能的位置
                    for (int offset = 0x20; offset <= 0x60; offset += 0x10) {
                        long targetAddr = sp + offset + 0x30;
                        byte[] stackValue = backend.mem_read(targetAddr, 4);
                        java.nio.ByteBuffer stackBuf = java.nio.ByteBuffer.wrap(stackValue);
                        stackBuf.order(java.nio.ByteOrder.LITTLE_ENDIAN);
                        int currentValue = stackBuf.getInt();

                        // 如果发现值是-1或看起来不对，修正为4
                        if (currentValue == -1 || currentValue == 0 || (currentValue & 0xFFFFFF00) != 0) {
                            byte[] correctValue = new byte[]{4, 0, 0, 0};
                            backend.mem_write(targetAddr, correctValue);
                            System.out.println("[签名绕过]   修正栈值 [SP+0x" + Integer.toHexString(offset) + "+0x30] = 4 (was " + currentValue + ")");
                        }
                    }

                    // 3. 跳转到返回地址
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, lr);

                    System.out.println("[签名绕过]   ✅ 已跳过所有验证，返回成功 (LR=0x" + Long.toHexString(lr) + ")");
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                System.out.println("[签名绕过] ✓ Hook 已激活");
            }

            @Override
            public void detach() {}
        }, SUB_3E5C0_ADDR, SUB_3E5C0_ADDR + 4, null);  // 只Hook入口的4字节

        // 🔧 终极策略：直接在sub_3E5C0的Hook中修正[sp+0x30]的值
        // 由于sub_3E5C0在初始化和加密流程中都被调用，我们在这里统一修正栈值
        //
        // 问题根源：
        // sub_3E5C0执行失败会在栈上设置错误标志（[sp+0x30] = -1）
        // 但我们已经跳过了sub_3E5C0，所以栈上的值是未初始化的随机值
        // 需要在跳过验证后，手动设置正确的值

        System.out.println("[签名绕过] ✓ Hook设置完成\n");
    }


    /**
     * 设置反调试变量监控
     *
     * 功能说明:
     * - 监控JNI_OnLoad函数中的关键反调试变量dword_70C10和dword_70C14
     * - 这两个变量位于SO的.data段,用于检测调试器和模拟器环境
     *
     * 数据类型:
     * - dword = DWORD = 4字节32位无符号整数 (uint32_t)
     * - 但在代码中被当作有符号int使用
     *
     * 反调试逻辑:
     * - 条件1: dword_70C10 >= 10
     * - 条件2: ((dword_70C14-1) * dword_70C14) & 1 != 0
     * - 如果两个条件都满足,则进入混淆代码分支(检测到调试器)
     *
     * 正常值(不触发反调试):
     * - dword_70C10 = -1 (0xFFFFFFFF) 或 < 10
     * - dword_70C14 = -1 (0xFFFFFFFF)
     *
     * 监控时机:
     * - JNI_OnLoad执行过程中的5个反调试检查点:
     *   1. 0x45908 - 初始化前检查
     *   2. 0x45978 - GetEnv后检查
     *   3. 0x45a14 - FindClass后检查
     *   4. 0x45b80 - 保存数据后检查
     *   5. 0x45ce0 - 最终死循环陷阱
     */
    private void setupAntiDebugMonitoring() {
        Backend backend = emulator.getBackend();
        System.out.println("\n[反调试监控] 开始设置监控...");

        // 定义反调试变量的地址
        // 这些地址是相对于SO基址的偏移量
        final long DWORD_70C10_OFFSET = 0x70C10;  // 第一个反调试标志
        final long DWORD_70C14_OFFSET = 0x70C14;  // 第二个反调试标志

        final long dword_70C10_addr = module.base + DWORD_70C10_OFFSET;
        final long dword_70C14_addr = module.base + DWORD_70C14_OFFSET;

        // 读取并显示初始值
        System.out.println("[反调试监控] 变量地址:");
        System.out.println("[反调试监控]   - dword_70C10 @ 0x" + Long.toHexString(dword_70C10_addr));
        System.out.println("[反调试监控]   - dword_70C14 @ 0x" + Long.toHexString(dword_70C14_addr));

        // 读取初始值(4字节,小端序)
        // ByteBuffer默认是大端序,需要设置为小端序来正确读取ARM架构的数据
        byte[] bytes1 = backend.mem_read(dword_70C10_addr, 4);
        java.nio.ByteBuffer buf1 = java.nio.ByteBuffer.wrap(bytes1);
        buf1.order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int initial_70C10 = buf1.getInt();

        byte[] bytes2 = backend.mem_read(dword_70C14_addr, 4);
        java.nio.ByteBuffer buf2 = java.nio.ByteBuffer.wrap(bytes2);
        buf2.order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int initial_70C14 = buf2.getInt();

        System.out.println("[反调试监控] 初始值:");
        System.out.println("[反调试监控]   - dword_70C10 = " + initial_70C10 +
                         " (0x" + Integer.toHexString(initial_70C10) + ")");
        System.out.println("[反调试监控]   - dword_70C14 = " + initial_70C14 +
                         " (0x" + Integer.toHexString(initial_70C14) + ")");

        // 分析当前值是否会触发反调试
        analyzeAntiDebugValues(initial_70C10, initial_70C14);

        // 定义JNI_OnLoad中的5个反调试检查点
        // 这些地址对应IDA中添加注释的位置
        long[] checkPoints = {
            module.base + 0x45908,  // 检查点1: 初始化前检查
            module.base + 0x45978,  // 检查点2: GetEnv后检查
            module.base + 0x45a14,  // 检查点3: FindClass后检查
            module.base + 0x45b80,  // 检查点4: 保存数据后检查
            module.base + 0x45cdc   // 检查点5: 最终检查(死循环前)
        };

        String[] checkPointNames = {
            "初始化前检查",
            "GetEnv后检查",
            "FindClass后检查",
            "保存数据后检查",
            "最终检查(死循环前)"
        };

        // 为每个检查点设置Hook
        for (int i = 0; i < checkPoints.length; i++) {
            final int checkIndex = i;
            final String checkName = checkPointNames[i];
            final long checkAddr = checkPoints[i];

            backend.hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    // 读取当前的反调试变量值(使用小端序)
                    byte[] bytes1 = backend.mem_read(dword_70C10_addr, 4);
                    java.nio.ByteBuffer buf1 = java.nio.ByteBuffer.wrap(bytes1);
                    buf1.order(java.nio.ByteOrder.LITTLE_ENDIAN);
                    int current_70C10 = buf1.getInt();

                    byte[] bytes2 = backend.mem_read(dword_70C14_addr, 4);
                    java.nio.ByteBuffer buf2 = java.nio.ByteBuffer.wrap(bytes2);
                    buf2.order(java.nio.ByteOrder.LITTLE_ENDIAN);
                    int current_70C14 = buf2.getInt();

                    System.out.println("\n[反调试监控] 检查点 #" + (checkIndex + 1) + ": " + checkName);
                    System.out.println("[反调试监控]   地址: 0x" + Long.toHexString(address - module.base));
                    System.out.println("[反调试监控]   dword_70C10 = " + current_70C10 +
                                     " (0x" + Integer.toHexString(current_70C10) + ")");
                    System.out.println("[反调试监控]   dword_70C14 = " + current_70C14 +
                                     " (0x" + Integer.toHexString(current_70C14) + ")");

                    // 分析是否会触发反调试
                    analyzeAntiDebugValues(current_70C10, current_70C14);
                }

                @Override
                public void onAttach(UnHook unHook) {}

                @Override
                public void detach() {}
            }, checkAddr, checkAddr + 4, null);
        }

        System.out.println("[反调试监控] ✓ 已设置 " + checkPoints.length + " 个监控点\n");
    }

    /**
     * 分析反调试变量的值,判断是否会触发反调试
     *
     * 反调试触发条件:
     * - 条件A: dword_70C10 >= 10
     * - 条件B: ((dword_70C14-1) * dword_70C14) & 1 != 0
     * - 如果 A && B 都为true,则触发反调试
     *
     * @param val_70C10 dword_70C10的当前值
     * @param val_70C14 dword_70C14的当前值
     */
    private void analyzeAntiDebugValues(int val_70C10, int val_70C14) {
        // 计算反调试表达式
        int expression = (val_70C14 - 1) * val_70C14;

        // 检查条件A
        boolean conditionA = val_70C10 >= 10;
        System.out.println("[反调试分析]   条件A: dword_70C10 >= 10 ? " +
                         conditionA + " (" + val_70C10 + " >= 10)");

        // 检查条件B
        boolean conditionB = (expression & 1) != 0;
        System.out.println("[反调试分析]   计算式: (dword_70C14-1)*dword_70C14 = " +
                         "(" + val_70C14 + "-1)*" + val_70C14 + " = " + expression);
        System.out.println("[反调试分析]   条件B: (计算式 & 1) != 0 ? " +
                         conditionB + " (" + expression + " & 1 = " + (expression & 1) + ")");

        // 最终判断
        if (conditionA && conditionB) {
            System.out.println("[反调试分析] ❌ 警告: 两个条件都满足,会触发反调试!");
            System.out.println("[反调试分析]      程序会进入混淆代码分支或死循环");
        } else {
            System.out.println("[反调试分析] ✓ 正常: 不会触发反调试");
            if (!conditionA) {
                System.out.println("[反调试分析]      原因: dword_70C10 < 10");
            }
            if (!conditionB) {
                System.out.println("[反调试分析]      原因: (表达式 & 1) == 0");
            }
        }
    }

    /**
     * 在初始化阶段提前设置全局标志位
     * 必须在 JNI_OnLoad 之后、第一次调用 doCommandNative 之前设置
     */
    private void setGlobalFlagsEarly() {
        Backend backend = emulator.getBackend();
        try {
            // 1. 设置 qword_70910 = 0x1800000000000
            long qword_70910_addr = module.base + 0x70910;
            long flagValue = 0x1800000000000L;
            byte[] flagBytes = new byte[8];
            for (int i = 0; i < 8; i++) {
                flagBytes[i] = (byte) ((flagValue >> (i * 8)) & 0xFF);
            }
            backend.mem_write(qword_70910_addr, flagBytes);
            System.out.println("[初始化]   ✓ qword_70910 @ 0x" + Long.toHexString(qword_70910_addr) +
                    " = 0x" + Long.toHexString(flagValue));

            // 验证写入是否成功
            byte[] verify70910 = backend.mem_read(qword_70910_addr, 8);
            java.nio.ByteBuffer buf1 = java.nio.ByteBuffer.wrap(verify70910);
            buf1.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            long actualValue = buf1.getLong();
            System.out.println("[验证]     实际读取到的值: 0x" + Long.toHexString(actualValue));
            if (actualValue != flagValue) {
                System.out.println("[验证]     ❌ 警告：写入的值与期望不符！");
            }

            // 2. 设置 byte_7091F 的 bit 5 (0x20)
            long byte_7091F_addr = module.base + 0x7091F;
            byte[] currentByte = backend.mem_read(byte_7091F_addr, 1);
            byte oldValue = currentByte[0];
            currentByte[0] |= 0x20;  // 设置 bit 5
            backend.mem_write(byte_7091F_addr, currentByte);
            System.out.println("[初始化]   ✓ byte_7091F @ 0x" + Long.toHexString(byte_7091F_addr) +
                    " = 0x" + Integer.toHexString(currentByte[0] & 0xFF) +
                    " (was 0x" + Integer.toHexString(oldValue & 0xFF) + ")");

            // 验证写入是否成功
            byte[] verify7091F = backend.mem_read(byte_7091F_addr, 1);
            System.out.println("[验证]     实际读取到的值: 0x" + Integer.toHexString(verify7091F[0] & 0xFF));
            if ((verify7091F[0] & 0x20) == 0) {
                System.out.println("[验证]     ❌ 警告：bit 5 未被正确设置！");
            }
        } catch (Exception e) {
            System.out.println("[初始化] ❌ 设置标志位失败: " + e.getMessage());
            e.printStackTrace();
        }
    }


    // BiliIOResolver.java - 独立的处理器类
    public static class BiliIOResolver implements IOResolver<AndroidFileIO> {
        @Override
        public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
            // 过滤掉无效路径（内存地址或乱码）
            if (pathname == null || pathname.length() < 3 || pathname.matches(".*[\\x00-\\x1F\\x7F-\\x9F].*")) {
                // 忽略无效路径，不打印日志
                return null;
            }

            // 打印所有文件访问请求
            System.out.println("[IOResolver] 文件打开请求: " + pathname + " (flags=0x" + Integer.toHexString(oflags) + ")");

            // ⭐ 关键修复：拦截APK路径访问，返回真实的APK文件
            // SO库会尝试打开getPackageCodePath()返回的路径
            if (pathname.contains("base.apk")) {
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
                        // 使用 O_RDONLY 标志创建 SimpleFileIO
                        return FileResult.<AndroidFileIO>success(new SimpleFileIO(0 /* O_RDONLY */, realApk, pathname));
                    } catch (Exception e) {
                        System.out.println("[IOResolver] ❌ 打开APK文件失败: " + e.getMessage());
                        e.printStackTrace();
                    }
                } else {
                    System.out.println("[IOResolver] ❌ APK文件不存在: " + realApk.getAbsolutePath());
                }
            }

            // 在这里添加具体的文件处理逻辑
            switch (pathname) {  // boot_id 处理
                // 注意：这里的路径需要和样本访问的完全一致   unidbg-android/src/test/resources/cpu/boot_id
                case "/proc/sys/kernel/random/boot_id": {
                    return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/resources/cpu/boot_id"), pathname));
                }
                case "/proc/sys/kernel/random/boot_id1": {  // 随机的 备用
                    // 动态生成UUID作为boot_id
                    String randomBootId = UUID.randomUUID().toString();
                    return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, randomBootId.getBytes(StandardCharsets.UTF_8)));
                }
                case "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq": {
                    // 直接返回一个字符串作为文件内容
                    return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, "1766400".getBytes()));
                }
                case "/proc/self/cmdline": {
                    return FileResult.success(new ByteArrayFileIO(oflags, pathname, PACKAGE_NAME.getBytes()));
                }
                case "/proc/self/status": {
                    // 返回一个包含 "TracerPid: 0" 的文件内容，表示未被调试
                    String statusContent = "Name:\t" + PACKAGE_NAME + "\n" +
                            "Umask:\t0077\n" +
                            "State:\tS (sleeping)\n" +
                            "Tgid:\t12345\n" +
                            "Pid:\t12345\n" +
                            "PPid:\t1\n" +
                            "TracerPid:\t0\n"; // 关键行
                    return FileResult.success(new ByteArrayFileIO(oflags, pathname, statusContent.getBytes()));
                }
                // 在 IOResolver 的 resolve 方法中  "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/" + packageName + "-JZD_aIoXsKoTPab3p20hBw==/base.apk"
                case "/proc/self/maps": {
                    final String APK_PATH = "/data/app/com.kuaishou.nebula-q14Fo0PSb77vTIOM1-iEqQ==/base.apk";
                    String maps = "7fbe852000-7fbe853000 r-xp 00000000 00:00 0 " + APK_PATH + "\n";
                    return FileResult.success(new ByteArrayFileIO(oflags, pathname, maps.getBytes(StandardCharsets.UTF_8)));
                }
                case "/proc/stat": {
                    return FileResult.success(new SimpleFileIO(oflags, new File("unidbg-android/src/test/java/com/kuaishou/nebula/proc_stat.txt"), pathname));

                }
                case "/dev/__properties__": {
                    System.out.println("[IOResolver] ✓ 返回空属性文件");
                    return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                            new byte[0]));  // 空文件即可
                }
            }

            //  有些 Root 检测会尝试访问 /data 目录的权限。由于 Unidbg 的虚拟文件系统会自动创建 /data 目录导致访问成功，我们需要手动拦截并返回"权限不足"。
            if ("/data".equals(pathname)) {
                return FileResult.failed(UnixEmulator.EACCES); // EACCES = 13, Permission denied
            }


            return null; // 返回null表示未处理，交由下一个处理器
        }


    }

//    /**
//     * IOResolver接口实现 - 处理文件系统访问
//     * 根据《安卓逆向这档事》第25课教程补充完整的文件访问处理
//     *
//     * 关键文件优先级：
//     * 1. /proc/self/maps - APK路径查找和完整性校验（必须）
//     * 2. /proc/self/status - 反调试检测 TracerPid（必须）
//     * 3. /proc/self/cmdline - 进程名校验（必须）
//     * 4. base.apk - 签名校验和资源访问（必须）
//     */
//    @Override
//    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
//        if (pathname == null) {
//            System.out.println("[IOResolver] pathname is NULL");
//            return null;
//        }
//
//        // 检测并忽略无效路径（内存地址被误当作字符串）
//        if (pathname.length() < 10 && pathname.contains("\ufffd")) {
//            // \ufffd 是 Unicode 替换字符，表示无效的字节序列
//            System.out.println("[IOResolver] 忽略无效路径（内存地址）: " + pathname);
//            // 🔍 调试：打印调用堆栈
//            Backend backend = emulator.getBackend();
//            long pc = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
//            long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
//            System.out.println("[IOResolver]   调用位置: PC=0x" + Long.toHexString(pc) +
//                             " LR=0x" + Long.toHexString(lr) +
//                             " (offset=0x" + Long.toHexString(lr - module.base) + ")");
//            return null;
//        }
//
//        System.out.println("[IOResolver] 请求打开文件: " + pathname);
//
//        // ========== 1. 处理APK路径（签名校验必需） ==========
//        if (pathname.contains("/base.apk")) {
//            File apkFile = new File("/Users/yml/IdeaProjects/unidbg_1/unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
//            if (apkFile.exists()) {
//                System.out.println("[IOResolver] ✓ 返回APK文件");
//                return FileResult.success(new com.github.unidbg.linux.file.SimpleFileIO(oflags, apkFile, pathname));
//            } else {
//                System.out.println("[IOResolver] ❌ APK文件不存在: " + apkFile.getAbsolutePath());
//            }
//        }
//
//        // ========== 2. 处理关键系统文件 ==========
//        switch (pathname) {
//            // ---------- /proc/self/cmdline: 进程名校验 ----------
//            case "/proc/self/cmdline": {
//                System.out.println("[IOResolver] ✓ 返回进程名（使用VM包名）");
//                // 使用VM的包名（从APK读取的真实包名）
//                String packageName = vm.getPackageName();
//                return FileResult.success(new ByteArrayFileIO(oflags, pathname,
//                        packageName.getBytes(StandardCharsets.UTF_8)));
//            }
//
//            // ---------- /proc/self/status: 反调试检测（TracerPid必须为0） ----------
//            case "/proc/self/status": {
//                System.out.println("[IOResolver] ✓ 返回进程状态（TracerPid=0，未被调试）");
//                // 构建完整的 status 内容，关键是 TracerPid: 0
//                StringBuilder statusContent = new StringBuilder();
//                // 使用VM的包名
//                String packageName = vm.getPackageName();
//                statusContent.append("Name:\t").append(packageName).append("\n");
//                statusContent.append("Umask:\t0077\n");
//                statusContent.append("State:\tS (sleeping)\n");
//                statusContent.append("Tgid:\t").append(emulator.getPid()).append("\n");
//                statusContent.append("Ngid:\t0\n");
//                statusContent.append("Pid:\t").append(emulator.getPid()).append("\n");
//                statusContent.append("PPid:\t1\n");
//                statusContent.append("TracerPid:\t0\n");  // ⭐ 关键：必须为0，表示未被调试
//                statusContent.append("Uid:\t10185\t10185\t10185\t10185\n");
//                statusContent.append("Gid:\t10185\t10185\t10185\t10185\n");
//
//                return FileResult.success(new ByteArrayFileIO(oflags, pathname,
//                        statusContent.toString().getBytes(StandardCharsets.UTF_8)));
//            }
//
//            // ---------- /proc/self/maps: APK路径查找和完整性校验 ----------
//            case "/proc/self/maps": {
//                System.out.println("[IOResolver] ✓ 返回极简 maps（使用真实包名构造路径）");
//                // 使用真实包名构造APK路径
//                String packageName = vm.getPackageName();
//                final String APK_PATH = "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/" + packageName + "-JZD_aIoXsKoTPab3p20hBw==/base.apk";
//                System.out.println("[IOResolver]   APK路径: " + APK_PATH);
//
//                // 构造一个虚拟的内存映射条目
//                // 格式: 起始地址-结束地址 权限 偏移 设备 inode 路径
//                StringBuilder mapsContent = new StringBuilder();
//                mapsContent.append("7fbe852000-7fbe853000 r-xp 00000000 00:00 0 ").append(APK_PATH).append("\n");
//
//                // 可选：添加 SO 库的映射（如果需要）
//                // mapsContent.append("12000000-12072000 r-xp 00000000 103:09 12345 /data/app/.../lib/arm64/libkwsgmain.so\n");
//
//                return FileResult.success(new ByteArrayFileIO(oflags, pathname,
//                        mapsContent.toString().getBytes(StandardCharsets.UTF_8)));
//            }
//
//            // ---------- /dev/__properties__: 系统属性存储 ----------
//            case "/dev/__properties__": {
//                System.out.println("[IOResolver] ✓ 返回空属性文件");
//                return FileResult.success(new ByteArrayFileIO(oflags, pathname,
//                        new byte[0]));  // 空文件即可
//            }
//
//            // ---------- 其他未处理的文件 ----------
//            default:
//                // 返回 null 让 Unidbg 使用默认处理
//                // 对于 /proc/stat 等文件，Unidbg 会自动处理
//                return null;
//        }
//    }


    private void call_doCommandNative_sig3(String text) {
        List<Object> params = new ArrayList<>();
        params.add(vm.getJNIEnv());
        params.add(0);
        params.add(10418);
        StringObject str = new StringObject(vm, text);
        vm.addLocalObject(str);
        ArrayObject strArray = new ArrayObject(str);
        StringObject key1 = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(key1);
        DvmInteger dInt = DvmInteger.valueOf(vm, -1);
        vm.addLocalObject(dInt);
        DvmBoolean dBoolean = DvmBoolean.valueOf(vm, false);
        vm.addLocalObject(dBoolean);
        DvmObject<?> dClass = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null);
        vm.addLocalObject(dClass);
        StringObject key2 = new StringObject(vm, "");
        vm.addLocalObject(key2);
        ArrayObject paramArray = new ArrayObject(strArray, key1, dInt, dBoolean, dClass, null, dBoolean, key2);
        params.add(vm.addLocalObject(paramArray));
        Number number = module.callFunction(emulator, 0x40cd4, params.toArray());
        DvmObject<?> object = vm.getObject(number.intValue());
        String result = (String) object.getValue();
        System.out.println("result:" + result);
    }

    public static void main(String[] args) {
        KSEmulator ksEmulator = new KSEmulator();

        // 🔍 创建ExecutionTracer进行详细跟踪
        System.out.println("\n========== 启动详细执行跟踪 ==========");
        ExecutionTracer tracer = new ExecutionTracer(ksEmulator.emulator, ksEmulator.module);
        tracer.enableDetailedTrace();

        // 策略1：正常初始化流程
        System.out.println("\n========== 第1步：初始化环境 ==========");
        String initResult = ksEmulator.call_doCommandNative_init();
        System.out.println("[主流程] 初始化结果: " + initResult);

        if (initResult == null || !initResult.equals("1")) {
            System.out.println("[主流程] ⚠️ 初始化返回0，但尝试继续执行（签名已通过）");
            // 不要 return，继续执行
        }

        // 策略2：尝试直接加密（全局标志位已在构造函数中设置）
        System.out.println("\n========== 第2步：加密数据 ==========");
        String encResult = ksEmulator.encryptEncData();

        if (encResult != null) {
            System.out.println("[主流程] ✓ 加密成功");
            System.out.println("[主流程] 加密结果长度: " + encResult.length());

            // 🔧 转换为Base64
            try {
                byte[] encBytes = hexToBytes(encResult);
                String base64Result = java.util.Base64.getEncoder().encodeToString(encBytes);
                System.out.println("\n[Base64结果] 加密数据的Base64编码:");
                System.out.println(base64Result);
                System.out.println("\n[Base64结果] Base64长度: " + base64Result.length());
            } catch (Exception e) {
                System.out.println("[Base64转换] ❌ 转换失败: " + e.getMessage());
                e.printStackTrace();
            }

            // 验证结果
            if (ENC_DATA_EXPECTED_HEX.equalsIgnoreCase(encResult)) {
                System.out.println("\n[主流程] 🎉 加密结果完全匹配！");
            } else {
                System.out.println("\n[主流程] ⚠️ 加密结果不匹配");
                System.out.println("[主流程] 期望长度: " + ENC_DATA_EXPECTED_HEX.length());
                System.out.println("[主流程] 实际长度: " + encResult.length());

                // 显示前后差异
                int previewLen = Math.min(100, Math.min(encResult.length(), ENC_DATA_EXPECTED_HEX.length()));
                System.out.println("[主流程] 实际结果前100字符: " + encResult.substring(0, previewLen));
                System.out.println("[主流程] 期望结果前100字符: " + ENC_DATA_EXPECTED_HEX.substring(0, previewLen));
            }
        } else {
            System.out.println("[主流程] ❌ 加密失败");
        }

        // 🔍 打印详细的执行跟踪报告
        tracer.printReport();

        System.out.println("\n========== 执行完成 ==========\n");
    }


    /**
     * ⚠️ 已废弃 - 根据ExecutionTracer分析,这个方法会导致加密失败!
     *
     * 问题: 设置 dword_70C10 = -1 会导致在 0x42e08 处的opcode检查失败
     * 真机数据显示这两个变量应该保持为 0 (初始值)
     *
     * 解决方案: 不调用此方法,保持变量为初始值 0
     */
    @Deprecated
    private void disableAntiDebugBeforeEncryption_DEPRECATED() {
        Backend backend = emulator.getBackend();
        System.out.println("\n[反调试绕过] ⚠️ 此方法已废弃,不应被调用!");

        // 定义反调试变量的地址（相对于SO基址的偏移量）
        final long DWORD_70C10_OFFSET = 0x70C10;  // 第一个反调试标志
        final long DWORD_70C14_OFFSET = 0x70C14;  // 第二个反调试标志

        final long dword_70C10_addr = module.base + DWORD_70C10_OFFSET;
        final long dword_70C14_addr = module.base + DWORD_70C14_OFFSET;

        System.out.println("[反调试绕过] 变量地址:");
        System.out.println("[反调试绕过]   - dword_70C10 @ 0x" + Long.toHexString(dword_70C10_addr));
        System.out.println("[反调试绕过]   - dword_70C14 @ 0x" + Long.toHexString(dword_70C14_addr));

        try {
            // 读取原始值（用于对比）
            byte[] bytes1 = backend.mem_read(dword_70C10_addr, 4);
            java.nio.ByteBuffer buf1 = java.nio.ByteBuffer.wrap(bytes1);
            buf1.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int original_70C10 = buf1.getInt();

            byte[] bytes2 = backend.mem_read(dword_70C14_addr, 4);
            java.nio.ByteBuffer buf2 = java.nio.ByteBuffer.wrap(bytes2);
            buf2.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int original_70C14 = buf2.getInt();

            System.out.println("[反调试绕过] 原始值:");
            System.out.println("[反调试绕过]   - dword_70C10 = " + original_70C10 +
                             " (0x" + Integer.toHexString(original_70C10) + ")");
            System.out.println("[反调试绕过]   - dword_70C14 = " + original_70C14 +
                             " (0x" + Integer.toHexString(original_70C14) + ")");

            // ❌ 错误的做法 - 不要设置为-1!
            // 设置 dword_70C10 = -1 (0xFFFFFFFF)
            // -1的小端序表示：FF FF FF FF
            byte[] newValue70C10 = new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
            backend.mem_write(dword_70C10_addr, newValue70C10);

            // 设置 dword_70C14 = -1 (0xFFFFFFFF)
            byte[] newValue70C14 = new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
            backend.mem_write(dword_70C14_addr, newValue70C14);

            System.out.println("[反调试绕过] 新值设置:");
            System.out.println("[反调试绕过]   - dword_70C10 = -1 (0xFFFFFFFF)");
            System.out.println("[反调试绕过]   - dword_70C14 = -1 (0xFFFFFFFF)");

            // 验证写入是否成功
            byte[] verify1 = backend.mem_read(dword_70C10_addr, 4);
            java.nio.ByteBuffer verifyBuf1 = java.nio.ByteBuffer.wrap(verify1);
            verifyBuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int actual_70C10 = verifyBuf1.getInt();

            byte[] verify2 = backend.mem_read(dword_70C14_addr, 4);
            java.nio.ByteBuffer verifyBuf2 = java.nio.ByteBuffer.wrap(verify2);
            verifyBuf2.order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int actual_70C14 = verifyBuf2.getInt();

            System.out.println("[反调试绕过] 验证写入:");
            System.out.println("[反调试绕过]   - dword_70C10 实际值: " + actual_70C10 +
                             " (0x" + Integer.toHexString(actual_70C10) + ")");
            System.out.println("[反调试绕过]   - dword_70C14 实际值: " + actual_70C14 +
                             " (0x" + Integer.toHexString(actual_70C14) + ")");

            // 验证反调试条件
            boolean condition1 = actual_70C10 < 10;
            int expression = (actual_70C14 - 1) * actual_70C14;
            boolean condition2 = (expression & 1) == 0;

            System.out.println("[反调试绕过] 条件检查:");
            System.out.println("[反调试绕过]   - 条件1: dword_70C10 < 10 ? " +
                             condition1 + " (" + actual_70C10 + " < 10)");
            System.out.println("[反调试绕过]   - 条件2: ((dword_70C14-1)*dword_70C14) & 1 == 0 ? " +
                             condition2 + " ((" + actual_70C14 + "-1)*" + actual_70C14 + " & 1 = " + (expression & 1) + ")");

            if (condition1 || condition2) {
                System.out.println("[反调试绕过] ✅ 反调试检查将会通过（至少一个条件满足）");
            } else {
                System.out.println("[反调试绕过] ⚠️ 警告：反调试检查可能仍会失败");
            }

            if (actual_70C10 != -1 || actual_70C14 != -1) {
                System.out.println("[反调试绕过] ❌ 警告：写入值与期望不符！");
            }

        } catch (Exception e) {
            System.out.println("[反调试绕过] ❌ 设置失败: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("[反调试绕过] ✓ 设置完成\n");
    }

    public String encryptEncData() {
        System.out.println("\n[encryptEncData] 开始执行 encData 调用...");

        // 🔍 启用详细的JNI调用跟踪
        setupDetailedJNITrace();

        // ✅ 修复：不再调用disableAntiDebugBeforeEncryption()
        // 根据ExecutionTracer分析,设置这两个变量为-1会导致opcode检查失败
        // 应该保持为初始值0,与真机一致
        System.out.println("\n[反调试变量] 保持初始值 0 (与真机一致)");

        // 🔍 在加密前验证全局标志位是否正确设置
        Backend backend = emulator.getBackend();
        System.out.println("\n[加密前检查] 验证全局标志位状态:");

        // 检查 qword_70910
        long qword_70910_addr = module.base + 0x70910;
        byte[] verify70910 = backend.mem_read(qword_70910_addr, 8);
        java.nio.ByteBuffer buf1 = java.nio.ByteBuffer.wrap(verify70910);
        buf1.order(java.nio.ByteOrder.LITTLE_ENDIAN);
        long actualValue70910 = buf1.getLong();
        System.out.println("[加密前检查]   qword_70910 @ 0x" + Long.toHexString(qword_70910_addr) +
                         " = 0x" + Long.toHexString(actualValue70910));
        long expectedFlag = 0x1800000000000L;
        if ((actualValue70910 & expectedFlag) == 0) {
            System.out.println("[加密前检查]   ❌ 警告：qword_70910 标志位检查失败！");
            System.out.println("[加密前检查]      期望: (value & 0x1800000000000) != 0");
            System.out.println("[加密前检查]      实际: (0x" + Long.toHexString(actualValue70910) +
                             " & 0x1800000000000) = 0x" + Long.toHexString(actualValue70910 & expectedFlag));
        } else {
            System.out.println("[加密前检查]   ✓ qword_70910 检查通过");
        }

        // 检查 byte_7091F
        long byte_7091F_addr = module.base + 0x7091F;
        byte[] verify7091F = backend.mem_read(byte_7091F_addr, 1);
        System.out.println("[加密前检查]   byte_7091F @ 0x" + Long.toHexString(byte_7091F_addr) +
                         " = 0x" + Integer.toHexString(verify7091F[0] & 0xFF));
        if ((verify7091F[0] & 0x20) == 0) {
            System.out.println("[加密前检查]   ❌ 警告：byte_7091F bit 5 未设置！");
            System.out.println("[加密前检查]      期望: (value & 0x20) != 0");
        } else {
            System.out.println("[加密前检查]   ✓ byte_7091F bit 5 检查通过");
        }
        System.out.println();

        int opcode = 10400;  // ✅ 修复：使用正确的opcode值
        System.out.println("[encryptEncData] opcode: " + opcode);
        System.out.println("[encryptEncData] 使用共享Context: " + context);

        List<Object> list = new ArrayList<>(4);
        list.add(vm.getJNIEnv());
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz));
        list.add(opcode);

        System.out.println("[encryptEncData] 📊 请求Hex长度: " + ENC_DATA_REQUEST_HEX.length());
        byte[] requestBytes = hexToBytes(ENC_DATA_REQUEST_HEX);
        System.out.println("[encryptEncData] 📊 请求字节长度: " + requestBytes.length);

        // 验证数据完整性
        String hexPreview = ENC_DATA_REQUEST_HEX.substring(0, Math.min(100, ENC_DATA_REQUEST_HEX.length()));
        System.out.println("[encryptEncData] 📊 数据预览: " + hexPreview + "...");

        // 检查版本号（应该包含 "13.8.40.10657" 的十六进制表示）
        if (ENC_DATA_REQUEST_HEX.contains("31332E382E34302E3130363537")) {
            System.out.println("[encryptEncData] ✅ 版本号校验通过: 13.8.40.10657");
        } else if (ENC_DATA_REQUEST_HEX.contains("31322E372E32302E38353032")) {
            System.out.println("[encryptEncData] ⚠️ 警告：使用的是旧版本 12.7.20.8502");
        } else {
            System.out.println("[encryptEncData] ⚠️ 警告：无法识别版本号");
        }

        // 🔑 根据错误日志分析不同 opcode 的参数类型：
        // - opcode 10400: 期望 ByteArray (DalvikVM64:3176)
        // - opcode 10408: 期望 ArrayObject(StringObject(Hex))
        // - encData.log 显示真实环境使用的是 Hex 字符串

        // 🔧 修复：根据执行日志，native 代码期望参数[0] 是 ArrayObject[StringObject]
        // 其中 StringObject 包含十六进制字符串（而不是 ByteArray）
        // 参考 call_doCommandNative_sig3 方法中的参数构造

        // 将字节数组转换为十六进制字符串
        String requestHexString = ENC_DATA_REQUEST_HEX;
        StringObject hexStringObj = new StringObject(vm, requestHexString);
        vm.addLocalObject(hexStringObj);

        // 将十六进制字符串包装成单元素的 ArrayObject
        ArrayObject requestParam = new ArrayObject(hexStringObj);
        vm.addLocalObject(requestParam);

        System.out.println("[encryptEncData] ✅ 参数[0]: ArrayObject[StringObject] (Hex字符串长度=" + requestHexString.length() + ")");

        // 参数[1]: UUID字符串
        StringObject uuid1 = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(uuid1);

        // 参数[2]: 整数 0
        DvmInteger intZero = DvmInteger.valueOf(vm, 0);
        vm.addLocalObject(intZero);

        // 参数[3]: null（真实环境中是 null）
        // 不需要 addLocalObject，直接在数组中传 null

        // 参数[4]: Application 对象（com.yxcorp.gifshow.App）
        // 使用共享的Context对象
        DvmObject<?> appObject = context;

        // 参数[5]: boolean true
        DvmBoolean boolTrue1 = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolTrue1);

        // 参数[6]: boolean true
        DvmBoolean boolTrue2 = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolTrue2);

        // 参数[7]: UUID字符串
        StringObject uuid2 = new StringObject(vm, "95147564-9763-4413-a937-6f0e3c12caf1");
        vm.addLocalObject(uuid2);

        // 🔍 根据 encData.log 真实抓包，参数结构：
        // [0] byte[] - 加密数据
        // [1] String - UUID-1
        // [2] int - 0
        // [3] null - 空对象
        // [4] Application - App对象
        // [5] boolean - true
        // [6] boolean - true
        // [7] String - UUID-2
        ArrayObject paramsArray = new ArrayObject(
                requestParam,      // [0] ByteArray
                uuid1,             // [1] UUID-1
                intZero,           // [2] Integer 0
                null,              // [3] null ⚠️ 关键修正
                appObject,         // [4] Application
                boolTrue1,         // [5] Boolean true
                boolTrue2,         // [6] Boolean true
                uuid2              // [7] UUID-2
        );
        System.out.println("[encryptEncData] 参数数组长度: " + 8);
        list.add(vm.addLocalObject(paramsArray));

        System.out.println("[encryptEncData] 即将调用 doCommandNative (0x40cd4)...");
        emulator.traceCode(module.base + 0x42bc8, module.base + 0x43000);  // 跟踪GetByteArrayRegion之后的代码

        Number result = module.callFunction(emulator, 0x40cd4, list.toArray());


        String resultInfo = result == null ? "null" : result + " (0x" + Long.toHexString(result.longValue()) + ")";
        System.out.println("\n[encryptEncData] JNI 原始返回: " + resultInfo);
        if (result == null || result.intValue() == -1) {
            System.out.println("[encryptEncData] 调用失败，返回值: " + result);
            return null;
        }

        DvmObject<?> resultObject = vm.getObject(result.intValue());
        System.out.println("[encryptEncData] vm.getObject -> " + resultObject);
        if (resultObject instanceof ByteArray) {
            byte[] encBytes = ((ByteArray) resultObject).getValue();
            String hexResult = bytesToHex(encBytes);
            System.out.println("[encryptEncData] encData Hex: " + hexResult);
            System.out.println("[encryptEncData] 是否匹配样本: " + ENC_DATA_EXPECTED_HEX.equalsIgnoreCase(hexResult));
            return hexResult;
        }

        if (resultObject != null) {
            System.out.println("[encryptEncData] 返回对象类型: " + resultObject.getClass().getSimpleName() + " 值: " + resultObject.getValue());
            return String.valueOf(resultObject.getValue());
        }

        System.out.println("[encryptEncData] 返回对象为空");
        return null;
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex string is null");
        }
        int length = hex.length();
        if ((length & 1) != 0) {
            throw new IllegalArgumentException("hex string length must be even");
        }
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex character detected");
            }
            data[i / 2] = (byte) ((high << 4) + low);
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    private String call_doCommandNative_init() {
        System.out.println("[initializeEnvironment] 使用共享Context: " + context);


        List<Object> list = new ArrayList<>(4);
        list.add(vm.getJNIEnv()); // 第⼀个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。

        list.add(10412); // opcode参数 - 初始化命令

        // 构建参数数组 - 参考 encryptEncData 的参数结构
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);

        DvmInteger zero = DvmInteger.valueOf(vm, 0);
        vm.addLocalObject(zero);

        // 参数数组：[null, appkey, zero, null, context, null, null]
        // 注意：第一个参数可能需要是 ByteArray 或其他类型
        ArrayObject paramsArray = new ArrayObject(
                null,       // [0] 可能需要 ByteArray
                appkey,     // [1] app key
                zero,       // [2] Integer 0
                null,       // [3] null
                context,    // [4] Context
                null,       // [5] null
                null        // [6] null
        );
        list.add(vm.addLocalObject(paramsArray));

        System.out.println("[initializeEnvironment] 调用 doCommandNative(opcode=10412)...");
        Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());


        // 详细的返回值分析
        System.out.println("[initializeEnvironment] 原始返回值: " + numbers +
                (numbers != null ? " (0x" + Long.toHexString(numbers.longValue()) + ")" : ""));

        if (numbers == null) {
            System.out.println("[initializeEnvironment] ❌ 返回值为 null");
            return null;
        }

        int retValue = numbers.intValue();
        System.out.println("[initializeEnvironment] 返回值整数: " + retValue);

        if (retValue == 0) {
            System.out.println("[initializeEnvironment] ⚠ 返回 0 表示失败");
            return null;
        }

        if (retValue == -1) {
            System.out.println("[initializeEnvironment] ❌ 返回 -1 表示失败");
            return null;
        }

        // 尝试作为对象引用解析
        try {
            DvmObject<?> object = vm.getObject(retValue);
            if (object == null) {
                System.out.println("[initializeEnvironment] 返回值不是对象引用，直接返回整数: " + retValue);
                return String.valueOf(retValue);
            }

            String result = (String) object.getValue();
            System.out.println("[initializeEnvironment] 结果: " + result);
            return result;
        } catch (Exception e) {
            System.out.println("[initializeEnvironment] 解析返回值出错: " + e.getMessage());
            return null;
        }
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Integer->intValue()I":
                return ((DvmInteger) dvmObject).getValue();
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/dispatch/JNICLibrary->getSecEnvValue()I": {
                System.out.println("[🔍 getSecEnvValue] 返回环境值检查结果");
                // ⚠️ 关键修复：C代码中检查 v149 == 1，如果为1则加密失败
                // 必须返回 0 或 -1 才能让加密继续执行
                System.out.println("[🔍 getSecEnvValue] ✅ 返回 0（绕过 v149 == 1 检查）");
                return 0;  // 修改为0，让加密流程继续
            }
            case "com/kuaishou/android/security/internal/dispatch/JNICLibrary->canRun(I)I": {
                int param = vaList.getIntArg(0);
                System.out.println("[🔍 canRun] 参数: " + param + ", 返回: 1 (允许运行)");
                return 1;  // 真机trace显示返回1
            }
        }
        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Long->longValue()J": {
                if (dvmObject instanceof DvmObject) {
                    Object value = dvmObject.getValue();
                    if (value instanceof Long) {
                        return (Long) value;
                    }
                }
                return 0L;
            }
        }
        return super.callLongMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        System.out.println("[getIntField] 请求字段: " + signature + " from " + dvmObject.getClass().getSimpleName());

        switch (signature) {
            case "java/lang/Integer->value:I": {
                // Integer对象的value字段
                if (dvmObject instanceof DvmInteger) {
                    int value = ((DvmInteger) dvmObject).getValue();
                    System.out.println("[getIntField] Integer.value = " + value);
                    return value;
                }
                System.out.println("[getIntField] ⚠️ 警告: 对象不是DvmInteger类型");
                return 0;
            }
        }

        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        System.out.println("[getLongField] 请求字段: " + signature + " from " + dvmObject.getClass().getSimpleName());

        // trace显示这里返回一个负的long值: -5476376602585044608
        // 这个值可能是某种状态标识或native对象指针
        // 0xB400007F5C479380 是可能的指针值
        switch (signature) {
            case "com/kuaishou/android/security/internal/dispatch/JNICLibrary->nativePtr:J": {
                System.out.println("[getLongField] 返回 nativePtr 字段");
                return -5476376602585044608L;  // 使用trace中的值
            }
        }

        return super.getLongField(vm, dvmObject, signature);
    }

    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Boolean->booleanValue()Z":
                return ((DvmBoolean) dvmObject).getValue();
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V": {
                int code = vaList.getIntArg(0);
                String message = vaList.getObjectArg(1).getValue().toString();

                // ⭐ 临时禁用签名错误拦截，查看完整错误信息以便诊断
                // 错误码说明：
                // - 0x111b7 (70071): APK签名验证失败 - ZIP读取/解析错误
                // - 0x111bc (70076): 证书链验证失败
                // - 0x11180 (70016): 包名/签名不在白名单
                if (false && (code == 0x111b7 || code == 0x111bc || code == 0x11180)) {
                    System.out.println("\n[🔧 签名绕过] 拦截签名验证错误报告");
                    System.out.println("[签名绕过]   错误码: 0x" + Integer.toHexString(code));
                    System.out.println("[签名绕过]   消息: " + message);
                    System.out.println("[签名绕过]   ⚠️ 注意：仅拦截报告，内部状态可能已损坏");
                    System.out.println("[签名绕过]   ✅ 已忽略，继续执行\n");
                    return;  // 阻止错误报告
                }

                System.out.println("\n[❌ nativeReport] 错误码: 0x" + Integer.toHexString(code) + " (" + code + ")");
                System.out.println("[❌ nativeReport] 消息: " + message);

                // 错误码解析
                switch (code) {
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
                    case 0x11180: // 70016
                        System.out.println("[❌ 分析] 70016 = 包名/签名不在白名单中");
                        System.out.println("[❌ 提示] 检查 Context.getPackageName() 返回值");
                        break;
                    case 0x11178: // 70008
                        System.out.println("[❌ 分析] 70008 = 初始化相关错误");
                        break;
                    case 0x11172: // 70002
                        System.out.println("[❌ 分析] 70002 = 环境检测失败");
                        break;
                    case 0x1117e: // 70014
                        System.out.println("[❌ 分析] 70014 = 加密前置条件未满足");
                        break;
                    case 0x111e5: // 70117
                        System.out.println("[❌ 分析] 70117 = 全局标志位检查失败");
                        break;
                }
                System.out.println();
                return;
            }
        }
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->getProcessName(Landroid/content/Context;)Ljava/lang/String;": {
                String processName = vm.getPackageName();
                System.out.println("[🔍 诊断] getProcessName() 返回: " + processName);
                return new StringObject(vm, processName);
            }
            case "java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;": {
                StringObject keyObj = vaList.getObjectArg(0);
                String key = keyObj.getValue();
                String value = System.getProperty(key);
                System.out.println("[System.getProperty] key: " + key + " => " + value);
                return value != null ? new StringObject(vm, value) : null;
            }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        // 添加通用日志来追踪所有方法调用
        if (signature.contains("getPackage") || signature.contains("Signature") || signature.contains("Context")) {
            System.out.println("[🔍 方法调用] " + signature + " on " + dvmObject.getClass().getSimpleName());
        }

        switch (signature) {
            // ===== 签名相关方法 =====
            case "android/content/pm/Signature->toByteArray()[B": {
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    byte[] data = sig.toByteArray();
                    System.out.println("[Signature.toByteArray] 返回签名数据，长度: " + data.length);

                    // 计算签名MD5用于对比
                    try {
                        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
                        byte[] hash = md.digest(data);
                        System.out.println("[Signature.toByteArray] MD5: " + bytesToHex(hash));
                    } catch (Exception e) {
                        System.out.println("[Signature.toByteArray] MD5计算失败");
                    }

                    return new ByteArray(vm, data);
                }
                System.out.println("[Signature.toByteArray] ⚠ 对象不是 Signature 类型: " + dvmObject.getClass());
                return null;
            }

            case "android/content/pm/Signature->toCharsString()Ljava/lang/String;": {
                String charsStr = ((Signature) dvmObject).toCharsString();
                System.out.println("[🔍 Signature.toCharsString] 返回: " + charsStr.substring(0, Math.min(50, charsStr.length())) + "...");
                return new StringObject(vm, charsStr);
            }

            // ===== Context 和 App 方法 =====
            case "com/yxcorp/gifshow/App->getPackageCodePath()Ljava/lang/String;": {
                // 使用真实包名构造路径
                String apkPath = "/data/app/~~En8y40Eyt_9SQIpY8tusUw==/com.kuaishou.nebula-94eN8Qsx7c5Ex2tlhTevMQ==/base.apk";
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

            case "com/yxcorp/gifshow/App->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                System.out.println("[🔍 getPackageName] 返回: " + packageName);
                return new StringObject(vm, packageName);
            }

            case "com/yxcorp/gifshow/App->getAssets()Landroid/content/res/AssetManager;": {
                return new AssetManager(vm, signature);
            }
            case "com/yxcorp/gifshow/App->getPackageManager()Landroid/content/pm/PackageManager;": {
                return vm.resolveClass("android/content/pm/PackageManager").newObject(signature);
            }
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;": {
                String packageName = (String) vaList.getObjectArg(0).getValue();
                int flags = vaList.getIntArg(1);
                System.out.println("[PackageManager] getPackageInfo(" + packageName + ", " + flags + ")");
                System.out.println("[PackageManager] flags解析: GET_SIGNATURES=" + ((flags & 0x40) != 0) +
                        ", GET_SIGNING_CERTIFICATES=" + ((flags & 0x8000000) != 0));

                // 创建PackageInfo，需要包含签名信息
                PackageInfo packageInfo = new PackageInfo(vm, packageName, 138401);

                // 如果请求签名信息（flags包含GET_SIGNATURES=0x40），需要设置signatures字段
                if ((flags & 0x40) != 0) {
                    System.out.println("[PackageManager] ⚠ 需要提供APK签名信息");
                    // TODO: 添加真实的APK签名
                }

                return packageInfo;
            }

            case "android/content/Context->getPackageCodePath()Ljava/lang/String;": {
                // 使用真实包名构造路径
                String packageName = vm.getPackageName();
                String path = "/data/app/~~En8y40Eyt_9SQIpY8tusUw==/com.kuaishou.nebula-94eN8Qsx7c5Ex2tlhTevMQ==/base.apk";
                System.out.println("[🔍 Context.getPackageCodePath] 返回: " + path);

                // ⚠️ 诊断：检查真实APK文件是否存在
                File realApk = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
                if (!realApk.exists()) {
                    System.out.println("[🔍 Context.getPackageCodePath] ❌ 警告：真实APK文件不存在!");
                }

                return new StringObject(vm, path);
            }

            case "android/content/Context->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                System.out.println("[🔍 Context.getPackageName] 返回: " + packageName);
                return new StringObject(vm, packageName);
            }
            case "android/content/Context->getAssets()Landroid/content/res/AssetManager;":
                return new AssetManager(vm, signature);

            // 添加签名相关的方法
            case "android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;": {
                System.out.println("[PackageInfo] 请求signatures字段");
                // 返回签名数组
                Signature[] signatures = createMockSignatures(vm);
                return new ArrayObject(signatures);
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    /**
     * 创建模拟的APK签名数组
     * 这是快手安全库验证APK完整性所必需的
     * <p>
     * 注意：这个方法已经不再使用，签名应该通过 VM.getSignatures() 获取
     * 参考 AbstractJni.java 第150-157行的实现
     */
    private Signature[] createMockSignatures(VM vm) {
        System.out.println("[签名验证] 从 VM 获取签名...");

        // 使用 VM 内置的签名机制
        CertificateMeta[] metas = vm.getSignatures();
        if (metas != null && metas.length > 0) {
            Signature[] signatures = new Signature[metas.length];
            for (int i = 0; i < metas.length; i++) {
                signatures[i] = new Signature(vm, metas[i]);
                // ⭐ 关键诊断：输出每个签名的详细信息
                byte[] certData = metas[i].getData();
                System.out.println("[签名验证]   证书 #" + (i + 1) + ":");
                System.out.println("[签名验证]     - 数据长度: " + certData.length + " 字节");
                System.out.println("[签名验证]     - 签名算法: " + metas[i].getSignAlgorithm());
                System.out.println("[签名验证]     - 开始日期: " + metas[i].getStartDate());
                System.out.println("[签名验证]     - 结束日期: " + metas[i].getEndDate());

                // 计算MD5用于对比
                try {
                    java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
                    byte[] hash = md.digest(certData);
                    System.out.println("[签名验证]     - MD5: " + bytesToHex(hash));
                } catch (Exception e) {
                    System.out.println("[签名验证]     - MD5: 计算失败");
                }
            }
            System.out.println("[签名验证] ✓ 成功获取 " + signatures.length + " 个签名");
            return signatures;
        }

        System.out.println("[签名验证] ⚠ VM 中没有签名数据，需要在创建 VM 时设置");
        return new Signature[0];
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        System.out.println("[getObjectField] 请求字段: " + signature + " from " + dvmObject.getClass().getSimpleName());

        switch (signature) {
            case "android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;": {
                System.out.println("[getObjectField] 返回签名数组");
                Signature[] signatures = createMockSignatures(vm);
                return new ArrayObject(signatures);
            }
        }

        return super.getObjectField(vm, dvmObject, signature);
    }


    /**
     * 修复GOT表 - 将GOT表项指向AndroidModule提供的真实函数实现
     * <p>
     * 问题分析：
     * - libkwsgmain.so 中有多个 AssetManager 函数的 GOT 表项未被正确重定位
     * - 当 PLT 代码从这些 GOT 表项加载地址时，会跳转到无效地址（如 0x9c00）
     * <p>
     * 解决方案：
     * - AndroidModule 已经通过虚拟模块提供了完整的 AssetManager 实现
     * - 我们从 libandroid.so 符号表获取这些函数的真实地址
     * - 将 GOT 表项重定向到这些真实地址
     */
    private void fixGotTable() {
        Backend backend = emulator.getBackend();
        System.out.println("\n[GOT修复] 开始修复 AssetManager GOT 表项...");

        // 查找 libandroid.so 模块
        com.github.unidbg.Module androidModule = emulator.getMemory().findModule("libandroid.so");
        if (androidModule == null) {
            System.out.println("[GOT修复] ❌ 找不到 libandroid.so，无法修复");
            return;
        }

        System.out.println("[GOT修复] ✓ 找到 libandroid.so at 0x" + Long.toHexString(androidModule.base));

        // 定义需要修复的GOT表项及其对应的函数名
        // 注意：有些函数 AndroidModule 没有实现，需要创建 stub
        String[][] gotMappings = {
                {"0x6eaf8", "AAssetManager_open"},
                {"0x6eb50", "AAssetManager_fromJava"},
                {"0x6eb80", "AAsset_close"},
                {"0x6ebe8", "AAssetDir_getNextFileName"},  // 需要 stub
                {"0x6ec40", "AAsset_read"},
                {"0x6ecf0", "AAssetManager_openDir"},      // 需要 stub
                {"0x6ee28", "AAsset_getLength"},
                {"0x6ee48", "AAssetDir_close"},            // 需要 stub
        };

        // 创建一个返回 NULL 的 stub 用于未实现的函数
        // 必须使用 mmap 并设置执行权限
        Memory memory = emulator.getMemory();
        long stubAddr = memory.mmap(0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC).peer;
        byte[] stubCode = {
                (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0xD2,  // MOV X0, #0
                (byte) 0xC0, (byte) 0x03, (byte) 0x5F, (byte) 0xD6   // RET
        };
        backend.mem_write(stubAddr, stubCode);
        System.out.println("[GOT修复] 创建可执行 stub at 0x" + Long.toHexString(stubAddr) + " (返回NULL)");

        int successCount = 0;
        for (String[] mapping : gotMappings) {
            long gotOffset = Long.parseLong(mapping[0].substring(2), 16);
            String funcName = mapping[1];

            long funcAddr;
            // 从 libandroid.so 查找函数地址
            com.github.unidbg.Symbol symbol = androidModule.findSymbolByName(funcName, false);
            if (symbol == null) {
                // 使用 stub 函数
                funcAddr = stubAddr;
                System.out.println("[GOT修复]   ⚠ " + funcName + " -> 0x" + Long.toHexString(funcAddr) + " (stub)");
            } else {
                funcAddr = symbol.getAddress();
                System.out.println("[GOT修复]   ✓ " + funcName + " -> 0x" + Long.toHexString(funcAddr));
            }

            // 准备地址的字节数组（小端序）
            byte[] addrBytes = new byte[8];
            for (int i = 0; i < 8; i++) {
                addrBytes[i] = (byte) ((funcAddr >> (i * 8)) & 0xFF);
            }

            // 写入GOT表
            long gotAddr = module.base + gotOffset;
            backend.mem_write(gotAddr, addrBytes);
            successCount++;
        }

        System.out.println("[GOT修复] ✓ 成功修复 " + successCount + "/" + gotMappings.length + " 个GOT表项\n");
    }

    /**
     * 设置指令跟踪 - 跟踪加密函数在读取数据后的执行流程
     * 目标：找出返回0之前的判断逻辑
     */
    private void setupInstructionTrace() {
        Backend backend = emulator.getBackend();

        // 关键地址点：
        // 0x42bc8: GetByteArrayRegion 之后（数据已读取）
        // 0x41de4: ReleaseStringUTFChars（函数即将返回）
        long traceStart = module.base + 0x42bc8;  // 数据读取完成
        long traceEnd = module.base + 0x43000;    // 覆盖到返回点

        System.out.println("\n[指令跟踪] 设置跟踪范围: 0x" + Long.toHexString(traceStart) +
                " - 0x" + Long.toHexString(traceEnd));
        System.out.println("[指令跟踪] 重点关注：X1寄存器为何始终为0");

        // 添加代码hook - 跟踪每条指令
        backend.hook_add_new(new CodeHook() {
            private int instructionCount = 0;
            private long lastAddress = 0;
            private final int MAX_INSTRUCTIONS = 200;  // 限制输出数量

            @Override
            public void onAttach(UnHook unHook) {
                // Hook attach 回调
            }

            @Override
            public void detach() {
                // Hook detach 回调
            }

            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                instructionCount++;

                // 只显示前N条指令，避免输出过多
                if (instructionCount > MAX_INSTRUCTIONS) {
                    return;
                }

                if (instructionCount == MAX_INSTRUCTIONS) {
                    System.out.println("[指令跟踪] 已达到最大跟踪数量，停止输出...");
                    return;
                }

                try {
                    // 读取指令字节
                    byte[] code = backend.mem_read(address, size);
                    String hexCode = toHexString(code);

                    // 读取关键寄存器
                    long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
                    long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();

                    // 格式化输出
                    String offset = String.format("0x%05x", address - module.base);
                    System.out.printf("[跟踪#%03d] %s: %s | X0=0x%x X1=0x%x LR=0x%x\n",
                            instructionCount, offset, hexCode, x0, x1, lr);

                    // 检测关键指令模式
                    detectKeyInstructions(address, code, backend);

                    lastAddress = address;

                } catch (Exception e) {
                    System.out.println("[指令跟踪] 错误: " + e.getMessage());
                }
            }

            /**
             * 检测关键指令模式
             */
            private void detectKeyInstructions(long address, byte[] code, Backend backend) {
                if (code.length < 4) return;

                // ARM64 指令是小端序
                int instruction = ((code[3] & 0xFF) << 24) |
                        ((code[2] & 0xFF) << 16) |
                        ((code[1] & 0xFF) << 8) |
                        (code[0] & 0xFF);

                // 检测 CMP 指令（比较操作）
                if ((instruction & 0x7F200000) == 0x6B000000) {
                    int rn = (instruction >> 5) & 0x1F;
                    int rm = (instruction >> 16) & 0x1F;
                    try {
                        long rnVal = backend.reg_read(Arm64Const.UC_ARM64_REG_X0 + rn).longValue();
                        long rmVal = backend.reg_read(Arm64Const.UC_ARM64_REG_X0 + rm).longValue();
                        System.out.println("[🔍 CMP] X" + rn + " vs X" + rm +
                                " (0x" + Long.toHexString(rnVal) + " vs 0x" + Long.toHexString(rmVal) + ")");
                        if (rnVal != rmVal) {
                            System.out.println("    [⚠️] 比较结果：不相等！这将触发后续的条件跳转");
                        }
                    } catch (Exception e) {
                    }
                }

                // 检测条件分支 (B.cond: 01010100_xxxxxxxx_xxxxxxxx_xxx0xxxx)
                if ((instruction & 0xFF000010) == 0x54000000) {
                    String cond = getConditionCode((instruction >> 0) & 0xF);
                    long target = address + ((instruction >> 5) & 0x7FFFF) * 4;
                    System.out.println("[⚠ 条件分支] B." + cond + " -> 0x" + Long.toHexString(target - module.base));

                    // 特别关注跳转到 0x43368 的情况
                    if ((target - module.base) == 0x43368) {
                        System.out.println("    [💥 致命跳转] 这是导致返回0的错误路径！");
                        System.out.println("    [分析] 在此之前的比较操作失败，需要检查之前的CMP指令");
                    }
                }

                // 检测 CBZ/CBNZ (比较并跳转)
                if ((instruction & 0x7F000000) == 0x34000000 ||
                        (instruction & 0x7F000000) == 0x35000000) {
                    boolean isNZ = ((instruction >> 24) & 1) == 1;
                    int reg = instruction & 0x1F;
                    long target = address + (((instruction >> 5) & 0x7FFFF) << 2);
                    System.out.println("[⚠ 条件跳转] CB" + (isNZ ? "NZ" : "Z") +
                            " X" + reg + " -> 0x" + Long.toHexString(target - module.base));

                    // 读取寄存器值
                    try {
                        long regValue = backend.reg_read(Arm64Const.UC_ARM64_REG_X0 + reg).longValue();
                        System.out.println("    [寄存器] X" + reg + " = 0x" + Long.toHexString(regValue) +
                                " (" + regValue + ")");
                    } catch (Exception e) {
                    }
                }

                // 检测无条件跳转 B (000101xx_xxxxxxxx_xxxxxxxx_xxxxxxxx)
                if ((instruction & 0xFC000000) == 0x14000000) {
                    long offset = ((instruction & 0x03FFFFFF) << 2);
                    if ((offset & 0x08000000) != 0) {  // 符号扩展
                        offset |= 0xFFFFFFF0_00000000L;
                    }
                    long target = address + offset;
                    System.out.println("[→ 无条件跳转] B -> 0x" + Long.toHexString(target - module.base));
                }

                // 检测 RET 返回指令
                if (instruction == 0xD65F03C0) {
                    long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
                    System.out.println("[← 返回] RET (返回到 0x" + Long.toHexString(lr) + ")");
                }
            }

            /**
             * 获取条件码名称
             */
            private String getConditionCode(int cond) {
                String[] codes = {"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
                        "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};
                return cond < codes.length ? codes[cond] : "??";
            }

        }, traceStart, traceEnd, null);

        System.out.println("[指令跟踪] ✓ 跟踪已设置\n");
    }

    /**
     * 字节数组转十六进制字符串（用于指令显示）
     */
    private static String toHexString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * 设置详细的JNI调用跟踪
     * 目标：追踪所有从native回调到Java的方法调用，特别关注返回值
     */
    private void setupDetailedJNITrace() {
        System.out.println("\n[JNI跟踪] 开始设置详细的JNI调用跟踪...");
        System.out.println("[JNI跟踪] 目标：找出为何加密返回0\n");

        // 标记：我们需要监控所有JNI回调的返回值
        // 特别是那些可能影响加密成功/失败的方法
    }


}