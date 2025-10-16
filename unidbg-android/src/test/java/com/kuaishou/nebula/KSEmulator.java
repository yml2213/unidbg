package com.kuaishou.nebula;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import unicorn.UnicornConst;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.AssetManager;
import com.github.unidbg.linux.android.dvm.api.PackageInfo;
import com.github.unidbg.linux.android.dvm.api.Signature;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class KSEmulator extends AbstractJni implements IOResolver {
    private final AndroidEmulator emulator;
    private final Module module;
    private final VM vm;
    private final DvmObject<?> context;  // 共享的Context对象
    private static final String ENC_DATA_REQUEST_HEX;
    private static final String ENC_DATA_EXPECTED_HEX;

    static {
        ENC_DATA_REQUEST_HEX = "7B22617070496E666F223A7B226170704964223A226B75616973686F755F6E6562756C61222C226E616D65223A22E5BFABE6898BE69E81E9809FE78988222C227061636B6167654E616D65223A22636F6D2E6B75616973686F752E6E6562756C61222C2276657273696F6E223A2231322E372E32302E38353032222C2276657273696F6E436F6465223A2D317D2C22646576696365496E666F223A7B226F616964223A2263343134383137373530613830623265222C226F7354797065223A312C226F7356657273696F6E223A223131222C226C616E6775616765223A227A68222C226465766963654964223A22414E44524F49445F31393164373437323435353931363964222C2273637265656E53697A65223A7B227769647468223A313038302C22686569676874223A323230367D2C22667474223A22227D2C226E6574776F726B496E666F223A7B226970223A2231302E302E302E313332222C22636F6E6E656374696F6E54797065223A3130307D2C2267656F496E666F223A7B226C61746974756465223A33362E3837373031352C226C6F6E676974756465223A3131372E3832313733367D2C2275736572496E666F223A7B22757365724964223A2234343335383835353631222C22616765223A302C2267656E646572223A22227D2C22696D70496E666F223A5B7B22706167654964223A31313130312C22737562506167654964223A3130303032363336372C22616374696F6E223A302C227769647468223A302C22686569676874223A302C2262726F77736554797065223A332C22726571756573745363656E6554797065223A312C226C61737452656365697665416D6F756E74223A302C22696D7045787444617461223A227B5C226F70656E48354164436F756E745C223A302C5C226E656F506172616D735C223A5C2265794A775957646C535751694F6A45784D5441784C434A7A64574A515957646C535751694F6A45774D4441794E6A4D324E7977696347397A535751694F6A4173496D4A3163326C755A584E7A535751694F6A59334D6977695A586830554746795957317A496A6F695A6D49335A6A49785A5751774E3249784F474E6C4E6A646A593249345A5452685A5745324D7A4532595449774E44526B597A51794E6A453359574E6D59544D334E6A4269597A5A6C4D546B314E6D5A684D3251795A574D334D7A4577597A4D324E6A41334D4759784D6A4D344D445669593249315A6A497A4E44566A4E6A4979596D4D784E6A4D794E7A4A6A4E7A45304E7A4E6D4E324E6B4D7A49774D4459334E47526C596D4D355A47457A4D6A67355A6A51314F474930596A63314E4467795A6D5A6B4D325A6D595468694D6D51304D7A51354E474D784E6A59334E544E6B4D5459794D6A56694E7A41344F574D335A54417A4D5464684E7A5933597A5935496977695933567A64473974524746305953493665794A6C65476C305357356D6279493665794A306232467A6445526C63324D694F6D353162477773496E527659584E305357316E56584A73496A70756457787366583073496E426C626D5268626E52556558426C496A6F784C434A6B61584E776247463556486C775A5349364D69776963326C755A32786C5547466E5A556C6B496A6F774C434A7A6157356E6247565464574A515957646C535751694F6A4173496D4E6F595735755A5777694F6A4173496D4E76645735305A473933626C4A6C63473979644349365A6D467363325573496E526F5A57316C56486C775A5349364D43776962576C345A5752425A4349365A6D467363325573496D5A316247784E6158686C5A43493664484A315A5377695958563062314A6C634739796443493664484A315A5377695A6E4A7662565268633274445A5735305A5849694F6D5A6862484E6C4C434A7A5A5746795932684A626E4E7761584A6C55324E6F5A57316C5357356D62794936626E5673624377695957317664573530496A6F7766515C227D222C226D6564696145787444617461223A227B7D222C2273657373696F6E223A227B5C2269645C223A5C2261356334373935632D383334322D346162332D616663322D6633343935616261306564625C227D227D5D2C227265636F5265706F7274436F6E74657874223A227B5C226164436C69656E74496E666F5C223A7B5C2273686F756C6453686F77416450726F66696C6553656374696F6E42616E6E65725C223A6E756C6C2C5C2270726F66696C65417574686F7249645C223A302C5C227869616F6D69437573746F6D4D61726B6574496E666F5C223A7B5C22737570706F72745C223A747275652C5C2264657461696C5374796C655C223A5C22312C322C332C352C3130302C3130312C3130325C227D7D7D227D";
        ENC_DATA_EXPECTED_HEX = "5A54EECDE4D4EA6193F79DB96E3254547B61710201457963823030FAD0F3D666E6EE798BF47349634A4A77BB399B1F3E5CC4518BB302137052CB534DC48E9BCB0850B9E265E1857C40336C08E36E308EE6E7D5D7EEBC9CAD7CF964F6CE6CC0452E9DB776A205F3A0E8E7701B177BB80DDD95B24FB50739215088EE729036819EA0F37EDFE56CF5F5EDC0EC3212343F3E028798401937DC8B5F6A1508B6DB742963DC52DC1B6A0B9557ADC242E50957A312A4194553AF8388FC0E44B99247CD5991EC581C8793AF62B55149C30A248AE9E6A5853F530C53930D78EBF2BA0542CB1DD6885AE9F9EA2C3DCE107647867981C19899EC3305087E33F79EF4D27E25F7C6BD7B47C0B278A9EDE84789108D56CED0484320859C990CCDA5DEC2933B36967BDA8E1B298181E2557F4608EDC4C2DE2F62CF5C3BB75AAE1E97BF37CBE73923F42351776705C759B6D7DA78B5CE0A8080BEA0500C0DA3636E833BF22A3466A09862F900659CE215F461A90C15A9AE56C499EAF64550EFE0B1025470E9EFACD7D17A05DDABD7390B60DAB6C7542577670453FBD8E1449970B68F95805332DF28001B69923CE563866519EC4075177D8442A4F4E701E243075EE1CA2A2203284E36233048CFF128450DECD6A28BC0C843B9813EEBDBA3D74080977A0BA774BD695A6418823A7871F5F088FF6457AF70CFFCEFBE0039E87EAE9C7D3CDD61AED98E3B75DAA4014325CDA31EC442DC933DFB2750EEC9CD07B3DBC40413CC0047BE09D6B334D5E3533D36F703118C4932276DA65381340CCDD7B58E149522B0C6A1C33EE6B849137029EB256186C112C17243E6280B73F14382E277497ABCDE5CA2554BFEB5405D7354D06760DA1DDB69B94C94C69C00D70EE80691CE9DE06735415318A4ADF6CF6F35E9897183CF66070B6436EC062190528A670C32E433367BFA1D7158836F5C43159B05331F5AEB5160678811FBF3780B3B4BEBE133C67F87532967A342D3E22D591C8B168CB7326CB7ED66EC3D011EF559357E523FE2ED6A81DA735999C630A3E91EBDCE19A6A401A830FE313CB2B4A2F0510C3154762749ED0BEF2B4A4934A830C7B226920839497540FD6DF422CBA0042E0BFB4C110BD7FFF09B80E1AB1F54F88C1AED093D0E999F0254CC5D4BCDF63684AD9E98DFB1A0E0B121F5710C6596C5AA116BCE5A67A456AC6C66B822BC034F7C86903E653473D5392A79AA1FDE02DF28F83CF0C3FFCD23B84884077934D3EB19B7658475FC21A1C9EA69680D56A7A9599DCC0C604AEBF28B48A481D2DD4BAD2057720BE87BC854368DA60B2E183A42FD67E087DF83BC45EFE5D55FDFB1CDD541B9B9493E245FFBF53A64B1F64384099224C8699D2CA2BCD039F81A33BDEDF714E9F74D26B129669CE99123A62CC721F031BA58715941525C9634416816BFD6E704998058004C6ABB8BB3877FF4C8DE23D70C041F320B5DCEA81E4C78121B37DC05A67B2C88143F4D41CEF45C84EBDDAFF42154A5CFD6C39AF27806038892C5FF27013CCF440F0E0DD6242B6503452986BC768B5A90998424AC206945131F80FC3A1764B76832EE1D0039D981220F5AE03F389CE1A8C7E94E61601CD0C78A0AF49227F96B3FA384CAFD49A56282E27713A475A6BA5B3C4D469E9E7E8E147D01149D7ADF6FFEA766161EA5EC42CFE7B2218F42F0595C8E2B6D7D22304E5E25758A144DA1C4C854B6F82F3AE05123605819BB4B6CE8ACB44EC150C10A0A7AA57A3232B69E0C8B0AB47136C830C9CCF89FACADFA696E18DDEB9CB8BC29A77907BBCE479ECFCACF5509D0AF33CA9E592D64B6AF945540C9E55CA6CAD5766AF211B1BCCA62F9EEB5827ADB1C2031A0631C90848D550417CC49187576BC23288A93298D446C39B5FC0BDC6284B584B367237BD140F176AB3A2ADD69953B6BD73CF065575DA4BB85F0B9469BD920C549C5FD3901F87654002BC96607DFAE345BD3A4BC4193F9AD294D899E92191C2C8B0A9407133CF82FE990159529ECD64BC6971363129B7BF1EB8DD969F506D9ABA9B88798C8A254ED716BE60D497BC7BFABAC47E318D80C59468DE63AAAD2950DFA276553BBDBB08C4984C8AD88D05406C74A5A621B88A57543D7D479B5C98C2BD121E509412E2A5956B7C890C1EB23B5B1FFE56425B3204F3C4DA65850DC1FE785DE6FB77E8B70C7452F4DDB059A606E66F908D70DF4AAB5E8178891E39952021DDC2F577D36E97994022CD32E148FD339A3FE1660294E16E647DB5B61D6E2FDF01724574C8255C20520ADABEE1E278004A404BF0EBD1780878DD5679EC95D2705CA4062243DAFFE435A0ECD5A544E490F165284EEB5EDCA37579CF1DE51A59610904531490322C0B374FB34CD8EE53657A99731EAA4116BB23D9BCBC58F1046136FAAB26CCD0D5D37E619E15E1231B0F24E040F50F0562D8FBA6AF9B794B3FB7B123EC7C320493E77C77ADE4B70881966191EA6B03DCC97F75DC817FD36CD14444B23EE87";
    }
    public KSEmulator() {
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.kuaishou.nebula")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        
        vm = emulator.createDalvikVM(new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk"));
        vm.setJni(this);
        vm.setVerbose(false);  // 先关闭verbose，减少干扰
        
        // 添加IOResolver - 必须在加载库之前
        emulator.getSyscallHandler().addIOResolver(this);
        
        // 注册AndroidModule - 必须在加载库之前
        new AndroidModule(emulator, vm).register(memory);
        
        // 创建共享的Context对象
        context = vm.resolveClass("com/yxcorp/gifshow/App").newObject(null);
        vm.addGlobalObject(context);  // 添加为全局对象，防止被回收
        
        System.out.println("[初始化] 开始加载 SO 库...");
        DalvikModule dm = vm.loadLibrary("kwsgmain", true);
        module = dm.getModule();
        System.out.println("[初始化] SO base: 0x" + Long.toHexString(module.base));
        System.out.println("[初始化] SO size: 0x" + Long.toHexString(module.size));
        
        System.out.println("[初始化] 调用 JNI_OnLoad...");
        dm.callJNI_OnLoad(emulator);
        
        // 修复GOT表 - 解决AssetManager函数的GOT重定位问题
        System.out.println("[初始化] 修复 GOT 表...");
        fixGotTable();
        
        System.out.println("[初始化] ✓ 初始化完成\n");
    }

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
        String result = (String)object.getValue();
        System.out.println("result:"+ result);
    }

    public static void main(String[] args) {
        KSEmulator emulator = new KSEmulator();
        System.out.println("\n========== 第1步：初始化环境 ==========");
        emulator.call_doCommandNative_init();
        System.out.println("\n========== 第2步：加密数据 ==========");
        emulator.encryptEncData();
        System.out.println("\n========== 执行完成 ==========\n");
    }
    public String encryptEncData() {
        System.out.println("\n[encryptEncData] 开始执行 encData 调用...");
        System.out.println("[encryptEncData] opcode: 10400");
        System.out.println("[encryptEncData] 使用共享Context: " + context);
        
        // 启用详细日志
        vm.setVerbose(true);
        
        List<Object> list = new ArrayList<>(4);
        list.add(vm.getJNIEnv());
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz));
        list.add(10400);  // opcode参数

        System.out.println("[encryptEncData] 请求Hex长度: " + ENC_DATA_REQUEST_HEX.length());
        byte[] requestBytes = hexToBytes(ENC_DATA_REQUEST_HEX);
        System.out.println("[encryptEncData] 请求字节长度: " + requestBytes.length);
        ByteArray requestArray = new ByteArray(vm, requestBytes);
        vm.addLocalObject(requestArray);

        StringObject appKey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appKey);
        
        DvmInteger zero = DvmInteger.valueOf(vm, 0);
        vm.addLocalObject(zero);
        
        // 使用共享的Context对象，而不是创建新的
        vm.addLocalObject(context);
        
        DvmBoolean boolTrueFirst = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolTrueFirst);
        
        DvmBoolean boolTrueSecond = DvmBoolean.valueOf(vm, true);
        vm.addLocalObject(boolTrueSecond);
        
        StringObject deviceKey = new StringObject(vm, "95147564-9763-4413-a937-6f0e3c12caf1");
        vm.addLocalObject(deviceKey);

        // 参数数组：[ByteArray, String, Integer, null, Context, Boolean, Boolean, String]
        ArrayObject paramsArray = new ArrayObject(
                requestArray,   // [0] 请求数据
                appKey,         // [1] app key
                zero,           // [2] Integer 0
                null,           // [3] null
                context,        // [4] Context
                boolTrueFirst,  // [5] Boolean true
                boolTrueSecond, // [6] Boolean true
                deviceKey       // [7] device key
        );
        System.out.println("[encryptEncData] 参数数组长度: " + 8);
        list.add(vm.addLocalObject(paramsArray));

        System.out.println("[encryptEncData] 即将调用 doCommandNative (0x40cd4)...");
        Number result = module.callFunction(emulator, 0x40cd4, list.toArray());
        
        // 关闭详细日志
        vm.setVerbose(false);
        
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





    private void call_doCommandNative_init() {
        System.out.println("[initializeEnvironment] 使用共享Context: " + context);
        List<Object> list = new ArrayList<>(4);
        list.add(vm.getJNIEnv()); // 第⼀个参数是env
        DvmObject<?> thiz = vm.resolveClass("com/kuaishou/android/security/internal/dispatch/JNICLibrary").newObject(null);
        list.add(vm.addLocalObject(thiz)); // 第⼆个参数，实例⽅法是jobject，静态⽅法是jclass，直接填0，⼀般⽤不到。
        // 使用共享的Context对象
        vm.addLocalObject(context);
        list.add(10412); // opcode参数
        StringObject appkey = new StringObject(vm, "d7b7d042-d4f2-4012-be60-d97ff2429c17");
        vm.addLocalObject(appkey);
        DvmInteger intergetobj = DvmInteger.valueOf(vm, 0);
        vm.addLocalObject(intergetobj);
        list.add(vm.addLocalObject(new ArrayObject(null, appkey, null, null, context, null, null)));
        Number numbers = module.callFunction(emulator, 0x40cd4, list.toArray());
        
        // 添加返回值检查
        if (numbers == null || numbers.intValue() == 0 || numbers.intValue() == -1) {
            System.out.println("[initializeEnvironment] 调用失败，返回值: " + numbers);
            return;
        }
        
        DvmObject<?> object = vm.getObject(numbers.intValue());
        if (object == null) {
            System.out.println("[initializeEnvironment] 无法获取返回对象");
            return;
        }
        
        String result = (String) object.getValue();
        System.out.println("[initializeEnvironment] 结果: " + result);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Integer->intValue()I":
                return ((DvmInteger)dvmObject).getValue();
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Boolean->booleanValue()Z":
                return ((DvmBoolean)dvmObject).getValue();
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->nativeReport(ILjava/lang/String;)V": {
                int code = vaList.getIntArg(0);
                String message = vaList.getObjectArg(1).getValue().toString();
                System.out.println("[nativeReport] 错误码: 0x" + Integer.toHexString(code) + " (" + code + "), 消息: " + message);
                return;
            }
        }
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }


    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kuaishou/android/security/internal/common/ExceptionProxy->getProcessName(Landroid/content/Context;)Ljava/lang/String;":
                return new StringObject(vm, "com.kuaishou.nebula");
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
        switch (signature) {
            case "com/yxcorp/gifshow/App->getPackageCodePath()Ljava/lang/String;": {
//                return new StringObject(vm, "/data/app/com.kuaishou.nebula-VZhzinzcefoqqzJZ47EE0A==/base.apk");
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");

            }
            case "com/yxcorp/gifshow/App->getPackageName()Ljava/lang/String;": {
//                return new StringObject(vm, "com.kuaishou.nebula");
                String packageName = vm.getPackageName();
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
                return new PackageInfo(vm, packageName, 138401);
            }

            case "android/content/Context->getPackageCodePath()Ljava/lang/String;": {
                return new StringObject(vm, "/data/app/~~tNMZVmV0fBgOq2lCiMwGRA==/com.kuaishou.nebula-JZD_aIoXsKoTPab3p20hBw==/base.apk");
            }
            case "android/content/Context->getAssets()Landroid/content/res/AssetManager;":
                return new AssetManager(vm, signature);

        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    /**
     * IOResolver接口实现 - 处理文件系统访问
     * 这是ksjsb.java有但KSEmulator缺少的关键实现
     */
    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        if (pathname == null) {
            System.out.println("[IOResolver] pathname is NULL");
            return null;
        }
        
        // 检测并忽略无效路径（内存地址被误当作字符串）
        if (pathname.length() < 10 && pathname.contains("\ufffd")) {
            // \ufffd 是 Unicode 替换字符，表示无效的字节序列
            System.out.println("[IOResolver] 忽略无效路径（内存地址）: " + pathname);
            return null;
        }
        
        System.out.println("[IOResolver] 请求打开文件: " + pathname);
        
        // 处理APK路径
        if (pathname.contains("/base.apk")) {
            File apkFile = new File("unidbg-android/apks/ksjsb/ksjsb_13.8.40.10657.apk");
            if (apkFile.exists()) {
                System.out.println("[IOResolver] ✓ 返回APK文件");
                return FileResult.success(new com.github.unidbg.linux.file.SimpleFileIO(oflags, apkFile, pathname));
            }
        }
        
        // 处理其他系统文件
        switch (pathname) {
            case "/proc/self/cmdline":
                return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                        "com.kuaishou.nebula".getBytes(StandardCharsets.UTF_8)));
            case "/dev/__properties__":
                return FileResult.success(new ByteArrayFileIO(oflags, pathname,
                        "".getBytes(StandardCharsets.UTF_8)));
            default:
                return null;
        }
    }


    /**
     * 修复GOT表 - 解决所有AssetManager相关函数的GOT重定位问题
     *
     * 问题分析：
     * - libkwsgmain.so 中有多个 AssetManager 函数的 GOT 表项未被正确重定位
     * - 当 PLT 代码从这些 GOT 表项加载地址时，会跳转到无效地址（如 0x9c00）
     * - 这些符号在模块中被标记为 "missing before init"
     *
     * 解决方案（两种stub函数）：
     * 1. AAssetManager_fromJava - 返回假的AAssetManager指针（非NULL）
     * 2. 其他AssetManager函数 - 返回NULL表示功能不可用
     */
    private void fixGotTable() {
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        
        // 1. 分配假的AssetManager结构体
        long fakeAssetManager = memory.malloc(0x100, false).getPointer().peer;
        System.out.println("[GOT修复] 分配假AssetManager: 0x" + Long.toHexString(fakeAssetManager));
        
        // 2. 创建并分配可执行内存用于stub函数
        long stubFromJava = memory.mmap(0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC).peer;
        long stubNull = stubFromJava + 0x100;
        System.out.println("[GOT修复] 分配fromJava stub: 0x" + Long.toHexString(stubFromJava));
        System.out.println("[GOT修复] 分配NULL stub: 0x" + Long.toHexString(stubNull));
        
        // 3. 写入 AAssetManager_fromJava stub代码（返回假指针）
        byte[] fromJavaCode = new byte[20];
        fromJavaCode[0] = (byte) ((fakeAssetManager >> 0) & 0xFF);
        fromJavaCode[1] = (byte) ((fakeAssetManager >> 8) & 0xFF);
        fromJavaCode[2] = (byte) 0x80;
        fromJavaCode[3] = (byte) 0xD2;
        fromJavaCode[4] = (byte) ((fakeAssetManager >> 16) & 0xFF);
        fromJavaCode[5] = (byte) ((fakeAssetManager >> 24) & 0xFF);
        fromJavaCode[6] = (byte) 0xA0;
        fromJavaCode[7] = (byte) 0xF2;
        fromJavaCode[8] = (byte) ((fakeAssetManager >> 32) & 0xFF);
        fromJavaCode[9] = (byte) ((fakeAssetManager >> 40) & 0xFF);
        fromJavaCode[10] = (byte) 0xC0;
        fromJavaCode[11] = (byte) 0xF2;
        fromJavaCode[12] = (byte) ((fakeAssetManager >> 48) & 0xFF);
        fromJavaCode[13] = (byte) ((fakeAssetManager >> 56) & 0xFF);
        fromJavaCode[14] = (byte) 0xE0;
        fromJavaCode[15] = (byte) 0xF2;
        fromJavaCode[16] = (byte) 0xC0;
        fromJavaCode[17] = (byte) 0x03;
        fromJavaCode[18] = (byte) 0x5F;
        fromJavaCode[19] = (byte) 0xD6;
        backend.mem_write(stubFromJava, fromJavaCode);
        
        // 4. 写入返回NULL的stub代码
        byte[] nullStubCode = {
                (byte) 0x00, (byte) 0x00, (byte) 0x80, (byte) 0xD2,
                (byte) 0xC0, (byte) 0x03, (byte) 0x5F, (byte) 0xD6
        };
        backend.mem_write(stubNull, nullStubCode);
        
        // 5. 修复所有AssetManager相关的GOT表项
        System.out.println("[GOT修复] 开始修复AssetManager GOT表项...\n");
        
        byte[] fromJavaAddr = new byte[8];
        for (int i = 0; i < 8; i++) {
            fromJavaAddr[i] = (byte) ((stubFromJava >> (i * 8)) & 0xFF);
        }
        long gotFromJava = module.base + 0x6eb50;
        backend.mem_write(gotFromJava, fromJavaAddr);
        System.out.println("[GOT修复] ✓ AAssetManager_fromJava[0x6eb50] -> 0x" + Long.toHexString(stubFromJava));
        
        byte[] nullAddr = new byte[8];
        for (int i = 0; i < 8; i++) {
            nullAddr[i] = (byte) ((stubNull >> (i * 8)) & 0xFF);
        }
        
        long[] otherGotOffsets = {
            0x6eaf8, 0x6eb80, 0x6ebe8, 0x6ec40, 0x6ecf0, 0x6ee28, 0x6ee48
        };
        
        for (long offset : otherGotOffsets) {
            backend.mem_write(module.base + offset, nullAddr);
            System.out.println("[GOT修复] ✓ GOT[0x" + Long.toHexString(offset) + "] -> NULL stub");
        }
        
        System.out.println("\n[GOT修复] ✓ 完成修复！\n");
    }

}