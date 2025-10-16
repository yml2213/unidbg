#!/bin/bash
# 快手加密测试脚本 - 避免 SLF4J 冲突

cd /Users/yml/IdeaProjects/unidbg_1/unidbg-android

# 排除冲突的 SLF4J 绑定
CLASSPATH="target/test-classes:target/classes"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/com/github/zhkl0228/unicorn/1.0.14/unicorn-1.0.14.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/com/github/zhkl0228/capstone/3.1.8/capstone-3.1.8.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/net/java/dev/jna/jna/5.10.0/jna-5.10.0.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/com/github/zhkl0228/keystone/0.9.7/keystone-0.9.7.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/commons-codec/commons-codec/1.15/commons-codec-1.15.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/commons-io/commons-io/2.14.0/commons-io-2.14.0.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/net/dongliu/apk-parser/2.6.10/apk-parser-2.6.10.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/org/scijava/native-lib-loader/2.3.5/native-lib-loader-2.3.5.jar"
# 只使用 reload4j 的 SLF4J 绑定
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/org/slf4j/slf4j-reload4j/2.0.16/slf4j-reload4j-2.0.16.jar"
CLASSPATH="$CLASSPATH:$HOME/.m2/repository/ch/qos/reload4j/reload4j/1.2.22/reload4j-1.2.22.jar"

# 添加 backend 模块
for backend in dynarmic hypervisor kvm unicorn2; do
    if [ -d "../backend/$backend/target/classes" ]; then
        CLASSPATH="$CLASSPATH:../backend/$backend/target/classes"
    fi
done

echo "================================"
echo "快手安全库加密测试"
echo "================================"
echo ""

/Users/yml/Library/Java/JavaVirtualMachines/openjdk-24.0.1/Contents/Home/bin/java \
    --enable-native-access=ALL-UNNAMED \
    -cp "$CLASSPATH" \
    com.kuaishou.nebula.KSEmulator

echo ""
echo "================================"
echo "测试完成"
echo "================================"