function hookConfigure() {
    const sfLibName = 'libstagefright.so';
    const sfFtLibName = 'libstagefright_foundation.so';

    const sfModule = Process.findModuleByName(sfLibName);
    if (!sfModule) {
        console.error(`Module ${sfLibName} not found.`);
        return;
    }

    const sfFtModule = Process.findModuleByName(sfFtLibName);
    if (!sfFtModule) {
        console.error(`Module ${sfFtLibName} not found.`);
        return;
    }

    const configure = sfModule.findExportByName('_ZN7android10MediaCodec9configureERKNS_2spINS_8AMessageEEERKNS1_INS_7SurfaceEEERKNS1_INS_7ICryptoEEERKNS1_INS_8hardware3cas6native4V1_012IDescramblerEEEj');
    if (!configure) {
        console.error(`Symbol not found in ${sfLibName}.`);
        return;
    }

    const debugStringMethod = sfFtModule.findExportByName('_ZNK7android8AMessage11debugStringEi');
    if (!debugStringMethod) {
        console.error(`Symbol not found in ${sfFtLibName}.`);
        return;
    }
    const debugString = new NativeFunction(debugStringMethod, 'pointer', ['pointer', 'int']);

    const cstrMethod = sfFtModule.findExportByName('_ZNK7android7AString5c_strEv');
    if (!cstrMethod) {
        console.error(`Symbol not found in ${sfFtLibName}.`);
        return;
    }
    const cstr = new NativeFunction(cstrMethod, 'pointer', ['pointer']);

    Interceptor.attach(configure, {
        onEnter(args) {
            const format = args[1];
            console.log("Got format: " + format);
            const msg = debugString(format, 2);

            const buffer = msg;
            const size = msg.add(Process.pointerSize).readU32();
            const str = buffer.readUtf8String(size);
            console.log(`MediaCodec::configure called with format: ${format}, msg: ${str}`);
        }
    });

    console.log("MediaCodec::configure hook initialized");
}

try {
    hookConfigure();
} catch (error) {
    console.error(`Error occurred while hooking MediaCodec::configure: ${error}`);
}