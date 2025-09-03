function hook() {
    const libName = 'libmedia_jni.so';
    const setScalingModeApi = '_ZN7android11JMediaCodec19setVideoScalingModeEi';

    const module = Process.findModuleByName(libName);
    if (!module) {
        console.error(`Module ${libName} not found.`);
        return;
    }

    const setScalingMode = module.findExportByName(setScalingModeApi);
    if (!setScalingMode) {
        console.error(`Symbol ${setScalingModeApi} not found in ${libName}.`);
        return;
    }

    Interceptor.attach(setScalingMode, {
        onEnter(args) {
            const backtrace = Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
            const mode = args[1].toInt32();
            console.log(`[JMediaCodec::setVideoScalingMode] mode=${mode}`);
            console.log(backtrace);
        },
        onLeave(retVal) {
        }
    });

    console.log("JMediaCodec hook initialized");
}

try {
    hook();
} catch (error) {
    console.error(`Error initializing JMediaCodec hook: ${error}`);
}