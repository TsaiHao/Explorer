function log(msg) {
    console.log(`[MediaCodec-ReleaseOutputBuffer] ${msg}`);
}

function hookMain() {
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

    const renderAndReleaseBooleanApi = sfModule.findExportByName('_ZN7android10MediaCodec28renderOutputBufferAndReleaseEj');
    if (!renderAndReleaseBooleanApi) {
        console.error('Immediate render api not found in stagefright');
        return;
    }

    const renderAndReleaseTsApi = sfModule.findExportByName('_ZN7android10MediaCodec28renderOutputBufferAndReleaseEjx');
    if (!renderAndReleaseTsApi) {
        console.error('Render api with timestmap not found in stagefright');
        return;
    }

    const dropBufferApi = sfModule.findExportByName('_ZN7android10MediaCodec19releaseOutputBufferEj');
    if (!dropBufferApi) {
        console.error('Drop buffer api not found in stagefright');
    }

    Interceptor.attach(renderAndReleaseBooleanApi, {
        onEnter: function(args) {
            log('Boolean render api called, index=' + args[1]);
        }
    });

    Interceptor.attach(renderAndReleaseTsApi, {
        onEnter: function(args) {
            const index = args[1];
            const ts_low_32 = args[2].toUInt32();
            const ts_high_32 = args[3].toUInt32();
            const ts = (BigInt(ts_high_32) << 32n) | BigInt(ts_low_32);

            log(`Rendering buffer at ${index} in ${ts}ns`);
        }
    });

    Interceptor.attach(dropBufferApi, {
        onEnter: function(args) {
            log(`Dropping buffer at ${args[1]}`);
        }
    });
}

try {
    hookMain();
    console.log('MediaCodec-ReleaseOutputBuffer related apis hooked');
} catch (e) {
    console.error('Hook failed ' + JSON.stringify(e));
}