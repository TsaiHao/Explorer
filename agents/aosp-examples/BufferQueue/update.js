function hook() {
    const module = Process.findModuleByName('libgui.so');
    if (!module) {
        console.error('Module libgui.so not found.');
        return;
    }

    const update = module.findExportByName('_ZN7android16BLASTBufferQueue6updateERKNS_2spINS_14SurfaceControlEEEjji');
    if (!update) {
        console.error('Export BLASTBufferQueue::update not found.');
        return;
    }

    Interceptor.attach(update, {
        onEnter(args) {
            const width = args[2].toUInt32();
            const height = args[3].toUInt32();
            const format = args[4].toInt32();

            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
            console.log(`BLASTBufferQueue::update called with:\n  Width: ${width}\n  Height: ${height}\n  Format: ${format}`);
            console.log('Backtrace:\n' + backtrace);
        }
    });
}

try {
    hook();
    console.log('BLASTBufferQueue::update hook initialized');
} catch (error) {
    console.error('Error initializing BLASTBufferQueue::update hook:', error);
}