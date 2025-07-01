function hook() {
    const module = Process.findModuleByName('libc.so');
    const printf = module.getExportByName('printf');
    console.log(`Found printf address: ${printf}`);
    console.log("Start attaching");

    Interceptor.attach(printf, {
        onEnter: function (args) {
            const s = args[0].readCString();
            console.log(`printf called, format string: ${s}`);
        }
    });

    console.log("printf hooked");
}

try {
    hook();
} catch (e) {
    console.log(`Error while hooking ${e}`)
}
