//import Java from 'frida-java-bridge';

function hook() {
    const libName = 'libaudioclient.so';
    const getTimestampApi = '_ZN7android10AudioTrack12getTimestampERNS_14AudioTimestampE';

    const module = Process.findModuleByName(libName);
    if (!module) {
        console.error(`Module ${libName} not found.`);
        return;
    }

    const getTimestamp = module.findExportByName(getTimestampApi);
    if (!getTimestamp) {
        console.error(`Symbol ${getTimestampApi} not found in ${libName}.`);
        return;
    }

    Interceptor.attach(getTimestamp, {
        onEnter(args) {
            this.timestamp = args[1];
        },
        onLeave(retVal) {
            const position = this.timestamp.readU32();
            const timespec_sec = this.timestamp.add(4).readS32();
            const timespec_nsec = this.timestamp.add(8).readS32();

            console.log(`[AudioTrack::getTimestamp] position=${position}, timestamp=${timespec_sec}.${timespec_nsec}`);
        }
    });

    const pauseApi = '_ZN7android10AudioTrack5pauseEv';
    const pause = module.findExportByName(pauseApi);
    if (!pause) {
        console.error(`Symbol ${pauseApi} not found in ${libName}.`);
        return;
    }

    Interceptor.attach(pause, {
        onEnter(args) {
            console.log(`[AudioTrack::pause]`);
        }
    });

    const startApi = '_ZN7android10AudioTrack5startEv';
    const start = module.findExportByName(startApi);
    if (!start) {
        console.error(`Symbol ${startApi} not found in ${libName}.`);
        return;
    }

    Interceptor.attach(start, {
        onEnter(args) {
            console.log(`[AudioTrack::start]`);
        }
    });

    const stopApi = '_ZN7android10AudioTrack4stopEv';
    const stop = module.findExportByName(stopApi);
    if (!stop) {
        console.error(`Symbol ${stopApi} not found in ${libName}.`);
        return;
    }

    Interceptor.attach(stop, {
        onEnter(args) {
            console.log(`[AudioTrack::stop]`);
        }
    });

    const flushApi = '_ZN7android10AudioTrack5flushEv';
    const flush = module.findExportByName(flushApi);
    if (!flush) {
        console.error(`Symbol ${flushApi} not found in ${libName}.`);
        return;
    }

    Interceptor.attach(flush, {
        onEnter(args) {
            console.log(`[AudioTrack::flush]`);
        }
    });

    console.log("AudioTrack hook initialized");
}

try {
    hook();
} catch (error) {
    console.error(`Error initializing AudioTrack hook: ${error}`);
}