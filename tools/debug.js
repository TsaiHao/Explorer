function hook() {
    const MediaCodec = Java.use('android.media.MediaCodec');
    MediaCodec.start.implementation = function () {
        console.log('MediaCodec.start called');
        return this.start.apply(this, arguments);
    }
}

try {
    Java.perform(hook);
} catch (e) {
    console.log(`Error while hooking ${e}`)
}