const MyUtils = {
    findMethodWithTypes: function (cls: any, returnTypeName: string, parameterTypes: string[]) {
        const methods = cls.class.getDeclaredMethods();
        const matchedMethods = [];

        for (let i = 0; i < methods.length; i++) {
            const method = methods[i];
            if (method.getReturnType().getName() === returnTypeName) {
                const argTypes = method.getParameterTypes();
                if (argTypes.length !== parameterTypes.length) {
                    continue;
                }
                let match = true;
                for (let j = 0; j < argTypes.length; j++) {
                    if (argTypes[j].getName() !== parameterTypes[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    matchedMethods.push(method.getName());
                }
            }
        }

        return matchedMethods;
    },

    findFieldNameWithType: function (cls: any, type: string) {
        let fields: string[] = [];
        const fieldsArray = cls.class.getDeclaredFields();
        fieldsArray.forEach((field: any) => {
            const fieldType = field.getType().getName();
            if (fieldType === type) {
                fields.push(field.getName());
            }
        });
        return fields;
    },

    findCppNativeDebugSymbol: function (namespace: string | null, cls: any | null, method: string) {
        let mangled = "*";
        if (namespace) {
            mangled += namespace.length + namespace;
        }
        // todo: support nested class
        if (cls) {
            mangled += cls.length + cls;
        }
        if (!namespace && !cls) {
            mangled += method;  // probably a c function
        } else {
            mangled += method.length + method;
        }
        mangled += "*";

        const candidates = DebugSymbol.findFunctionsMatching(mangled).map(DebugSymbol.fromAddress);
        return candidates;
    },

    _NativeLogWrite: (function() {
        const module = Process.findModuleByName('liblog.so');
        if (!module) {
            console.log('liblog.so not found');
            return function() {};
        }
        const ptr = module.findExportByName('__android_log_write');
        if (!ptr) {
            console.log('__android_log_write not found');
            return function() {};
        }
        return new NativeFunction(
            ptr,
            'void',
            ['int', 'pointer', 'pointer']
        );
    })(),
    NativeTag: Memory.allocUtf8String('AmzFridaLogger'),
    alog: function (...args: any[]) {
        const msg = args.join(' ');
        const msgPtr = Memory.allocUtf8String(msg);
        this._NativeLogWrite(4, this.NativeTag, msgPtr);          // INFO
    },

    beginTrace: (function() {
        try {
            let ptr = Module.findExportByName(null, 'atrace_begin_body');
            if (!ptr) {
                return function(name: NativePointer | null) {};
            }
            const begin = new NativeFunction(ptr, 'void', ['pointer']);
            return function(name: NativePointer | null) {
                if (name) {
                    begin(name);
                }
            };
        } catch (e) {
            // in some native process, atrace library may not be loaded
            // just ignore it
            return function(name: NativePointer | null) {};
        }
    })(),
    endTrace: (function() {
        try {
            let ptr = Module.findExportByName(null, 'atrace_end_body');
            if (!ptr) {
                return function() {};
            }
            return new NativeFunction(ptr, 'void', []);
        } catch (e) {
            return function() {};
        }
    })(),

    // must run in Java.perform
    getJavaBacktrace: function () {
        return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()) + "";
    },

    getNativeBacktrace: function (context: any) {
        return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
    },
}

export { MyUtils };