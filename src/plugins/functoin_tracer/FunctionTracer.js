(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Utils_1 = require("./Utils");
const ERRNO = {
    SUCCESS: 0,
    CLASS_NOT_FOUND: 1,
    METHOD_NOT_FOUND: 2,
    JAVA_ENV_NOT_AVAILABLE: 3,
    SYMBOL_NOT_FOUND: 4,
    UNABLE_TO_HOOK: 5,
};
rpc.exports = {
    resolveNativeSymbols: function (namespace, cls, method) {
        return Utils_1.MyUtils.findCppNativeDebugSymbol(namespace, cls, method).map((symbol) => {
            return {
                address: symbol.address.toString(),
                moduleName: symbol.moduleName || 'unknown',
                name: symbol.name || 'unknown',
            };
        });
    },
    resolveJavaSignature: function (cls, method) {
        if (!Java.available) {
            return Promise.resolve([{ what: 'Java env not available', errno: ERRNO.JAVA_ENV_NOT_AVAILABLE }]);
        }
        return new Promise((resolve, reject) => {
            Java.performNow(() => {
                let c;
                try {
                    c = Java.use(cls);
                }
                catch (e) {
                    resolve([{ what: 'Class not found ' + cls, errno: ERRNO.CLASS_NOT_FOUND }]);
                    return;
                }
                const isConstructor = method === '$init' || method === '<init>';
                if (isConstructor) {
                    const constructors = c.class.getDeclaredConstructors();
                    const results = constructors.map((m) => {
                        return {
                            cls: cls,
                            method: '$init',
                            retType: '<init>',
                            argTypes: m.getParameterTypes().map((t) => t.getName()),
                        };
                    });
                    resolve(results);
                }
                else {
                    const results = c.class.getDeclaredMethods()
                        .filter((m) => {
                        return method === null || m.getName() === method;
                    }).map((m) => {
                        return {
                            cls: cls,
                            method: m.getName(),
                            retType: m.getReturnType().getName(),
                            argTypes: m.getParameterTypes().map((t) => t.getName()),
                        };
                    });
                    resolve(results);
                }
            });
        });
    },
    traceNativeFunctions: function (addrs, identifiers, config) {
        const { bt: printBacktrace, args: printArguments, atrace: addAtraceEvent, log: outputToLogcat, quiet, } = config;
        const type = 'native_trace';
        const hookNativeMethod = (address, identifier) => {
            let traceName = null;
            if (addAtraceEvent) {
                traceName = Memory.allocUtf8String(identifier);
            }
            // todo: demangle and analyze arguments
            Interceptor.attach(address, {
                onEnter(args) {
                    const callId = Math.random() * Math.pow(2, 32);
                    this.callId = callId;
                    let enterMessage = {
                        event: 'enter',
                        type,
                        identifier,
                        callId,
                    };
                    if (printBacktrace) {
                        enterMessage.backtrace = Utils_1.MyUtils.getNativeBacktrace(this.context);
                    }
                    if (outputToLogcat) {
                        Utils_1.MyUtils.alog(JSON.stringify(enterMessage));
                    }
                    if (addAtraceEvent) {
                        Utils_1.MyUtils.beginTrace(traceName);
                    }
                    if (!quiet) {
                        send(enterMessage);
                    }
                },
                onLeave(ret) {
                    const exitMessage = {
                        event: 'exit',
                        type,
                        identifier,
                        callId: this.callId,
                    };
                    if (outputToLogcat) {
                        Utils_1.MyUtils.alog(JSON.stringify(exitMessage));
                    }
                    if (addAtraceEvent) {
                        Utils_1.MyUtils.endTrace();
                    }
                    if (!quiet) {
                        send(exitMessage);
                    }
                }
            });
        };
        let result = [];
        for (let i = 0; i < addrs.length; i++) {
            try {
                hookNativeMethod(ptr(addrs[i]), identifiers[i]);
                result.push({ what: 'done', errno: ERRNO.SUCCESS });
            }
            catch (e) {
                result.push({ what: `Failed to hook ${identifiers[i]}, error: ${e}`, errno: ERRNO.UNABLE_TO_HOOK });
            }
        }
        return result;
    },
    traceJavaMethods: function (methods, config) {
        const { bt: printBacktrace, args: printArguments, atrace: addAtraceEvent, log: outputToLogcat, quiet, } = config;
        const type = 'java_trace';
        const len = methods.length;
        if (!Java.available) {
            return Promise.resolve(new Array(len).fill({ what: 'Java env not available', errno: ERRNO.CLASS_NOT_FOUND }));
        }
        const clsName = methods[0].cls;
        return new Promise((resolve, reject) => {
            Java.performNow(() => {
                let cls;
                try {
                    cls = Java.use(clsName);
                }
                catch (e) {
                    resolve(new Array(len).fill({ what: `Class not found ${clsName}`, errno: ERRNO.CLASS_NOT_FOUND }));
                    return;
                }
                let results = [];
                for (const { method, retType, argTypes } of methods) {
                    try {
                        cls[method].overload(...argTypes).implementation = function () {
                            const callId = Math.random() * Math.pow(2, 32);
                            let enterMessage = {
                                event: 'enter',
                                type,
                                identifier: `${cls.$className}.${method}`,
                                callId,
                            };
                            if (printBacktrace) {
                                enterMessage.backtrace = Utils_1.MyUtils.getJavaBacktrace();
                            }
                            if (printArguments) {
                                let args = [];
                                if (arguments.length !== argTypes.length) {
                                    args.push({ type: "null", value: 'Argument count mismatch' });
                                }
                                else {
                                    for (let i = 0; i < arguments.length; i++) {
                                        args.push({
                                            type: argTypes[i],
                                            value: arguments[i] ? arguments[i].toString() : null,
                                        });
                                    }
                                }
                                enterMessage.arguments = args;
                            }
                            if (!quiet) {
                                send(enterMessage);
                            }
                            if (outputToLogcat) {
                                Utils_1.MyUtils.alog(JSON.stringify(enterMessage));
                            }
                            if (addAtraceEvent) {
                                Utils_1.MyUtils.beginTrace(Memory.allocUtf8String(`${cls.$className}.${method}`));
                            }
                            const result = this[method].apply(this, arguments);
                            if (addAtraceEvent) {
                                Utils_1.MyUtils.endTrace();
                            }
                            const exitMessage = {
                                event: 'exit',
                                type,
                                identifier: `${cls.$className}.${method}`,
                                callId,
                            };
                            if (printArguments) {
                                if (retType === 'void') {
                                    exitMessage.result = {
                                        type: 'void',
                                        value: null,
                                    };
                                }
                                else {
                                    exitMessage.result = {
                                        type: retType,
                                        value: result,
                                    };
                                }
                            }
                            if (outputToLogcat) {
                                Utils_1.MyUtils.alog(JSON.stringify(exitMessage));
                            }
                            if (!quiet) {
                                send(exitMessage);
                            }
                            return result;
                        };
                        results.push({ what: 'done', errno: ERRNO.SUCCESS });
                    }
                    catch (e) {
                        results.push({ what: `Failed to hook ${method}, error: ${e}`, errno: ERRNO.UNABLE_TO_HOOK });
                    }
                }
                resolve(results);
            });
        });
    }
};

},{"./Utils":2}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MyUtils = void 0;
const MyUtils = {
    findMethodWithTypes: function (cls, returnTypeName, parameterTypes) {
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
    findFieldNameWithType: function (cls, type) {
        let fields = [];
        const fieldsArray = cls.class.getDeclaredFields();
        fieldsArray.forEach((field) => {
            const fieldType = field.getType().getName();
            if (fieldType === type) {
                fields.push(field.getName());
            }
        });
        return fields;
    },
    findCppNativeDebugSymbol: function (namespace, cls, method) {
        let mangled = "*";
        if (namespace) {
            mangled += namespace.length + namespace;
        }
        // todo: support nested class
        if (cls) {
            mangled += cls.length + cls;
        }
        if (!namespace && !cls) {
            mangled += method; // probably a c function
        }
        else {
            mangled += method.length + method;
        }
        mangled += "*";
        const candidates = DebugSymbol.findFunctionsMatching(mangled).map(DebugSymbol.fromAddress);
        return candidates;
    },
    _NativeLogWrite: (function () {
        const module = Process.findModuleByName('liblog.so');
        if (!module) {
            console.log('liblog.so not found');
            return function () { };
        }
        const ptr = module.findExportByName('__android_log_write');
        if (!ptr) {
            console.log('__android_log_write not found');
            return function () { };
        }
        return new NativeFunction(ptr, 'void', ['int', 'pointer', 'pointer']);
    })(),
    NativeTag: Memory.allocUtf8String('AmzFridaLogger'),
    alog: function (...args) {
        const msg = args.join(' ');
        const msgPtr = Memory.allocUtf8String(msg);
        this._NativeLogWrite(4, this.NativeTag, msgPtr); // INFO
    },
    beginTrace: (function () {
        try {
            let ptr = Module.findExportByName(null, 'atrace_begin_body');
            if (!ptr) {
                return function (name) { };
            }
            const begin = new NativeFunction(ptr, 'void', ['pointer']);
            return function (name) {
                if (name) {
                    begin(name);
                }
            };
        }
        catch (e) {
            // in some native process, atrace library may not be loaded
            // just ignore it
            return function (name) { };
        }
    })(),
    endTrace: (function () {
        try {
            let ptr = Module.findExportByName(null, 'atrace_end_body');
            if (!ptr) {
                return function () { };
            }
            return new NativeFunction(ptr, 'void', []);
        }
        catch (e) {
            return function () { };
        }
    })(),
    // must run in Java.perform
    getJavaBacktrace: function () {
        return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()) + "";
    },
    getNativeBacktrace: function (context) {
        return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
    },
};
exports.MyUtils = MyUtils;

},{}]},{},[1]);
