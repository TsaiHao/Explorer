import { MyUtils } from './Utils';

const ERRNO = {
    SUCCESS: 0,
    CLASS_NOT_FOUND: 1,
    METHOD_NOT_FOUND: 2,
    JAVA_ENV_NOT_AVAILABLE: 3,
    SYMBOL_NOT_FOUND: 4,
    UNABLE_TO_HOOK: 5,
}

interface NativeSymbol {
    address: string;
    moduleName: string;
    name: string;
}

interface JavaMethod {
    cls: string;
    method: string;
    retType: string;
    argTypes: Array<string>;
}

interface AgentResult {
    what: string;
    errno: number;
}

interface TraceConfig {
    bt: boolean;
    args: boolean;
    atrace: boolean;
    log: boolean;
    transform: Array<{
        index: number;
        new_value: any;
    }>;
}

interface OnEnterMessage {
    event: 'enter';
    type: string;
    identifier: string;
    callId: number;
    backtrace?: any;
    arguments?: Array<{ type: string; value: any }>;
}

interface OnLeaveMessage {
    event: 'exit';
    type: string;
    identifier: string;
    callId: number;
    backtrace?: any;
    result?: { type: string; value: any };
}

rpc.exports = {
    resolveNativeSymbols: function (namespace: string, cls: string, method: string): Array<NativeSymbol> {
        return MyUtils.findCppNativeDebugSymbol(namespace, cls, method).map((symbol): NativeSymbol => {
            return {
                address: symbol.address.toString(),
                moduleName: symbol.moduleName || 'unknown',
                name: symbol.name || 'unknown',
            };
        });
    },

    resolveJavaSignature: function (cls: string, method: string | null) : Promise<Array<JavaMethod | AgentResult>> {
        if (!Java.available) {
            return Promise.resolve([{ what: 'Java env not available', errno: ERRNO.JAVA_ENV_NOT_AVAILABLE }]);
        }

        return new Promise((resolve, reject) => {
            Java.performNow(() => {
                let c;
                try {
                    c = Java.use(cls);
                } catch (e) {
                    resolve([{ what: 'Class not found ' + cls, errno: ERRNO.CLASS_NOT_FOUND }]);
                    return;
                }

                const isConstructor = method === '$init' || method === '<init>';
                if (isConstructor) {
                    const constructors = c.class.getDeclaredConstructors();
                    const results = constructors.map((m: any) => {
                        return {
                            cls: cls,
                            method: '$init',
                            retType: '<init>',
                            argTypes: m.getParameterTypes().map((t: any) => t.getName()),
                        };
                    });
                    resolve(results);
                } else {
                    const results = c.class.getDeclaredMethods()
                        .filter((m: any) => {
                        return method === null || m.getName() === method;
                    }).map((m: any) => {
                        return {
                            cls: cls,
                            method: m.getName(),
                            retType: m.getReturnType().getName(),
                            argTypes: m.getParameterTypes().map((t: any) => t.getName()),
                        };
                    });
                    resolve(results);
                }
            });
        });
    },

    traceNativeFunctions: function (addrs: number[], identifiers: string[], config: TraceConfig): Array<AgentResult> {
        const {
            bt: printBacktrace,
            args: printArguments,
            atrace: addAtraceEvent,
            log: outputToLogcat,
        } = config;

        const type = 'native_trace';
        const hookNativeMethod = (address: NativePointer, identifier: string) => {
            let traceName: NativePointer | null = null;
            if (addAtraceEvent) {
                traceName = Memory.allocUtf8String(identifier);
            }

            // todo: demangle and analyze arguments
            Interceptor.attach(address, {
                onEnter(args) {
                    const callId = Math.floor(Math.random() * Math.pow(2, 32));
                    this.callId = callId;
                    let enterMessage: OnEnterMessage = {
                        event: 'enter',
                        type,
                        identifier,
                        callId,
                    };
                    if (printBacktrace) {
                        enterMessage.backtrace = MyUtils.getNativeBacktrace(this.context);
                    }
                    if (outputToLogcat) {
                        MyUtils.alog(JSON.stringify(enterMessage));
                    }
                    if (addAtraceEvent) {
                        MyUtils.beginTrace(traceName);
                    }
                },
                onLeave(ret) {
                    const exitMessage: OnLeaveMessage = {
                        event: 'exit',
                        type,
                        identifier,
                        callId: this.callId,
                    };
                    if (outputToLogcat) {
                        MyUtils.alog(JSON.stringify(exitMessage));
                    }
                    if (addAtraceEvent) {
                        MyUtils.endTrace();
                    }
                }
            });
        };

        let result = [];
        for (let i = 0; i < addrs.length; i++) {
            try {
                hookNativeMethod(ptr(addrs[i]), identifiers[i]);
                result.push({ what: 'done', errno: ERRNO.SUCCESS });
            } catch (e) {
                result.push({ what: `Failed to hook ${identifiers[i]}, error: ${e}`, errno: ERRNO.UNABLE_TO_HOOK });
            }
        }
        return result;
    },

    traceJavaMethods: function (methods, config): Promise<Array<AgentResult>> {
        const {
            bt: printBacktrace,
            args: printArguments,
            atrace: addAtraceEvent,
            log: outputToLogcat,
        } = config;
        const type = 'java_trace';

        const len = methods.length;
        if (!Java.available) {
            return Promise.resolve(new Array(len).fill({ what: 'Java env not available', errno: ERRNO.CLASS_NOT_FOUND }));
        }

        const clsName = methods[0].cls;
        return new Promise((resolve, reject) => {
            Java.performNow(() => {
                let cls: Java.Wrapper;
                try {
                    cls = Java.use(clsName);
                } catch (e) {
                    resolve(new Array(len).fill({ what: `Class not found ${clsName}`, errno: ERRNO.CLASS_NOT_FOUND }));
                    return;
                }
                let results = [];
                for (const { method, retType, argTypes } of methods) {
                    try {
                        cls[method].overload(...argTypes).implementation = function () {
                            const callId = Math.floor(Math.random() * Math.pow(2, 32));
                            let enterMessage: OnEnterMessage = {
                                event: 'enter',
                                type,
                                identifier: `${cls.$className}.${method}`,
                                callId,
                            }
                            if (printBacktrace) {
                                enterMessage.backtrace = MyUtils.getJavaBacktrace();
                            }
                            if (printArguments) {
                                let args = [];
                                if (arguments.length !== argTypes.length) {
                                    args.push({ type: "null", value: 'Argument count mismatch' });
                                } else {
                                    for (let i = 0; i < arguments.length; i++) {
                                        args.push({
                                            type: argTypes[i],
                                            value: arguments[i] ? arguments[i].toString() : null,
                                        })
                                    }
                                }
                                enterMessage.arguments = args;
                            }

                            if (outputToLogcat) {
                                MyUtils.alog(JSON.stringify(enterMessage));
                            }

                            if (addAtraceEvent) {
                                MyUtils.beginTrace(Memory.allocUtf8String(`${cls.$className}.${method}`));
                            }

                            const result = this[method].apply(this, arguments);

                            if (addAtraceEvent) {
                                MyUtils.endTrace();
                            }

                            const exitMessage: OnLeaveMessage = {
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
                                    }
                                } else {
                                    exitMessage.result = {
                                        type: retType,
                                        value: result,
                                    }
                                }
                            }

                            if (outputToLogcat) {
                                MyUtils.alog(JSON.stringify(exitMessage));
                            }

                            return result;
                        }
                        results.push({ what: 'done', errno: ERRNO.SUCCESS });
                    } catch (e) {
                        results.push({ what: `Failed to hook ${method}, error: ${e}`, errno: ERRNO.UNABLE_TO_HOOK });
                    }
                }
                resolve(results);
            })
        });
    }
}