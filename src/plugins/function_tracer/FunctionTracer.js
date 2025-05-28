(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
        "use strict";

        Object.defineProperty(exports, "__esModule", {
            value: !0
        });

        const e = require("./utils"), t = {
            SUCCESS: 0,
            CLASS_NOT_FOUND: 1,
            METHOD_NOT_FOUND: 2,
            JAVA_ENV_NOT_AVAILABLE: 3,
            SYMBOL_NOT_FOUND: 4,
            UNABLE_TO_HOOK: 5
        };

        rpc.exports = {
            resolveNativeSymbols: function(t, a, r) {
                return e.MyUtils.findCppNativeDebugSymbol(t, a, r).map((e => ({
                    address: e.address.toString(),
                    moduleName: e.moduleName || "unknown",
                    name: e.name || "unknown"
                })));
            },
            resolveJavaSignature: function(e, a) {
                return Java.available ? new Promise(((r, n) => {
                    Java.performNow((() => {
                        let n;
                        try {
                            n = Java.use(e);
                        } catch (a) {
                            return void r([ {
                                what: "Class not found " + e,
                                errno: t.CLASS_NOT_FOUND
                            } ]);
                        }
                        if ("$init" === a || "<init>" === a) {
                            const t = n.class.getDeclaredConstructors().map((t => ({
                                cls: e,
                                method: "$init",
                                retType: "<init>",
                                argTypes: t.getParameterTypes().map((e => e.getName()))
                            })));
                            r(t);
                        } else {
                            const t = n.class.getDeclaredMethods().filter((e => null === a || e.getName() === a)).map((t => ({
                                cls: e,
                                method: t.getName(),
                                retType: t.getReturnType().getName(),
                                argTypes: t.getParameterTypes().map((e => e.getName()))
                            })));
                            r(t);
                        }
                    }));
                })) : Promise.resolve([ {
                    what: "Java env not available",
                    errno: t.JAVA_ENV_NOT_AVAILABLE
                } ]);
            },
            traceNativeFunctions: function(a, r, n) {
                const {bt: l, args: o, atrace: s, log: i, quiet: c} = n, u = "native_trace", d = (t, a) => {
                    let r = null;
                    s && (r = Memory.allocUtf8String(a)), Interceptor.attach(t, {
                        onEnter(t) {
                            const n = Math.random() * Math.pow(2, 32);
                            this.callId = n;
                            let o = {
                                event: "enter",
                                type: u,
                                identifier: a,
                                callId: n
                            };
                            l && (o.backtrace = e.MyUtils.getNativeBacktrace(this.context)), i && e.MyUtils.alog(JSON.stringify(o)),
                            s && e.MyUtils.beginTrace(r), c || send(o);
                        },
                        onLeave(t) {
                            const r = {
                                event: "exit",
                                type: u,
                                identifier: a,
                                callId: this.callId
                            };
                            i && e.MyUtils.alog(JSON.stringify(r)), s && e.MyUtils.endTrace(), c || send(r);
                        }
                    });
                };
                let y = [];
                for (let e = 0; e < a.length; e++) try {
                    d(ptr(a[e]), r[e]), y.push({
                        what: "done",
                        errno: t.SUCCESS
                    });
                } catch (a) {
                    y.push({
                        what: `Failed to hook ${r[e]}, error: ${a}`,
                        errno: t.UNABLE_TO_HOOK
                    });
                }
                return y;
            },
            traceJavaMethods: function(a, r) {
                const {bt: n, args: l, atrace: o, log: s, quiet: i} = r, c = "java_trace", u = a.length;
                if (!Java.available) return Promise.resolve(new Array(u).fill({
                    what: "Java env not available",
                    errno: t.CLASS_NOT_FOUND
                }));
                const d = a[0].cls;
                return new Promise(((r, y) => {
                    Java.performNow((() => {
                        let y;
                        try {
                            y = Java.use(d);
                        } catch (e) {
                            return void r(new Array(u).fill({
                                what: `Class not found ${d}`,
                                errno: t.CLASS_NOT_FOUND
                            }));
                        }
                        let p = [];
                        for (const {method: r, retType: u, argTypes: d} of a) try {
                            y[r].overload(...d).implementation = function() {
                                const t = Math.random() * Math.pow(2, 32);
                                let a = {
                                    event: "enter",
                                    type: c,
                                    identifier: `${y.$className}.${r}`,
                                    callId: t
                                };
                                if (n && (a.backtrace = e.MyUtils.getJavaBacktrace()), l) {
                                    let e = [];
                                    if (arguments.length !== d.length) e.push({
                                        type: "null",
                                        value: "Argument count mismatch"
                                    }); else for (let t = 0; t < arguments.length; t++) e.push({
                                        type: d[t],
                                        value: arguments[t] ? arguments[t].toString() : null
                                    });
                                    a.arguments = e;
                                }
                                i || send(a), s && e.MyUtils.alog(JSON.stringify(a)), o && e.MyUtils.beginTrace(Memory.allocUtf8String(`${y.$className}.${r}`));
                                const p = this[r].apply(this, arguments);
                                o && e.MyUtils.endTrace();
                                const g = {
                                    event: "exit",
                                    type: c,
                                    identifier: `${y.$className}.${r}`,
                                    callId: t
                                };
                                return l && (g.result = "void" === u ? {
                                    type: "void",
                                    value: null
                                } : {
                                    type: u,
                                    value: p
                                }), s && e.MyUtils.alog(JSON.stringify(g)), i || send(g), p;
                            }, p.push({
                                what: "done",
                                errno: t.SUCCESS
                            });
                        } catch (e) {
                            p.push({
                                what: `Failed to hook ${r}, error: ${e}`,
                                errno: t.UNABLE_TO_HOOK
                            });
                        }
                        r(p);
                    }));
                }));
            }
        };

    },{"./utils":2}],2:[function(require,module,exports){
        "use strict";

        Object.defineProperty(exports, "__esModule", {
            value: !0
        }), exports.MyUtils = void 0;

        const e = {
            findMethodWithTypes: function(e, t, n) {
                const o = e.class.getDeclaredMethods(), i = [];
                for (let e = 0; e < o.length; e++) {
                    const r = o[e];
                    if (r.getReturnType().getName() === t) {
                        const e = r.getParameterTypes();
                        if (e.length !== n.length) continue;
                        let t = !0;
                        for (let o = 0; o < e.length; o++) if (e[o].getName() !== n[o]) {
                            t = !1;
                            break;
                        }
                        t && i.push(r.getName());
                    }
                }
                return i;
            },
            findFieldNameWithType: function(e, t) {
                let n = [];
                return e.class.getDeclaredFields().forEach((e => {
                    e.getType().getName() === t && n.push(e.getName());
                })), n;
            },
            findCppNativeDebugSymbol: function(e, t, n) {
                let o = "*";
                e && (o += e.length + e), t && (o += t.length + t), o += e || t ? n.length + n : n,
                    o += "*";
                return DebugSymbol.findFunctionsMatching(o).map(DebugSymbol.fromAddress);
            },
            _NativeLogWrite: function() {
                const e = Process.findModuleByName("liblog.so");
                if (!e) return console.log("liblog.so not found"), function() {};
                const t = e.findExportByName("__android_log_write");
                return t ? new NativeFunction(t, "void", [ "int", "pointer", "pointer" ]) : (console.log("__android_log_write not found"),
                    function() {});
            }(),
            NativeTag: Memory.allocUtf8String("AmzFridaLogger"),
            alog: function(...e) {
                const t = e.join(" "), n = Memory.allocUtf8String(t);
                this._NativeLogWrite(4, this.NativeTag, n);
            },
            beginTrace: function() {
                try {
                    let e = Module.findExportByName(null, "atrace_begin_body");
                    if (!e) return function(e) {};
                    const t = new NativeFunction(e, "void", [ "pointer" ]);
                    return function(e) {
                        e && t(e);
                    };
                } catch (e) {
                    return function(e) {};
                }
            }(),
            endTrace: function() {
                try {
                    let e = Module.findExportByName(null, "atrace_end_body");
                    return e ? new NativeFunction(e, "void", []) : function() {};
                } catch (e) {
                    return function() {};
                }
            }(),
            getJavaBacktrace: function() {
                return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()) + "";
            },
            getNativeBacktrace: function(e) {
                return Thread.backtrace(e, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
            }
        };

        exports.MyUtils = e;

    },{}]},{},[1])
