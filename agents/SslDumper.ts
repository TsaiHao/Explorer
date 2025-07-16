// adapted from git@github.com:BigFaceCat2017/frida_ssl_logger.git

type GetFdType = (ssl: any) => number;

class SocketLogger {
    addresses: Record<string, NativePointer> = {};
    SSL_get_fd: NativeFunction<number, [NativePointer]> | GetFdType = this.return_zero;
    SSL_get_session: NativeFunction<NativePointer, [NativePointer]> | null = null;
    SSL_SESSION_get_id: NativeFunction<NativePointer, [NativePointer, NativePointer]> | null = null;
    ntohl: NativeFunction<number, [number]> | null = null;

    return_zero (args: any) {
        return 0;
    }

    init () {
        const apis = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "ntohl"];

        for (let i = 0; i < apis.length; i++) {
            const name = apis[i];
            const symbol = DebugSymbol.fromName(name);
            if (symbol.name === null) {
                return -1;
            }
            this.addresses[name] = symbol.address;
        }
        if (this.addresses["SSL_get_fd"].toUInt32() === 0) {
            this.SSL_get_fd = this.return_zero;
        } else {
            this.SSL_get_fd = new NativeFunction(this.addresses["SSL_get_fd"], "int", ["pointer"]);
        }
        this.SSL_get_session = new NativeFunction(this.addresses["SSL_get_session"], "pointer", ["pointer"]);
        this.SSL_SESSION_get_id = new NativeFunction(this.addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
        this.ntohl = new NativeFunction(this.addresses["ntohl"], "int", ["int"]);

        return 0;
    }

    ipToNumber (ip: string) {
        let num = 0;
        if (ip === "") {
            return num;
        }
        const aNum = ip.split(".");
        if (aNum.length !== 4) {
            return num;
        }
        num += parseInt(aNum[0]) << 0;
        num += parseInt(aNum[1]) << 8;
        num += parseInt(aNum[2]) << 16;
        num += parseInt(aNum[3]) << 24;
        num = num >>> 0;
        return num;
    }

    getPortsAndAddresses (sockfd: number, isRead: boolean) {
        const message: any = {};
        const src_dst = ["src", "dst"];
        for (const sd of src_dst) {
            let sockAddr;
            if ((sd === "src") !== isRead) {
                sockAddr = Socket.localAddress(sockfd);
            } else {
                sockAddr = Socket.peerAddress(sockfd);
            }

            if (sockAddr !== null && 'port' in sockAddr && this.ntohl) {
                message[sd + "_port"] = (sockAddr.port & 0xFFFF);
                const ip = sockAddr.ip.split(":").pop();
                message[sd + "_addr"] = ip ? this.ntohl(this.ipToNumber(ip)) : 0;
            } else {
                message[sd + "_port"] = 0;
                message[sd + "_addr"] = 0;
            }
        }
        return message;
    }

    getSslSessionId (ssl: NativePointer) {
        if (this.SSL_get_session == null || this.SSL_SESSION_get_id == null) {
            return "";
        }

        const session = this.SSL_get_session(ssl);
        if (session.toUInt32() === 0) {
            return "";
        }

        const lenBuffer = Memory.alloc(4);
        const p = this.SSL_SESSION_get_id(session, lenBuffer);

        const len = lenBuffer.readU32();

        let session_id = "";
        for (let i = 0; i < len; i++) {
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).slice(-2);
        }
        return session_id;
    }

    start () {
        try {
            let self = this;
            Interceptor.attach(this.addresses["SSL_read"],
                {
                    onEnter: function (args) {
                        const fd = self.SSL_get_fd(args[0]);
                        
                        let message = self.getPortsAndAddresses(fd, true);
                        message["ssl_session_id"] = self.getSslSessionId(args[0]);
                        message["function"] = "SSL_read";
                        message["event"] = "ssl";
                        this.message = message;

                        this.buf = args[1];
                    },
                    onLeave: function (retval: NativePointer) {
                        const ret = retval.toInt32();
                        if (ret <= 0) {
                            return;
                        }
                        send(this.message, this.buf.readByteArray(ret));
                    }
                }
            );
            /*
            Interceptor.attach(this.addresses["SSL_write"],
                {
                    onEnter: function (args) {
                        let message = self.getPortsAndAddresses(self.SSL_get_fd(args[0]), false);
                        message["ssl_session_id"] = self.getSslSessionId(args[0]);
                        message["function"] = "SSL_write";
                        message["event"] = "ssl";

                        const size = args[2].toInt32();

                        send(message, args[1].readByteArray(size));
                    },
                }
            );
            */

            return 0;
        } catch (e) {
            return -1;
        }
    }
}

const logger = new SocketLogger();

rpc.exports = {
    init: logger.init.bind(logger),
    start: logger.start.bind(logger),
    stop: function () {},   // Detaching from a specific function is not feasible, just unload this script
};