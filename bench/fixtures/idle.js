const fs = require("fs");
const net = require("net");

function emit(event) {
  const eventFile = process.env.BENCH_EVENT_FILE;
  if (!eventFile) {
    return;
  }

  const payload = {
    event,
    pid: process.pid,
    ts_ms: Date.now(),
  };
  fs.appendFileSync(eventFile, `${JSON.stringify(payload)}\n`);
}

emit("start");

const readyPort = Number(process.env.BENCH_READY_PORT || 0);
const readyHost = process.env.BENCH_READY_HOST || "127.0.0.1";
let readyServer = null;

if (readyPort > 0) {
  readyServer = net.createServer((socket) => {
    socket.end(`${process.pid}\n`);
  });
  readyServer.on("error", (error) => {
    emit(`error:${error.code || "tcp"}`);
    process.stderr.write(`${error.stack || error}\n`);
    process.exit(1);
  });
  readyServer.listen(readyPort, readyHost, () => {
    emit("ready:tcp");
  });
} else {
  emit("ready:idle");
}

function shutdown(signal) {
  emit(`signal:${signal}`);
  if (!readyServer) {
    process.exit(0);
    return;
  }

  readyServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 250).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

setInterval(() => {}, 1000);
