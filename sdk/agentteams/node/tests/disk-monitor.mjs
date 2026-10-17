import { parentPort, workerData } from 'node:worker_threads';
import * as fs from 'node:fs';
import path from 'node:path';

let peak = 0, journalSeen = false;
function measure() {
  let sum = 0;
  for (const name of fs.readdirSync(workerData)) {
    try {
      const size = fs.statSync(path.join(workerData, name)).size;
      sum += size;
      if (name.endsWith('-journal') && size > 512) journalSeen = true;
    } catch { /* A journal can disappear between directory listing and stat. */ }
  }
  peak = Math.max(peak, sum);
}
const timer = setInterval(measure, 1);
parentPort.on('message', () => { clearInterval(timer); measure(); parentPort.postMessage({ peak, journalSeen }); });
parentPort.postMessage('ready');
