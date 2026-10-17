'use strict';
const fs = require('node:fs');
const error = new Error('owned original error');
function mark(name) { fs.appendFileSync(process.env.AGF_BUSINESS_COUNTER, `${name}\n`); }
function sync(value) { mark('sync'); return value; }
async function asynchronous(value) { mark('async'); return value; }
function fail() { mark('fail'); throw error; }
async function root() {
  mark('root');
  const privateValue = { private: 'business-secret-13800138000' };
  const first = module.exports.sync(privateValue) === privateValue;
  const second = await module.exports.asynchronous(privateValue) === privateValue;
  let sameError = false;
  try { module.exports.fail(); } catch (caught) { sameError = caught === error; }
  if (!first || !second || !sameError) throw new Error('Original business semantics changed');
  return { ok: true, syncIdentity: first, asyncIdentity: second, errorIdentity: sameError };
}
module.exports = { root, sync, asynchronous, fail };
