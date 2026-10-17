import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fixture, target, STARTUP, closeAndPrint } from './startup_support.mjs';

test('preload does not eagerly import and keeps original CJS entry.js require.main argv and side-effect order', async t => {
  const f = fixture(t, 'ordering');
  f.write('work.js', `global.order.push('module'); let calls=0; exports.work=function(value){calls++;global.order.push('call');return value;};exports.calls=()=>calls;`);
  f.configure([target('./work.js')]);
  const entry = f.write('entry.js', `global.order=['entry'];const api=require('./work.js');const again=require('./work.js');const result=api.work(17);${closeAndPrint("({result,order:global.order,calls:api.calls(),same:api===again,main:require.main===module,argv:process.argv.slice(2)})")}`);
  const result = await f.run(entry, { args: ['owned', 'two'] });
  assert.equal(result.code, 0);
  assert.deepEqual(result.json(), { result: 17, order: ['entry', 'module', 'call'], calls: 1, same: true, main: true, argv: ['owned', 'two'] });
  assert.equal(f.events().length, 1);
});

test('sync wrappers preserve this argument/return identity error identity and do not capture raw values', async t => {
  const f = fixture(t, 'identity');
  f.write('work.cjs', `exports.failure={name:'OwnedError',private:'private-error-value'};exports.work=function(value){if(value===exports.failure)throw value;return {receiver:this,input:value};};exports.keep=()=>23;`);
  f.configure([target('./work.cjs', ['work'], { capture: 'shape' })]);
  const entry = f.write('entry.cjs', `const api=require('./work.cjs');const receiver={private:'private-this'};const arg={private:'private-argument'};const result=api.work.call(receiver,arg);let sameError=false;try{api.work(api.failure);}catch(error){sameError=error===api.failure;}const keep=api.keep();${closeAndPrint('({sameError,sameThis:result.receiver===receiver,sameArg:result.input===arg,keep})')}`);
  const response = await f.run(entry);
  assert.equal(response.code, 0); assert.deepEqual(response.json(), { sameError: true, sameThis: true, sameArg: true, keep: 23 });
  assert.deepEqual(f.events().map(event => event.status), ['success', 'error']);
  for (const marker of ['private-this', 'private-argument', 'private-error-value']) assert(!JSON.stringify(f.events()).includes(marker));
});

test('promise result and rejection objects remain original without a second business call', async t => {
  const f = fixture(t, 'promise');
  f.write('work.cjs', `exports.value={id:1};exports.failure={name:'OwnedError'};exports.calls=0;exports.work=async function(fail){exports.calls++;if(fail)throw exports.failure;return exports.value;};`);
  f.configure([target('./work.cjs', ['work'], { mode: 'promise' })]);
  const entry = f.write('entry.cjs', `(async()=>{const api=require('./work.cjs');const same=await api.work(false)===api.value;let error=false;try{await api.work(true);}catch(e){error=e===api.failure;}await require(${JSON.stringify(STARTUP)}).close(0);console.log(JSON.stringify({same,error,calls:api.calls}));})();`);
  const response = await f.run(entry);
  assert.equal(response.code, 0); assert.deepEqual(response.json(), { same: true, error: true, calls: 2 });
  assert.deepEqual(f.events().map(event => event.status), ['success', 'error']);
});

test('generator remains lazy and early return cannot fabricate full success', async t => {
  const f = fixture(t, 'generator');
  f.write('work.cjs', `exports.value={id:1};exports.steps=0;exports.work=function*(){exports.steps++;yield exports.value;exports.steps++;return 9;};`);
  f.configure([target('./work.cjs', ['work'], { mode: 'iterator' })]);
  const entry = f.write('entry.cjs', `const api=require('./work.cjs');const iterator=api.work();const before=api.steps;const first=iterator.next();const end=iterator.return(7);${closeAndPrint('({before,same:first.value===api.value,end,steps:api.steps})')}`);
  const response = await f.run(entry);
  assert.equal(response.code, 0); assert.deepEqual(response.json(), { before: 0, same: true, end: { value: 7, done: true }, steps: 1 });
  assert.equal(f.events().length, 1); assert.equal(f.events()[0].status, 'unknown');
});

test('async generator preserves lazy backpressure yields and its original thrown object', async t => {
  const f = fixture(t, 'async-generator');
  f.write('work.cjs', `exports.value={id:1};exports.failure={name:'OwnedError'};exports.steps=0;exports.work=async function*(){exports.steps++;yield exports.value;exports.steps++;throw exports.failure;};`);
  f.configure([target('./work.cjs', ['work'], { mode: 'asyncIterator' })]);
  const entry = f.write('entry.cjs', `(async()=>{const api=require('./work.cjs');const iterator=api.work();const before=api.steps;const first=await iterator.next();let sameError=false;try{await iterator.next();}catch(e){sameError=e===api.failure;}await require(${JSON.stringify(STARTUP)}).close(0);console.log(JSON.stringify({before,same:first.value===api.value,sameError,steps:api.steps}));})();`);
  const response = await f.run(entry);
  assert.equal(response.code, 0); assert.deepEqual(response.json(), { before: 0, same: true, sameError: true, steps: 2 });
  assert.equal(f.events().length, 1); assert.equal(f.events()[0].status, 'error');
});

test('new and subclass construction are original unobserved pass-through; classes are an explicit gap', async t => {
  const f = fixture(t, 'constructors');
  f.write('work.cjs', `function Ctor(value){this.value=value;this.originalTarget=new.target===Ctor;}class Klass{constructor(value){this.value=value;}}exports.Ctor=Ctor;exports.Klass=Klass;`);
  f.configure([target('./work.cjs', ['Ctor']), target('./work.cjs', ['Klass'])]);
  const entry = f.write('entry.cjs', `const api=require('./work.cjs');const a=new api.Ctor(4);class Sub extends api.Ctor{}const b=new Sub(5);const c=new api.Klass(6);const control=require(${JSON.stringify(STARTUP)});const state=control.status().targets;${closeAndPrint('({a:a.value,originalTarget:a.originalTarget,b:b.value,sub:b instanceof Sub,c:c.value,state})')}`);
  const response = await f.run(entry);
  assert.equal(response.code, 0); const result = response.json();
  assert.equal(result.a, 4); assert.equal(result.originalTarget, true); assert.equal(result.b, 5); assert.equal(result.sub, true); assert.equal(result.c, 6);
  assert.equal(result.state[1].state, 'startup_unsupported_callable'); assert.equal(f.events().length, 0);
});

test('accessors and locked exports are not touched and do not execute getters during observation', async t => {
  const f = fixture(t, 'descriptors');
  f.write('work.cjs', `exports.getters=0;Object.defineProperty(exports,'lazy',{get(){exports.getters++;return ()=>7;}});Object.defineProperty(exports,'locked',{value:()=>8,writable:false});`);
  f.configure([target('./work.cjs', ['lazy']), target('./work.cjs', ['locked'])]);
  const entry = f.write('entry.cjs', `const api=require('./work.cjs');const before=api.getters;const value=api.lazy();const locked=api.locked();const state=require(${JSON.stringify(STARTUP)}).status().targets;${closeAndPrint('({before,after:api.getters,value,locked,state})')}`);
  const response = await f.run(entry);
  assert.equal(response.code, 0); const result = response.json();
  assert.deepEqual([result.before, result.after, result.value, result.locked], [0, 1, 7, 8]);
  assert.deepEqual(result.state.map(row => row.state), ['startup_accessor_or_missing_export', 'startup_locked_export']);
  assert.equal(f.events().length, 0);
});

test('modules cached before installation remain untouched and are not loaded a second time', async t => {
  const f = fixture(t, 'preloaded');
  f.write('work.cjs', `global.loads=(global.loads??0)+1;exports.work=()=>11;`);
  const earlier = f.write('earlier.cjs', `global.reference=require('./work.cjs').work;`);
  f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `const api=require('./work.cjs');const value=api.work();const state=require(${JSON.stringify(STARTUP)}).status().targets;${closeAndPrint('({value,loads:global.loads,same:global.reference===api.work,state})')}`);
  const response = await f.run(entry, { preloads: [earlier] });
  assert.equal(response.code, 0); assert.equal(response.json().same, true); assert.equal(response.json().loads, 1);
  assert.equal(response.json().state[0].state, 'startup_preloaded_gap'); assert.equal(f.events().length, 0);
});

test('a circular partial export is a persistent coverage gap and escaped references are not rewritten', async t => {
  const f = fixture(t, 'cycle');
  f.write('work.cjs', `exports.work=()=>12;exports.peer=require('./peer.cjs');`);
  f.write('peer.cjs', `exports.reference=require('./work.cjs').work;`);
  f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `const api=require('./work.cjs');const value=api.work();const same=api.work===api.peer.reference;const state=require(${JSON.stringify(STARTUP)}).status().targets;${closeAndPrint('({value,same,state})')}`);
  const response = await f.run(entry); assert.equal(response.code, 0);
  assert.equal(response.json().same, true); assert.equal(response.json().value, 12);
  assert.equal(response.json().state[0].state, 'startup_circular_partial_gap'); assert.equal(f.events().length, 0);
});

test('original module loading error identity and missing-module code escape without telemetry replacement', async t => {
  const f = fixture(t, 'loading-errors');
  f.write('work.cjs', `throw global.originalError;`); f.configure([target('./work.cjs')]);
  const entry = f.write('entry.cjs', `global.originalError={tag:'original'};let same=false,code=null;try{require('./work.cjs');}catch(error){same=error===global.originalError;}try{require('./missing-business.cjs');}catch(error){code=error.code;}${closeAndPrint('({same,code})')}`);
  const response = await f.run(entry); assert.equal(response.code, 0);
  assert.deepEqual(response.json(), { same: true, code: 'MODULE_NOT_FOUND' }); assert.equal(f.events().length, 0);
});

test('real ESM .js custom module.exports cannot masquerade as a configured completed CJS callable', async t => {
  const f = fixture(t, 'esm-gap');
  f.write('esm/package.json', '{"type":"module"}');
  f.write('esm/work.js', `const work=()=>13;export {work as 'module.exports'};`);
  f.configure([target('./esm/work.js', null)]);
  const entry = f.write('entry.cjs', `const work=require('./esm/work.js');const value=work();const state=require(${JSON.stringify(STARTUP)}).status().targets;${closeAndPrint('({value,state})')}`);
  const response = await f.run(entry); assert.equal(response.code, 0);
  assert.equal(response.json().value, 13); assert.equal(response.json().state[0].state, 'startup_non_cjs_gap');
  assert.equal(f.events().length, 0);
});

test('fork inherits preload but a busy parent queue is a gap without changing the child business execution', async t => {
  const f = fixture(t, 'fork-gap');
  f.write('work.cjs', `exports.work=()=>29;`); f.configure([target('./work.cjs')]);
  const child = f.write('child.cjs', `const value=require('./work.cjs').work();process.send({value,main:require.main===module,status:require(${JSON.stringify(STARTUP)}).status()});`);
  const entry = f.write('entry.cjs', `const child=require('node:child_process').fork(${JSON.stringify(child)},{stdio:['ignore','ignore','ignore','ipc']});let message;child.once('message',value=>message=value);child.once('exit',code=>{${closeAndPrint('({code,message})')}});`);
  const response = await f.run(entry); assert.equal(response.code, 0);
  assert.equal(response.json().code, 0); assert.equal(response.json().message.main, true); assert.equal(response.json().message.value, 29);
  assert.equal(response.json().message.status.reason, 'startup_owned_queue_gap'); assert.equal(f.events().length, 0);
  assert(fs.existsSync(f.environment.AGF_SPOOL_DIR));
});
