import { Worker } from '../index.mjs';

// Wrap the application's real callables; this module executes no demo business call.
export function instrumentWorkers(collector, { fromName, fromTeam, toName, toTeam, taskId,
  runTask, invokeWorker, incomingCarrier }) {
  const from = new Worker(fromName, fromTeam), to = new Worker(toName, toTeam);
  return {
    runTask: collector.task(from, { mode: 'promise', taskId, carrier: incomingCarrier,
      operation: 'workflow.task' })(runTask),
    invokeWorker: collector.callWorker(from, to, { mode: 'promise', taskId,
      operation: 'workflow.call' })(invokeWorker),
  };
}
