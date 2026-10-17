function plain(value) { return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype; }
function own(value, name) {
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
export function mcpResult(input) {
  try {
    if (!plain(input)) return 'unknown';
    let result = input;
    if (Object.hasOwn(input, 'jsonrpc')) {
      if (own(input, 'jsonrpc') !== '2.0' || !Object.hasOwn(input, 'id') || Object.hasOwn(input, 'method') ||
          Object.hasOwn(input, 'result') === Object.hasOwn(input, 'error')) return 'unknown';
      if (Object.hasOwn(input, 'error')) {
        const error = own(input, 'error');
        return plain(error) && Number.isInteger(own(error, 'code')) && typeof own(error, 'message') === 'string'
          ? 'error' : 'unknown';
      }
      result = own(input, 'result');
      if (!plain(result)) return 'unknown';
    }
    const content = own(result, 'content');
    if (!Array.isArray(content) || content.some(item => !plain(item) ||
        !['text', 'image', 'audio', 'resource', 'resource_link'].includes(own(item, 'type')))) return 'unknown';
    const flag = Object.hasOwn(result, 'isError') ? own(result, 'isError') : false;
    return flag === true ? 'error' : flag === false ? 'success' : 'unknown';
  } catch { return 'unknown'; }
}
