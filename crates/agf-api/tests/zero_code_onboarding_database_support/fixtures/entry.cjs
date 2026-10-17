'use strict';
const business = require('./business.cjs');
if (require.main !== module) throw new Error('Original entry was not the Node main module');
business.root().then(result => process.stdout.write(`${JSON.stringify(result)}\n`));
