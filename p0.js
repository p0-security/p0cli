const r = require("module").createRequire(__filename);
r(`${__dirname}/dist/index.js`).main();
