const express = require('express');
const _ = require('lodash');

const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: _.capitalize('hello from demo app protected by Release Sentinel'),
  });
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Demo app listening on port ${port}`);
  });
}

module.exports = app;
