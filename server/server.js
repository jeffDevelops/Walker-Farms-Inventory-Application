/* jshint esversion: 6 */

const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const mongoose = require('mongoose');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const path = require('path');

// Request Logging
app.use(morgan('dev'));

// API Config
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: false
}));

const useCaseRoutes = require('./api/useCases.js');
const logSrcRoutes = require('./api/logSrcs.js');
const dashboardRoutes = require('./api/dashboards.js');
app.use(useCaseRoutes);
app.use(logSrcRoutes);
app.use(dashboardRoutes);

// const forceSSL = function() {
//   return function (req, res, next) {
//     if (req.headers['x-forwarded-proto'] !== 'https') {
//       return res.redirect(
//        ['https://', req.get('Host'), req.url].join('')
//       );
//     }
//     next();
//   }
// }

// app.use(forceSSL());

app.use(express.static(path.join(__dirname, '../client/dist')));

app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, '../client/dist/index.html'));
});

app.get('/dashboards', function(req, res) {
  res.sendFile(path.join(__dirname, '../client/dist/index.html'));
});

// Start Server
app.listen(port, () => {
  console.log(`vSOC Content Library API running on localhost:${port}`);
});
