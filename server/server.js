/* jshint esversion: 6 */

const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const mongoose = require('mongoose');
const morgan = require('morgan');
const bodyParser = require('body-parser');

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


// Start Server
app.listen(port, () => {
  console.log(`vSOC Content Library API running on localhost:${port}`);
});
