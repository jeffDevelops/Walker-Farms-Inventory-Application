/* jshint esversion: 6*/
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const LogSrcSchema = require('./logSources.js');

let DashboardSchema = new Schema({
  dashboardName: String,
  domain: String,
  dashboardXML: String,
  requiredLogSrcs: [LogSrcSchema.schema],
  comments: String
});

let Dashboard = mongoose.model('Dashboard', DashboardSchema);
module.exports = Dashboard;
