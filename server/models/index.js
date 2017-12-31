/* jshint esversion:6 */

const mongoose = require('mongoose');
mongoose.connect(
  process.env.MONGODB_URI ||
  process.env.MONGOLAB_URI ||
  process.env.MONGOHQ_URL ||
  'mongodb://localhost/vSOC_content_library'
);


module.exports.UseCase = require('./usecase.js');
module.exports.Dashboard = require('./dashboard.js');
module.exports.LogSrc = require('./logSources.js');
