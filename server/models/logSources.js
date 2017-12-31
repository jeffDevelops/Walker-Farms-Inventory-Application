/* jshint esversion: 6 */
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let LogSrcSchema = new Schema({
  logSrc: {
    type: String
  }
});

let LogSrc = mongoose.model('Log_Source', LogSrcSchema);
module.exports = LogSrc;
