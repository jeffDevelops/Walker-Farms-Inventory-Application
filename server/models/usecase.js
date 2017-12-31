/* jshint esversion: 6 */
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const LogSrcSchema = require('./logSources.js');

let UseCaseSchema = new Schema({
  useCase: {
    type: String,
  },
  domain: {
    type: String,
  },
  spl: {
    type: String,
  },
  requiredLogSrcs: [LogSrcSchema.schema],
  comments: String
});

let UseCase = mongoose.model('Use_Case', UseCaseSchema);
module.exports = UseCase;
