/* jshint esversion: 6 */
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const mongoose = require('mongoose');
mongoose.Promise = Promise;

const db = require('../models/index.js');

app.use(bodyParser.json());

function handleCORS(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
    next();
}

function showAllLogSrcs(req, res) {
  db.LogSrc.find({})
    .then(logsrcs => {
      res.header('Access-Control-Allow-Origin', '*');
      res.json(logsrcs);
    })
    .catch(err => {
      console.log(err);
    });
}

function createLogSrc(req, res) {
  db.LogSrc.create({ logSrc: req.body.logSrc })
    .then(createdLogSrc => {
      console.log(createdLogSrc);
      res.header('Access-Control-Allow-Origin', '*');
      res.json(createdLogSrc);
    })
    .catch(err => {
      console.log(err);
    });
}

function deleteLogSrc(req, res) {
  console.log('DELETE CALLED');
  db.LogSrc.remove({ 'logSrc': req.params.logSrcName })
    .then(deletedLogSrc => {
      res.header('Access-Control-Allow-Origin', '*');
      res.json(deletedLogSrc);
    })
    .catch(err => {
      console.log(err);
    });
}

module.exports = {
  handleCORS: handleCORS,
  showAllLogSrcs: showAllLogSrcs,
  createLogSrc: createLogSrc,
  deleteLogSrc: deleteLogSrc
};
