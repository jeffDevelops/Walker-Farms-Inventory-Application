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

function createNewUseCase(req, res) {
  let logSrcsArray = req.body.requiredLogSrcs.slice(0);
  db.UseCase.create({
    useCase: req.body.useCase,
    domain: req.body.domain,
    spl: req.body.spl,
    comments: req.body.comments
  }).then(createdUseCase => {
    // define database interactions as functions that return promises
    function asyncPushSubdoc(subdoc) {
      return new Promise(resolve => {
        db.LogSrc.findOne(subdoc)
          .then(foundSubdoc => {
            resolve(createdUseCase.requiredLogSrcs.push(foundSubdoc));
          });
      });
    }
    let dbInteractions = logSrcsArray.map(asyncPushSubdoc);
    let dbResults = Promise.all(dbInteractions);
    dbResults.then( () => {
      createdUseCase.save();
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json(createdUseCase);
    }).catch(err => console.log(err));
  }).catch(err => console.log(err));
}

function showAllUseCases(req, res) {
  console.log('SHOW ALL HIT \n \n \n \n \n \n');
  db.UseCase.find({})
    .then(usecases => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json(usecases);
    })
    .catch(err => {
      console.log(err);
    });
}

function updateUseCase(req, res) {
  db.UseCase.findOneAndUpdate({ '_id': req.params.id },
    { "$set":
      {
        "useCase": req.body.useCase,
        "domain": req.body.domain,
        "spl": req.body.spl,
        "requiredLogSrcs": req.body.requiredLogSrcs,
        "comments": req.body.comments
      }
    }, { new: true }, function(err, newDoc) {
      if (err) throw err;
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json('updated');
    });
}

function deleteUseCase(req, res) {
  db.UseCase.findOneAndRemove({ '_id': req.params.id }, function(err, deletedDoc) {
    if (err) throw err;
    console.log(deletedDoc);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.json('deleted');
  });
}

module.exports = {
  handleCORS: handleCORS,
  createNewUseCase: createNewUseCase,
  showAllUseCases: showAllUseCases,
  updateUseCase: updateUseCase,
  deleteUseCase: deleteUseCase
};
