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

function createNewDashboard(req, res) {
  let logSrcsArray = req.body.requiredLogSrcs.slice(0);
  db.Dashboard.create({
    dashboardName: req.body.dashboardName,
    domain: req.body.domain,
    dashboardXML: req.body.dashboardXML,
    comments: req.body.comments
  }).then(createdDashboard => {
    function asyncPushSubdoc(subdoc) {
      return new Promise(resolve => {
        db.LogSrc.findOne(subdoc)
          .then(foundSubdoc => {
            resolve(createdDashboard.requiredLogSrcs.push(foundSubdoc));
          });
      });
    }
    let dbInteractions = logSrcsArray.map(asyncPushSubdoc);
    let dbResults = Promise.all(dbInteractions);
    dbResults.then( () => {
      createdDashboard.save();
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json(createdDashboard);
    }).catch(err => console.log(err));
  }).catch(err => console.log(err));
}

function showAllDashboards(req, res) {
  db.Dashboard.find( (err, dashboards) => {
    if (err) {
      console.log(err);
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json(dashboards);
    }
  });
}

function updateDashboard(req, res) {
  db.Dashboard.findOneAndUpdate({ '_id': req.params.id },
    { '$set':
      {
        'dashboardName': req.body.dashboardName,
        'domain': req.body.domain,
        'dashboardXML': req.body.dashboardXML,
        'requiredLogSrcs': req.body.requiredLogSrcs,
        'comments': req.body.comments
      }
    }, { new: true }, function(err, newDoc) {
      if (err) throw err;
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.json('updated');
    });
}

function deleteDashboard(req, res) {
  db.Dashboard.findOneAndRemove({ '_id': req.params.id }, function(err, deletedDoc) {
    if (err) throw err;
    console.log(deletedDoc);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.json('deleted');
  });
}

module.exports = {
  handleCORS: handleCORS,
  createNewDashboard: createNewDashboard,
  showAllDashboards: showAllDashboards,
  updateDashboard: updateDashboard,
  deleteDashboard: deleteDashboard
};
