/* jshint esversion: 6 */
const express = require('express');
const router = express.Router();

const logSrcsController = require('../controllers/logSrcs');

router.route('/api/log_sources')
      .get(logSrcsController.showAllLogSrcs)
      .post(logSrcsController.createLogSrc);

router.route('/api/log_sources/:logSrcName')
      .delete(logSrcsController.deleteLogSrc);

router.route('/*')
      .options(logSrcsController.handleCORS);

module.exports = router;
