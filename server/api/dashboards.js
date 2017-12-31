/* jshint esversion: 6 */
const express = require('express');
const router = express.Router();

const dashboardController = require('../controllers/dashboards');

router.route('/api/dashboards')
      .post(dashboardController.createNewDashboard)
      .get(dashboardController.showAllDashboards);

router.route('/api/dashboards/:id')
      .put(dashboardController.updateDashboard)
      .delete(dashboardController.deleteDashboard);

router.route('/*')
      .options(dashboardController.handleCORS);

module.exports = router;
