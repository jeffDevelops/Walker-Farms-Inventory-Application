/* jshint esversion: 6 */
const express = require('express');
const router = express.Router();

const useCaseController = require('../controllers/useCases');

router.route('/api/use_cases')
      .post(useCaseController.createNewUseCase)
      .get(useCaseController.showAllUseCases);

router.route('/api/use_cases/:id')
      .put(useCaseController.updateUseCase)
      .delete(useCaseController.deleteUseCase);

router.route('/*')
      .options(useCaseController.handleCORS);

module.exports = router;
