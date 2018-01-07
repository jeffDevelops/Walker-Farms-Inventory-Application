import { Component, OnInit } from '@angular/core';

import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { UseCaseHttpService } from '../use-case-http.service';
import { LogSrcsHttpService } from '../log-srcs-http.service';

import { ModalService } from '../modal.service';

@Component({
  selector: 'app-edit-use-case',
  templateUrl: './edit-use-case.component.html',
  styleUrls: ['./edit-use-case.component.scss'],
})
export class EditUseCaseComponent implements OnInit {

  constructor(
    private http: UseCaseHttpService,
    private logSrcsHttp: LogSrcsHttpService,
    private modals: ModalService
  ) { }

  subscription: Subscription;
  logSrcs: Array<any> = []; // ALL logSrcs
  specificLogSrcs: Array<string> = []; // LogSrcs, new and old, specific to the UseCase being created
  tagToAdd: string = '';
  tagToDelete: string = '';

  // UX Enhancements
  savingTag: boolean = false;
  updatingDB: boolean = false;
  deletingFromDB: boolean = false;

  splUseCase = {
    useCase: '',
    domain: '',
    spl: '',
    requiredLogSrcs: [],
    comments: ''
  }

  domains: Array<string> = [
    'Lorem',
    'Ipsum',
    'Dolor',
    'Sit',
    'Amet',
    'Consectetur',
    'Adipicising',
    'Elit',
    'Nulla',
    'Sodales'
  ];

  useCaseNameValid: boolean = true;

  addTag() {
    console.log(this.tagToAdd);
    // clone the services array
    let existingTags = this.logSrcsHttp.logSrcsArray.slice(0);
    // lower case all entries for comparison's sake (it's easier to read than capitalizing)
    let normalizedExistingTags = existingTags.map(tag => tag.toLowerCase());
    let normalizedNewTags = [];
    this.splUseCase.requiredLogSrcs.map(tag => {
      normalizedNewTags.push(tag.logSrc.toLowerCase());
    });
    // don't let the input be empty and don't create a new tag if it already exists
    if (this.tagToAdd) {
      console.log('Not empty.');
      if (!normalizedExistingTags.includes(this.tagToAdd.toLowerCase())) {
        // this.savingTag = true;
        console.log(this);
        setTimeout( () => {
          console.log(this);
          console.log(this.tagToAdd);
          this.logSrcsHttp.createLogSrc(this.tagToAdd)
            .then( () => {
              // this.savingTag = false;
              this.logSrcsHttp.getAllLogSrcs();
              existingTags.push(this.tagToAdd);
              this.splUseCase.requiredLogSrcs.push({ logSrc: this.tagToAdd });
              // this.specificLogSrcs.unshift(this.tagToAdd);
              this.tagToAdd = '';
            });
        }, 400);
      } else if (!normalizedNewTags.includes(this.tagToAdd.toLowerCase())) {
        console.log('Already exists in the DB.');
        this.splUseCase.requiredLogSrcs.push({ logSrc: this.tagToAdd });
        // this.specificLogSrcs.unshift(this.tagToAdd);
        this.tagToAdd = '';
      } else {
        alert('That tag already exists for this use case.');
        this.tagToAdd = '';
      }
    }
  }

  deleteTag(which) {
    let shouldDeleteFromDB = false;
    this.tagToDelete = this.splUseCase.requiredLogSrcs[which].logSrc;
    console.log(this.tagToDelete);
    //Remove it from the view's array
    this.splUseCase.requiredLogSrcs.splice(which, 1);
    console.log(this.splUseCase.requiredLogSrcs);
    // check master copy of usecases to see if any of them have the we're deleting
    console.log('HTTP\'S USECASES: ', this.http.useCaseArray);
    let iterations = this.http.useCaseArray.length;
    let match = false;
    for (let i = 0; i < iterations; i++) { // A for-loop was better here than forEach for break support
      if (match) {
        console.log('SHOULD BREAK FROM OUTER');
        break;
      }
      console.log('Iteration: ', i);
      let currentUseCaseLogSrcs = this.http.useCaseArray[i].requiredLogSrcs; // Array of objects
      console.log(currentUseCaseLogSrcs);
      for (let j = 0; j < currentUseCaseLogSrcs.length; j++) {
        if (match) {
          console.log('SHOULD BREAK FROM INNER');
          break;
        }
        let currentTagObject = currentUseCaseLogSrcs[j];
        console.log(currentTagObject);
        if (currentTagObject.logSrc === this.tagToDelete) {
          match = true;
          console.log('FOUND ONE: Shouldnt delete');
        } else if (j === currentUseCaseLogSrcs.length - 1) {
          console.log('Last inner iteration. Didnt find anything');
        } else {
          console.log('DIDNT FIND ANY, gonna keep looking');
        }
      }
      if (!match && i === iterations - 1) {
        console.log('DIDNT FIND ANYTHING, AND SHOULD DELETE FROM DB');
        shouldDeleteFromDB = true;
      }
    }
    if (shouldDeleteFromDB) {
      // Ask user if it's okay to delete the log source from the db
      if (!window.confirm(`The tag you deleted doesn\'t exist anywhere else in our records and will be deleted permanently.\nClick "Cancel" to keep it as a suggestion.`)) {
        shouldDeleteFromDB = false;
        console.log('KEEPING FOR LATER USE');
      } else {
        this.logSrcsHttp.deleteLogSrc(this.tagToDelete)
          .then( () => {
            this.logSrcsHttp.getAllLogSrcs();
          });
        shouldDeleteFromDB = false;
      }
    }
  }

  validateUseCaseName() {
    this.useCaseNameValid = true;
    console.log('validating...');
    let pool = this.http.useCaseArray.slice(0);
    pool.forEach(element => {
      if (this.splUseCase.useCase.toLowerCase().trim() === element.useCase.toLowerCase().trim()) {
        pool.splice(element, 1);
        console.log('REMOVED CURRENT');
      }
    });
    this.useCaseNameValid = true;
    pool.forEach(usecase => {
      if (this.splUseCase.useCase.toLowerCase().trim() === usecase.useCase.toLowerCase().trim()) {
        console.log("MATCH");
        this.useCaseNameValid = false;
      }
    });
  }

  updateUseCase() {
    this.updatingDB = true;
    console.log('updateUseCase called on: ', this.splUseCase);
    setTimeout( () => {
      this.http.updateUseCase(this.splUseCase)
               .then( () => {
                 this.updatingDB = false;
                 this.http.getUseCases().then( response => {
                   console.log('EDIT MODAL CALLING GET ALL AFTER UPDATE', response);
                   this.exitModal();
                 });
               });
    }, 400);
  }

  deleteUseCase() {
    if (window.confirm('Delete this SPL Query and its associated data?')) {
      this.deletingFromDB = true;
      window.setTimeout( () => {
        this.http.deleteUseCase(this.splUseCase)
          .then( () => {
            this.deletingFromDB = false;
            this.http.getUseCases().then( response => {
              console.log('EDIT MODAL CALLING GET ALL AFTER DELETE', response);
              this.exitModal();
            });
          });
      }, 400);
    } else {
      console.log('Not yet');
    }
  }

  confirmModalExit() { // Checks if the object two-way bound to the view is identical
    // Check for object equality
    function hasBeenEdited(componentVersion, serviceVersion) {
      let componentProps = Object.getOwnPropertyNames(componentVersion);
      let serviceProps = Object.getOwnPropertyNames(serviceVersion);
      // Objects aren't equal if number of properties unequal, although I can't think of when this would ever happen in our app
      if (componentProps.length != serviceProps.length) {
        console.log('Different number of properties');
        return true;
      }
      // Iterate through object to check property values' equivalencies
      for (let i = 0; i < componentProps.length; i++) {
        let propName = componentProps[i];
        if (componentVersion[propName] !== serviceVersion[propName]) {
          return true;
        }
      }
      return false;
    }
    // Check if the modal has been edited
    if(hasBeenEdited(this.splUseCase, this.http.specificUseCase)) {
      // If so, confirm whether user wants to exit
      if (window.confirm('Your changes will not be saved. Exit anyway?')) {
        this.exitModal();
      }
      // If not, modal safely closed without warning
    } else {
      this.exitModal();
    }
  }

  transitionOpacity() {
    let styles = {
      'background-color': this.modals.edit.displayed ? 'rgba(0, 0, 0, 0.4)' : 'rgba(0, 0, 0, 0)',
      'transition' : 'background-color 3s'
    }
    return styles;
  }

  exitModal() {
    this.modals.edit.displayed = false;
  }

  ngOnInit() {
    // INITIAL HTTP REQUEST
    this.logSrcsHttp.getAllLogSrcs().then( () => {
      this.logSrcs = this.logSrcsHttp.logSrcsArray;
    });
    // SUBSCRIBE COMPONENT TO CHANGES IN LOGSRCS ARRAY
    this.subscription = this.logSrcsHttp.cast.subscribe( logSrcs => {
      this.logSrcs = logSrcs;
    });
    // POPULATE THE FORM FIELDS WITH THE SPECIFIC USE CASE PROPERTIES
    this.splUseCase = Object.assign(this.splUseCase, this.http.specificUseCase);
    console.log(this.splUseCase);
  }

}
