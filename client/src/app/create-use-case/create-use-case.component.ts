import { Component, OnInit } from '@angular/core';

import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { UseCaseHttpService } from '../use-case-http.service';
import { LogSrcsHttpService } from '../log-srcs-http.service';

import { ModalService } from '../modal.service';

@Component({
  selector: 'app-create-use-case',
  templateUrl: './create-use-case.component.html',
  styleUrls: ['./create-use-case.component.scss'],
})
export class CreateUseCaseComponent implements OnInit {

  constructor(
    public http: UseCaseHttpService,
    public logSrcsHttp: LogSrcsHttpService,
    public modals: ModalService
  ) { }

  subscription: Subscription;
  logSrcs: Array<any> = []; // ALL logSrcs
  specificLogSrcs: Array<string> = []; // LogSrcs, new and old, specific to the UseCase being created
  tagToAdd: string = '';
  tagToDelete: string = '';

  // UX Enhancements
  savingTag: boolean = false;
  fetchingFromDB: boolean = false;
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
  splValid: boolean = true;
  domainValid: boolean = false;

  addTag() {
    console.log(this.tagToAdd);
    // clone the services array
    let existingTags = this.logSrcsHttp.logSrcsArray.slice(0);
    // lower case all entries for comparison's sake (it's easier to read than capitalizing)
    let normalizedExistingTags = existingTags.map(tag => tag.toLowerCase());
    let normalizedNewTags = this.specificLogSrcs.map(tag => tag.toLowerCase());
    // don't let the input be empty and don't create a new tag if it already exists
    if (this.tagToAdd) {
      if (!normalizedExistingTags.includes(this.tagToAdd.toLowerCase())) {
        setTimeout( () => {
          this.logSrcsHttp.createLogSrc(this.tagToAdd)
            .then( () => {
              this.logSrcsHttp.getAllLogSrcs();
              existingTags.push(this.tagToAdd);
              this.splUseCase.requiredLogSrcs.push({ logSrc: this.tagToAdd });
              this.specificLogSrcs.unshift(this.tagToAdd);
              this.tagToAdd = '';
            });
        }, 400);
      } else if (!normalizedNewTags.includes(this.tagToAdd.toLowerCase())) {
        console.log('Already exists in the DB.');
        this.specificLogSrcs.unshift(this.tagToAdd);
        this.tagToAdd = '';
      } else {
        alert('That tag already exists for this use case.');
        this.tagToAdd = '';
      }
    }
  }

  deleteTag(which) {
    let shouldDeleteFromDB = false;
    this.tagToDelete = this.specificLogSrcs[which];
    //Remove it from the view's array
    this.specificLogSrcs.splice(which, 1);
    // check master copy of usecases to see if any of them have the we're deleting
    console.log('HTTP\'S USECASES: ', this.http.useCaseArray);

    let iterations = this.http.useCaseArray.length;
    let match = false;
    for (let i = 0; i < iterations; i++) { // A for-loop was better here than forEach for break support
      if (match) {
        console.log('SHOULD BREAK FROM OUTER');
        break;
      }
      let currentUseCaseLogSrcs = this.http.useCaseArray[i].requiredLogSrcs; // Array of objects
      for (let j = 0; j < currentUseCaseLogSrcs.length; j++) {
        if (match) {
          console.log('SHOULD BREAK FROM INNER');
          break;
        }
        let currentTagObject = currentUseCaseLogSrcs[j];
        console.log(currentTagObject);
        if (currentTagObject.logSrc === this.tagToDelete) {
          console.log('FOUND ONE: Shouldnt delete');
          match = true;
        } else if (j === currentUseCaseLogSrcs.length - 1) {
          console.log('Last iteration. Didnt find anything');
        } else {
          console.log('DIDNT FIND ANY, gonna keep looking');
        }
      }
      if (!match && i === iterations - 1) {
        console.log('Last outer iteration. Didnt find anything');
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
    this.http.useCases.forEach(usecaseArray => {
      usecaseArray.forEach( usecase => {
        if (this.splUseCase.useCase.toLowerCase().trim() === usecase.useCase.toLowerCase().trim()) {
          this.useCaseNameValid = false;
        }
      });
    });
  }

  validateDomain() {
    if (this.splUseCase.domain) {
      this.domainValid = true;
    }
  }

  validateSPL() {
    this.splValid = true;
    this.http.useCases.forEach(usecaseArray => {
      usecaseArray.forEach( usecase => {
        if (this.splUseCase.spl.toLowerCase().trim() === usecase.spl.toLowerCase().trim() && this.splUseCase.spl !== '') {
          this.splValid = false;
        }
      });
    });
  }

  postUseCase() {
    console.log(this.splValid);
    console.log(this.domainValid);
    console.log(this.useCaseNameValid);
    if (this.splValid && this.domainValid && this.useCaseNameValid) {
      this.specificLogSrcs.forEach(logsrc => {
        let logSrcObj = {
          logSrc: logsrc
        }
        this.splUseCase.requiredLogSrcs.unshift(logSrcObj);
      });
      this.fetchingFromDB = true;
      // Call HTTP Service POST request method
      window.setTimeout( () => {
      this.http.createUseCase(this.splUseCase)
              .then( () => {
                this.fetchingFromDB = false;
                this.http.getUseCases().then( () => {
                  this.exitModal();
                });
              });
      }, 400);
    } else {
      alert('Not all fields are valid. Make changes and try again.');
    }
  }

  transitionOpacity() {
    let styles = {
      'background-color': this.modals.create.displayed ? 'rgba(0, 0, 0, .4)' : 'rgba(0, 0, 0, 0)',
      'transition': 'background-color 3s'
    }
    return styles;
  }

  confirmModalExit() { // Checks if the object properties bound to the view are still empty
    function modalUntouched(boundObject) {
      let objProps = Object.getOwnPropertyNames(boundObject);
      for (let i = 0; i < objProps.length; i++) {
        let propName = objProps[i];
        if (boundObject[propName] && boundObject[propName][0]) {
          return false;
        }
      }
      return true;
    }
    console.log(this.splUseCase);
    if (modalUntouched(this.splUseCase)) {
      this.exitModal();
    } else {
      if (window.confirm('Your changes will not be saved. Exit anyway?')) {
        this.exitModal();
      }
    }
  }

  exitModal(): void {
    this.modals.create.displayed = false;
  }

  ngOnInit() {
    // INITIAL HTTP REQUEST
    this.logSrcsHttp.getAllLogSrcs().then( () => {
      this.logSrcs = this.logSrcsHttp.logSrcsArray;
    });
    // SUBSCRIBE COMPONENT TO CHANGES IN LOGSRCS ARRAY
    this.subscription = this.logSrcsHttp.cast.subscribe( logsrcs => {
      this.logSrcs = logsrcs;
      // this.specificLogSrcs = logsrcs;
    });
  }

  ngOnDestroy() {
    // Garbage collection, especially important in modal components!
    this.subscription.unsubscribe() ? this.subscription.unsubscribe() : null;
  }

}
