import { Component, OnInit } from '@angular/core';

import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { DashboardHttpService } from '../dashboard-http.service';
import { LogSrcsHttpService } from '../log-srcs-http.service';

import { ModalService } from '../modal.service';

@Component({
  selector: 'app-edit-dashboard',
  templateUrl: './edit-dashboard.component.html',
  styleUrls: ['./edit-dashboard.component.scss'],
})
export class EditDashboardComponent implements OnInit {

  constructor(
    private http: DashboardHttpService,
    private logSrcsHttp: LogSrcsHttpService,
    private modals: ModalService
  ) { }

  subscription: Subscription;
  logSrcs: Array<any> = [];
  specificLogSrcs: Array<string> = [];
  tagToAdd: string = '';
  tagToDelete: string = '';

  // UX Enhancements
  savingTag: boolean = false;
  updatingDB: boolean = false;
  deletingFromDB: boolean = false;

  dashboard = {
    dashboardName: '',
    domain: '',
    dashboardXML: '',
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

dashboardNameValid = true;


  addTag() {
    console.log(this.tagToAdd);
    // clone the services array
    let existingTags = this.logSrcsHttp.logSrcsArray.slice(0);
    // lower case all entries for comparison's sake (it's easier to read than capitalizing)
    let normalizedExistingTags = existingTags.map(tag => tag.toLowerCase());
    let normalizedNewTags = [];
    this.dashboard.requiredLogSrcs.map(tag => {
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
              this.dashboard.requiredLogSrcs.push({ logSrc: this.tagToAdd });
              // this.specificLogSrcs.unshift(this.tagToAdd);
              this.tagToAdd = '';
            });
        }, 400);
      } else if (!normalizedNewTags.includes(this.tagToAdd.toLowerCase())) {
        console.log('Already exists in the DB.');
        this.dashboard.requiredLogSrcs.push({ logSrc: this.tagToAdd });
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
    this.tagToDelete = this.dashboard.requiredLogSrcs[which].logSrc;
    console.log(this.tagToDelete);
    //Remove it from the view's array
    this.dashboard.requiredLogSrcs.splice(which, 1);
    console.log(this.dashboard.requiredLogSrcs);
    // check master copy of usecases to see if any of them have the we're deleting
    console.log('HTTP\'S USECASES: ', this.http.dashboardArray);
    let iterations = this.http.dashboardArray.length;
    let match = false;
    for (let i = 0; i < iterations; i++) { // A for-loop was better here than forEach for break support
      if (match) {
        console.log('SHOULD BREAK FROM OUTER');
        break;
      }
      console.log('Iteration: ', i);
      let currentUseCaseLogSrcs = this.http.dashboardArray[i].requiredLogSrcs; // Array of objects
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

  validateDashboardName() {
    this.dashboardNameValid = true;
    console.log('validating...');
    let pool = this.http.dashboardArray.slice(0);
    pool.forEach(element => {
      if (this.dashboard.dashboardName.toLowerCase().trim() === element.dashboardName.toLowerCase().trim()) {
        pool.splice(element, 1);
        console.log('REMOVED CURRENT');
      }
    });
    this.dashboardNameValid = true;
    pool.forEach(dashboard => {
      if (this.dashboard.dashboardName.toLowerCase().trim() === dashboard.dashboardName.toLowerCase().trim()) {
        console.log("MATCH");
        this.dashboardNameValid = false;
      }
    });
  }

  updateDashboard() {
    this.updatingDB = true;
    window.setTimeout( () => {
      this.http.updateDashboard(this.dashboard)
                .then( () => {
                  this.updatingDB = false;
                  this.http.getDashboards().then( response => {
                    console.log('Edit Modal Calling Get All After Update', response);
                    this.exitModal();
                  });
                });
    }, 400);
  }

  deleteDashboard() {
    if (window.confirm('Delete this dashboard and its associated data?')) {
      this.deletingFromDB = true;
      window.setTimeout( () => {
        this.http.deleteDashboard(this.dashboard)
        .then( () => {
          this.deletingFromDB = false;
          this.http.getDashboards().then( response => {
            console.log('Edit Modal Calling Get All After Delete', response);
            this.exitModal();
          });
        });
      }, 400);
    } else {
      console.log('not yet');
    }
  }

  confirmModalExit() {
    console.log(this.dashboard);
    console.log(this.http.specificDashboard);
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
        console.log(i);
        console.log(componentVersion[propName]);
        console.log(serviceVersion[propName]);
        if (componentVersion[propName] !== serviceVersion[propName]) {
          return true;
        }
      }
      return false;
    }
    // Check if the modal has been edited
    if(hasBeenEdited(this.dashboard, this.http.specificDashboard)) {
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
      'background-color': this.modals.edit.displayed ? 'rgba(0, 0, 0, 0.4)' : 'rgba(0,0,0,0)',
      'transition': 'background-color 3s'
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
    this.dashboard = Object.assign(this.dashboard, this.http.specificDashboard);
    console.log(this.dashboard);
  }

}
