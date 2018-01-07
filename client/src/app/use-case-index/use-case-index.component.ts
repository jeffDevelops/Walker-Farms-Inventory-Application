import { Component, OnInit, AfterViewInit, OnDestroy, HostListener, ViewChild, ElementRef } from '@angular/core';
import { trigger, state, style, animate, transition } from '@angular/animations';

import { Observable } from 'rxjs/Observable';
import { Subscription } from 'rxjs/Subscription';

import { UseCaseHttpService } from '../use-case-http.service';
import { LogSrcsHttpService } from '../log-srcs-http.service';
import { ModalService } from '../modal.service';

import { Angular2Csv } from 'angular2-csv/Angular2-csv';

@Component({
  selector: 'app-use-case-index',
  templateUrl: './use-case-index.component.html',
  styleUrls: ['./use-case-index.component.scss'],
  animations: [
    trigger('navState', [
      state('fullHeight', style({
        transform: 'translateY(0)'
      })),
      state('collapsed', style({
        transform: 'translateY(-125px)'
      })),
      transition('collapsed <=> fullHeight', animate('500ms ease-out'))
    ])
  ]
})
export class UseCaseIndexComponent implements OnInit, OnDestroy {

  @HostListener('window:scroll', [])
  onWindowScroll() {
    if (window.innerWidth > 863) {
      if (window.pageYOffset > 0) {
        this.navState = 'collapsed';
      } else {
        this.navState = 'fullHeight';
      }
    } else {
      this.navState = 'fullHeight';
    }
  }

  @HostListener('window:resize', [])
  onWindowResize() {
    if (window.innerWidth < 864) {
      this.menuExpanded = false;
      this.navState = 'fullHeight';
    } else {
      this.menuExpanded = true;
      if (window.pageYOffset > 0) {
        this.navState = 'collapsed';
      } else {
        this.navState = 'fullHeight';
      }
    }
  }

  @ViewChild('expandedFilter') expandedFilter: ElementRef;

  constructor(
    public http: UseCaseHttpService,
    public logSrcsHttp: LogSrcsHttpService, // fix if bored: this name is inconsistent with the name in the dashboard index class--should be singular
    public modals: ModalService
  ) {}

  viewInitialized: boolean = false;

  navState = 'fullHeight'; // Navigation animation
  menuExpanded: boolean; // Mobile/Tablet size menu

  // GET ALL USECASES
  subscription: Subscription;
  logSrcsSubscription: Subscription;
  logSrcObjects: Array<any> = []; // Populates the logSrcs filter, e.g. { logSrc: 'Wineventlog', selected: false }
  logSrcs: Array<any> = []; // Master copy (Don't mutate this array)
  useCases: Array<any> = []; // Master copy (Don't mutate this array)
  displayedUseCases: Array<any> = []; // Mutable copy
  displayedLogSrcs: Array<any> = []; // Mutable copy

  // FILTER (LOGSRC)
  filterExpanded: boolean = false;
  closedFromBlur: boolean = false;
  logSrcSelected: boolean = false;
  selectedLogSrcs: Array<string> = [];
  logSrcFilterEngaged: boolean = false;
  logSrcFilterResults: Array<any> = [];

  // FILTER (SEARCH)
  term: string;
  searchFilterEngaged: boolean = false;
  searchFilterResults: Array<any> = [];

  // FILTER (DOMAIN)
  selected = null;
  domainFilterEngaged: boolean = false;
  domainFilterResults: Array<any> = [];
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
    'Sodales',
    'All'
  ];

  // Modals
  toggleCreate() {
    this.modals.create.displayed = !this.modals.create.displayed;
  }

  toggleEdit(whichUseCase) {
    console.log(whichUseCase);
    // Populate data
    this.http.specificUseCase = this.displayedUseCases[whichUseCase];
    // Call modal
    this.modals.edit.displayed = !this.modals.edit.displayed;
  }

  toggleSpl(whichUseCase) {
    this.http.specificUseCase= this.displayedUseCases[whichUseCase];
    this.modals.view.displayed = !this.modals.view.displayed;
  }

  setStyles() {
    let styles = {
      'filter': this.modals.create.displayed || this.modals.edit.displayed || this.modals.view.displayed ? 'blur(2px)' : 'blur(0px)',
      'overflow': this.modals.create.displayed || this.modals.edit.displayed || this.modals.view.displayed ? 'hidden' : 'auto',
      'transition': 'all 1s'
    };
    this.modals.toggleScrollUnderModal();
    return styles;
  }

  // LOGSRCS FILTER
  closeLogSrcFilter() {
    this.filterExpanded = false;
    console.log(this.logSrcFilterEngaged);
  }

  toggleLogSrcFilter(event) {
    this.filterExpanded = true;
    if (this.filterExpanded && this.viewInitialized) {
      setTimeout( () => this.expandedFilter.nativeElement.focus(), 1);
    }
  }

  toggleLogSrcSelection(which) {
    this.logSrcObjects[which].selected = !this.logSrcObjects[which].selected;
    // If LogSrc is selected, pass it to selected array
    if (this.logSrcObjects[which].selected) {
      this.selectedLogSrcs.push(this.logSrcObjects[which].logSrc);
    // If not, remove it
    } else {
      let indexToRemove = this.selectedLogSrcs.indexOf(this.logSrcObjects[which].logSrc);
      this.selectedLogSrcs.splice(indexToRemove, 1);
    }
    if (this.selectedLogSrcs.length > 0) {
      this.logSrcFilterEngaged = true;
      this.filterByLogSrcs(this.selectedLogSrcs);
    } else {
      this.logSrcFilterEngaged = false;
      this.logSrcFilterResults = [];
      if (!this.domainFilterEngaged && !this.searchFilterEngaged) {
        this.displayedUseCases = this.useCases;
      } else if (this.domainFilterEngaged && !this.searchFilterEngaged) {
        this.getDomainFilterResults(this.useCases, this.selected);
      } else if (this.searchFilterEngaged && !this.domainFilterEngaged) {
        this.getSearchResults(this.useCases);
      } else if (this.searchFilterEngaged && this.domainFilterEngaged) {
        let combinedFilterResults = [];
        this.domainFilterResults.forEach(domainFilterResult => {
          this.searchFilterResults.forEach(searchFilterResult => {
            if (searchFilterResult.useCase === domainFilterResult.useCase) {
              combinedFilterResults.push(domainFilterResult);
            }
          });
        });
        this.displayedUseCases = combinedFilterResults.slice(0);
      }
    }
  }

  filterByLogSrcs(selections) {
    this.logSrcFilterResults = [];
    // Determine the initial pool of resrouces to enact the filter on
    if (!this.searchFilterEngaged && !this.domainFilterEngaged) {
      this.displayedUseCases = this.useCases.slice(0);
      this.getLogSrcFilterResults(this.displayedUseCases, selections);
    } else if (this.searchFilterEngaged && !this.domainFilterEngaged) {
      this.getSearchResults(this.useCases);
      this.getLogSrcFilterResults(this.searchFilterResults, selections);
    } else if (this.domainFilterEngaged && !this.searchFilterEngaged) {
      console.log('DOMAIN SELECTED: ', this.selected);
      this.getDomainFilterResults(this.useCases, this.selected);
      this.getLogSrcFilterResults(this.displayedUseCases, selections);
    } else if (this.domainFilterEngaged && this.searchFilterEngaged) {
      let combinedFilterResults = [];
      this.domainFilterResults.forEach(domainFilterResult => {
        this.searchFilterResults.forEach(searchFilterResult => {
          if (searchFilterResult.useCase === domainFilterResult.useCase) {
            combinedFilterResults.push(domainFilterResult);
          }
        });
      });
      this.getLogSrcFilterResults(combinedFilterResults, selections);
    }
  }

  getLogSrcFilterResults(pool, selections) {
    this.logSrcFilterResults = [];
    console.log('LOG SRC SELECTIONS: ', selections);
    console.log('LOG SRC POOL: ', pool);
    for (let i = 0; i < pool.length; i++) {
      logSrcs: for (let j = 0; j < pool[i].requiredLogSrcs.length; j++) {
        for (let k = 0; k < selections.length; k++) {
          if (selections[k] === pool[i].requiredLogSrcs[j].logSrc) {
            // this.displayedUseCases.push(this.useCases[i]);
            this.logSrcFilterResults.push(pool[i]);
            break logSrcs;
          }
        }
      }
    }
    this.displayedUseCases = this.logSrcFilterResults.slice(0);
  }

  // DOMAIN FILTER
  onDomainSelect(selected) {
    console.log(selected);
    // FILTER NOT ENGAGED, don't get domain results
    this.domainFilterResults = [];
    if (selected === 'All' || selected === null) {
      this.domainFilterEngaged = false;
      if (!this.logSrcFilterEngaged && !this.searchFilterEngaged) {
        this.displayedUseCases = this.useCases.slice(0);
      } else if (this.logSrcFilterEngaged && !this.searchFilterEngaged) {
        this.getLogSrcFilterResults(this.useCases, this.selectedLogSrcs);
      } else if (this.searchFilterEngaged && !this.logSrcFilterEngaged) {
        this.getSearchResults(this.useCases);
      } else if (this.searchFilterEngaged && this.logSrcFilterEngaged) {
        let combinedFilterResults = [];
        this.logSrcFilterResults.forEach(logSrcFilterResult => {
          this.searchFilterResults.forEach(searchFilterResult => {
            if (searchFilterResult.useCase === logSrcFilterResult.useCase) {
              combinedFilterResults.push(logSrcFilterResult);
            }
          });
        });
        this.displayedUseCases = combinedFilterResults.slice(0);
        combinedFilterResults = [];
      }
    } else {
      this.displayedUseCases = this.useCases.slice(0);
      this.domainFilterEngaged = true;
      // Determine the initial pool of resources to enact the filter on, but don't worry about it if selected is 'All' or null
      if (!this.searchFilterEngaged && !this.logSrcFilterEngaged) {
        this.getDomainFilterResults(this.displayedUseCases, selected);
      } else if (this.logSrcFilterEngaged && !this.searchFilterEngaged) {

        console.log('DISPLAYED USECASES: ', this.displayedUseCases);
        console.log('FILTERED LOG SRCS ON DOMAIN FILTER: ', this.logSrcFilterResults);
        console.log('LOG SRC RESULTS: ', this.logSrcFilterResults);
        this.getLogSrcFilterResults(this.useCases, this.selectedLogSrcs);
        console.log('LOG SRC RESULTS: ', this.logSrcFilterResults);
        this.getDomainFilterResults(this.logSrcFilterResults, selected);
      } else if (this.searchFilterEngaged && !this.logSrcFilterEngaged) {
        this.getSearchResults(this.useCases);
        this.getDomainFilterResults(this.searchFilterResults, selected);
      } else if (this.searchFilterEngaged && this.logSrcFilterEngaged) {
        let combinedFilterResults = [];
        this.logSrcFilterResults.forEach(logSrcFilterResult => {
          this.searchFilterResults.forEach(searchFilterResult => {
            if (searchFilterResult.useCase === logSrcFilterResult.useCase) {
              combinedFilterResults.push(logSrcFilterResult);
            }
          });
        });
        this.getDomainFilterResults(combinedFilterResults, selected);
      }
    }
  }

  getDomainFilterResults(pool, selected) {
    console.log('Search filter engaged: ', this.searchFilterEngaged);
    console.log('DOMAIN SELECTED: ', selected);
    console.log('DOMAIN POOL: ', pool);
    this.domainFilterResults = [];
    pool.forEach(usecase => {
      if (usecase.domain === selected) {
        this.domainFilterResults.push(usecase);
      }
    });
    this.displayedUseCases = this.domainFilterResults;
  }

  // SEARCH FILTER
  onSearch() {
    if (!this.term) {
      this.searchFilterEngaged = false;
      this.searchFilterResults = [];
      if (!this.domainFilterEngaged && !this.logSrcFilterEngaged) {
        this.displayedUseCases = this.useCases;
      } else if (this.domainFilterEngaged && !this.logSrcFilterEngaged) {
        this.getDomainFilterResults(this.useCases, this.selected);
      } else if (this.logSrcFilterEngaged && !this.domainFilterEngaged) {
        this.getLogSrcFilterResults(this.useCases, this.selectedLogSrcs);
      } else if (this.logSrcFilterEngaged && this.domainFilterEngaged) {
        this.getLogSrcFilterResults(this.useCases, this.selectedLogSrcs);
        this.getDomainFilterResults(this.displayedUseCases, this.selected);
        // let combinedFilterResults = [];
        // this.domainFilterResults.forEach(domainFilterResult => {
        //   this.logSrcFilterResults.forEach(logSrcFilterResult => {
        //     if (logSrcFilterResult.useCase === domainFilterResult.useCase) {
        //       combinedFilterResults.push(domainFilterResult);
        //     }
        //   });
        // });
        // this.displayedUseCases = combinedFilterResults.slice(0);
      }
    } else {
      this.displayedUseCases = this.useCases;
      this.searchFilterEngaged = true;
      // Determine the initial pool of resources to enact the filter on, but don't worry about it's empty
      if (!this.logSrcFilterEngaged && !this.domainFilterEngaged) {
        this.getSearchResults(this.displayedUseCases);
      } else if (this.logSrcFilterEngaged && !this.domainFilterEngaged) {
        this.getSearchResults(this.logSrcFilterResults);
      } else if (this.domainFilterEngaged && !this.logSrcFilterEngaged) {
        this.getSearchResults(this.domainFilterResults);
      } else if (this.domainFilterEngaged && this.logSrcFilterEngaged) {
        let combinedFilterResults = [];
        this.logSrcFilterResults.forEach(logSrcFilterResult => {
          this.domainFilterResults.forEach(domainFilterResult => {
            if (domainFilterResult.useCase === logSrcFilterResult.useCase) {
              combinedFilterResults.push(logSrcFilterResult);
            }
          });
        });
        this.getSearchResults(combinedFilterResults);
      }
    }
  }

  getSearchResults(pool) {
    console.log('SEARCH POOL: ', pool);
    console.log('SEARCH SEARCHTERM: ', this.term);
    this.searchFilterResults = [];
    let isMatch = false;
    let normalizedTerm = this.term.toLowerCase();
    pool.forEach( usecase => {
      // iterate through object properties
      let useCaseProps = Object.getOwnPropertyNames(usecase);
      useCaseProps.forEach( property => {
        //don't search the MongoDB-added properties
        if (property !== '__v' && property !== '_id') {
        // if property is a string
          if (typeof(usecase[property]) === 'string') {
            let normalizedProperty = usecase[property].toLowerCase();
            // see if value of search box exists in that string
            if (normalizedProperty.includes(normalizedTerm)) {
              isMatch = true;
            }
          }
          // if property is an array
          if (Array.isArray(usecase[property])) {
            let logSources = usecase[property];
            logSources.forEach(logsrc => {
              let normalizedLogSrcName = logsrc.logSrc.toLowerCase();
              if (normalizedLogSrcName.includes(normalizedTerm)) {
                isMatch = true;
              }
            });
          }
        }
      });
      if (isMatch) {
        this.searchFilterResults.push(usecase);
        isMatch = false;
      }
    });
    this.displayedUseCases = this.searchFilterResults.slice(0);
  }

  // DOWNLOAD CSV
  download() {
    let csvUseCases = [];
    this.displayedUseCases.forEach(usecase => {
      let stringAccumulator = '';
      console.log(usecase.useCase);
      let logSrcArray = usecase.requiredLogSrcs;
      for(let i = 0; i < logSrcArray.length; i++) {
        console.log(logSrcArray[i]);
        if (i === logSrcArray.length - 1) {
          stringAccumulator += logSrcArray[i].logSrc;
        } else {
          stringAccumulator += logSrcArray[i].logSrc + ', ';
        }
      }
      let newObj = {};
      Object.defineProperty(newObj, 'useCase', { value: usecase.useCase, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'domain', { value: usecase.domain, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'spl', { value: usecase.spl, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'requiredLogSrcs', { value: stringAccumulator, configurable: true, enumerable: true, writable: true });
      Object.defineProperty(newObj, 'comments', {  value: usecase.comments, configurable: true, enumerable: true, writable: true });
      console.log(newObj);
      csvUseCases.push(newObj);
      console.log('\n \n');
    });
    console.log(csvUseCases);
    var options = {
      fieldSeparator: ',',
      quoteStrings: '"',
      decimalseparator: '.',
      showLabels: true,
      showTitle: false,
      headers: ['USE CASE', 'DOMAIN', 'SPL', 'REQD LOG SOURCES', 'COMMENTS'] //NEED TO ADD REQD LOG SOURCES
    };
      new Angular2Csv(csvUseCases, 'Searches_Correlations', options);
  }

  toggleMenu() {
    this.menuExpanded = !this.menuExpanded;
  }

  setMenuStyles() {
    let menuStyle = { 'display': this.menuExpanded ? 'block' : 'none' };
    return menuStyle;
  }

  compensateForMenu() {
    let filterResultsStyle = { 'margin-top': this.menuExpanded && window.innerWidth < 864 ? '150px' : '0' };
    return filterResultsStyle;
  }

  // Lifecycle Hooks
  ngOnInit() {
    // NAVBAR STATE
    if (window.pageYOffset > 0) {
      this.navState = 'collapsed';
    } else {
      this.navState = 'fullHeight';
    }

    // MENU STATE
    if (window.innerWidth > 863) {
      this.menuExpanded = true;
    } else {
      this.menuExpanded = false;
    }

    // INITIAL HTTP REQUEST FOR USECASES
    this.http.getUseCases().then( response => {
      this.useCases = this.http.useCaseArray;
      // Displayed usecases stored in different place in memory
      this.displayedUseCases = this.useCases.slice(0);
    });

    // SUBSCRIBE COMPONENT TO CHANGES IN USECASES ARRAY
    this.subscription = this.http.cast.subscribe( useCases => {
      this.displayedUseCases = [];
      this.useCases = useCases;
      this.term = "";
      this.useCases.forEach( usecase => {
        // check filter selection before rendering anything
        if (usecase.domain === this.selected) {
          this.displayedUseCases.push(usecase);
        // if no filter selection, display all
        } else if (this.selected === 'All' || !this.selected) {
          this.displayedUseCases.push(usecase);
        }
      });
    });
    // INITIAL HTTP REQUEST FOR LOG SRCS
    this.logSrcsHttp.getAllLogSrcs().then( () => {
      this.logSrcs = this.logSrcsHttp.logSrcsArray;
    });
    // SUBSCRIBE COMPONENT TO CHANGES IN LOGSRCS ARRAY
    this.logSrcsSubscription = this.logSrcsHttp.cast.subscribe( logsrcs => {
      this.logSrcs = logsrcs;
      this.displayedLogSrcs = [];
      this.logSrcObjects = [];
      logsrcs.forEach(logsrc => {
        let object = {};
        Object.defineProperty(object, 'logSrc', { value: logsrc });
        Object.defineProperty(object, 'selected', { value: false, writable: true });
        this.logSrcObjects.unshift(object);
      });
    });
  }

  ngAfterViewInit() {
    this.viewInitialized = true;
  }

  ngOnDestroy() {
    // Garbage collection
    this.subscription ? this.subscription.unsubscribe() : null;
    this.logSrcsSubscription ? this.logSrcsSubscription.unsubscribe() : null;
  }
}
