import { Component, OnInit, HostListener } from '@angular/core';

import { trigger, state, style, animate, transition } from '@angular/animations';

import { DashboardIndexComponent } from './dashboard-index/dashboard-index.component';
import { UseCaseIndexComponent } from './use-case-index/use-case-index.component';

import { ModalService } from './modal.service';


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
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
export class AppComponent implements OnInit {

  @HostListener('window:scroll', [])
  onWindowScroll() {
    if (window.pageYOffset > 0) {
      this.navState = 'collapsed';
    } else {
      this.navState = 'fullHeight';
    }
  }

  constructor(private modals: ModalService) {}

  // Navigation Scroll state
  navState = 'fullHeight';

  // Navigation properties (determine whether link is active)
  active = { 'border-top': '3px solid #21447e' };
  inactive = { 'border-top': '3px solid transparent' };
  pathname = window.location.pathname;

  toggleModalStyles() {
    let styles = {
      'filter': this.modals.edit.displayed || this.modals.create.displayed || this.modals.view.displayed ? 'blur(2px)' : 'blur(0px)',
      'overflow': this.modals.edit.displayed || this.modals.create.displayed || this.modals.view.displayed ? 'hidden' : 'auto',
      'transition': 'all 1s'
    };
    if (this.modals.create.displayed || this.modals.edit.displayed || this.modals.view.displayed) {
      document.body.style.overflow = 'hidden'; // I'm sure this is resolutely frowned-upon
    }
    return styles;
  }

  checkIfActive(path) {
    if (path == window.location.pathname) {
      return this.active;
    } else {
      return this.inactive;
    }
  }

  ngOnInit() {

  }

}
