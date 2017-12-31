import { RouterModule, Routes, CanActivate } from '@angular/router';

// Front-end Routed Components
import { UseCaseIndexComponent } from './use-case-index/use-case-index.component';
import { DashboardIndexComponent } from './dashboard-index/dashboard-index.component';

export const appRoutes: Routes = [
  {
    path: '',
    component: UseCaseIndexComponent
  },
  {
    path: 'dashboards',
    component: DashboardIndexComponent
  }
];
