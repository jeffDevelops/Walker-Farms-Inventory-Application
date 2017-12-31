// ng Dependencies
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

// Components
import { AppComponent } from './app.component';
import { CreateUseCaseComponent } from './create-use-case/create-use-case.component';
import { CreateDashboardComponent } from './create-dashboard/create-dashboard.component';
import { UseCaseIndexComponent } from './use-case-index/use-case-index.component';
import { DashboardIndexComponent } from './dashboard-index/dashboard-index.component';
import { ViewUseCaseComponent } from './view-use-case/view-use-case.component';

// Services
import { UseCaseHttpService} from './use-case-http.service';
import { DashboardHttpService } from './dashboard-http.service';
import { LogSrcsHttpService } from './log-srcs-http.service';
import { ModalService } from './modal.service';

// Front-end Routing
import { RouterModule, Routes } from '@angular/router';
import { appRoutes } from './routes';
import { EditUseCaseComponent } from './edit-use-case/edit-use-case.component';

// Universal Search
import { Ng2SearchPipeModule } from 'ng2-search-filter';
import { EditDashboardComponent } from './edit-dashboard/edit-dashboard.component';

// DOM (For Copy To Clipboard)
import { DomService } from './dom.service';
import { ViewDashboardComponent } from './view-dashboard/view-dashboard.component';

@NgModule({
  declarations: [
    AppComponent,
    CreateUseCaseComponent,
    CreateDashboardComponent,
    UseCaseIndexComponent,
    DashboardIndexComponent,
    EditUseCaseComponent,
    EditDashboardComponent,
    ViewUseCaseComponent,
    ViewDashboardComponent
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    FormsModule,
    HttpClientModule,
    Ng2SearchPipeModule,
    RouterModule.forRoot(
      appRoutes,
      { enableTracing: true }
    )
  ],
  providers: [
    UseCaseHttpService,
    LogSrcsHttpService,
    DashboardHttpService,
    ModalService,
    DomService
   ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }
