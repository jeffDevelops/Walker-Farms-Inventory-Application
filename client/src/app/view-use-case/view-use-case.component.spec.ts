import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ViewUseCaseComponent } from './view-use-case.component';

describe('ViewUseCaseComponent', () => {
  let component: ViewUseCaseComponent;
  let fixture: ComponentFixture<ViewUseCaseComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ViewUseCaseComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ViewUseCaseComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
