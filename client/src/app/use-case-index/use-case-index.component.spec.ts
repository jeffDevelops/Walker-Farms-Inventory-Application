import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { UseCaseIndexComponent } from './use-case-index.component';

describe('UseCaseIndexComponent', () => {
  let component: UseCaseIndexComponent;
  let fixture: ComponentFixture<UseCaseIndexComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ UseCaseIndexComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(UseCaseIndexComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
