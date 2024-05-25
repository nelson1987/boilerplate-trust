import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

import { MatDialogModule} from '@angular/material/dialog';
import { CadastroSetorComponent } from './cadastro-setor/cadastro-setor.component';
import {HttpModule} from '@angular/http';

@NgModule({

  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    [MatDialogModule],
    HttpModule
  ],
  exports:[CadastroSetorComponent],
  providers:[],
  declarations: [ AppComponent ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }