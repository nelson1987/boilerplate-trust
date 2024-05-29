import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatDialogModule} from '@angular/material/dialog';
import { CadastroSetorComponent } from './cadastro-setor/cadastro-setor.component';
import { AppRoutingModule } from './app-routing.module';
import { HttpClientModule } from '@angular/common/http';

@NgModule({

  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule 
  ],
  exports:[CadastroSetorComponent],
  providers:[],
  declarations: [ AppComponent, CadastroSetorComponent ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }