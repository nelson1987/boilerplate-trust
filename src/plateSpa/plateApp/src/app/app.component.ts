import { Component, OnInit } from '@angular/core';
import { FormBuilder } from '@angular/forms';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-root',
  standalone: true,
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit {
  title = 'plateApp';
  
  formCadastro : any;
  valoresForm : any;
  mensagem: any;
  setores : any;

  constructor(private fb: FormBuilder, private http : HttpClient){

  }
  
  ngOnInit(): void {
   this.formCadastro = this.fb.group({
    nome : ['']
   });   
  }

  cadastrar(){
    this.http
      .post('',{
        'nome' : this.formCadastro.value.nome
      })
      .subscribe(res => this.mensagem = res);
  }

  consultar(): void{
    this.http.get('https://jsonplaceholder.typicode.com/posts/1')
    .subscribe(response => {
      this.mensagem = response;
    });
    // this.http
    //   .get('http://localhost:56925/api/Setor')
    //   .subscribe(res => this.setores = res.json());
    // }
  }

}
