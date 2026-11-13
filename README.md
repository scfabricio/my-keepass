# Meu Cofre

Aplicativo desktop pessoal para guardar senhas em um arquivo criptografado. O cofre pode ficar em uma pasta sincronizada com serviços como Google Drive ou Dropbox.

## Tecnologias

- Wails 3
- Go
- TypeScript, Svelte e Vite

## Desenvolvimento

Pré-requisitos: Go, Node.js com npm e as dependências nativas do Wails 3 para o sistema operacional.

```sh
npm install --prefix frontend
../.tools/wails3 task dev
```

O comando Wails acima presume que o repositório foi clonado com a estrutura atual, em que `.tools/wails3` fica na pasta raiz e o app em `my-keepass/`. Também é possível instalar o CLI Wails 3 e executar `wails3 task dev` a partir desta pasta.

## Build desktop

```sh
../.tools/wails3 task build
```

O artefato local será criado em `bin/`. Para criar o pacote de instalação do sistema atual:

```sh
../.tools/wails3 task package
```

O build deve ser feito no sistema operacional de destino e exige as ferramentas nativas correspondentes. Consulte a [documentação do Wails 3](https://v3.wails.io/) para os requisitos de cada plataforma.
