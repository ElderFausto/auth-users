# API de Autenticação de Usuários com Spring Boot

API RESTful para cadastro e login de usuários, construída com Spring Boot 3, Spring Security e autenticação via JSON Web Tokens (JWT).

## Tecnologias Utilizadas
- Java 21
- Spring Boot 3
- Spring Web
- Spring Data JPA
- Spring Security
- Lombok
- PostgreSQL
- Maven
- JJWT

## Como Gerar o Projeto
O projeto foi gerado usando o [Spring Initializr](https://start.spring.io/) com as seguintes dependências:
- Spring Web
- Spring Data JPA
- Spring Security
- Validation
- PostgreSQL Driver
- Lombok
- Spring Boot DevTools

## Como Rodar a Aplicação
1.  **Pré-requisito:** Tenha o Java 17 (ou superior) e o Maven instalados. Tenha uma instância do PostgreSQL rodando.
2.  Crie um banco de dados no PostgreSQL (ex: `CREATE DATABASE auth_db;`).
3.  Configure suas credenciais do banco no arquivo `src/main/resources/application.properties`.
4.  Abra o projeto em sua IDE (ex: IntelliJ IDEA).
5.  Execute a classe principal `UsersApplication.java`.
6.  O servidor estará rodando em `http://localhost:8080`.

## Endpoints da API

#### Autenticação

- **`POST /api/auth/register`**
  - Cadastra um novo usuário.
  - **Body**: `{ "username": "user", "email": "user@example.com", "password": "password123" }`

- **`POST /api/auth/login`**
  - Autentica um usuário e retorna um token JWT.
  - **Body**: `{ "username": "user", "password": "password123" }`
  - **Retorno**: `{ "token": "seu-jwt-token" }`

#### Usuários (Protegido)
- **`GET /api/users/me`**
  - Retorna o perfil do usuário atualmente autenticado.
  - **Header Obrigatório**: `Authorization: Bearer <seu-jwt-token>`

## Exemplo com cURL
```bash
# Registrar
curl -X POST http://localhost:8080/api/auth/register -H "Content-Type: application/json" -d '{"username": "testuser", "email": "test@user.com", "password": "password"}'

# Login e extrair token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login -H "Content-Type: application/json" -d '{"username": "testuser", "password": "password"}' | jq -r .token)
echo "Token: $TOKEN"

# Acessar rota protegida
curl -X GET http://localhost:8080/api/users/me -H "Authorization: Bearer $TOKEN"
