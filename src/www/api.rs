use crate::{Session, Sessions};
use rocket::{
	form::Form,
	http::{Method, Status},
	request::{FromRequest, Outcome},
	response::{self, Redirect, Responder},
	serde::json::Json,
	tokio::sync::Mutex,
	Request, Response, Route, State,
};
use rocket_sync_db_pools::rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
	collections::HashSet,
	hash::{Hash, Hasher},
	io,
	path::PathBuf,
};

#[repr(transparent)]
struct OptionsResponder<I: IntoIterator<Item = Method>>(I);
impl<'r, I: IntoIterator<Item = Method>> Responder<'r, 'static> for OptionsResponder<I>
where
	I: Send,
{
	fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
		use rocket::http::{hyper::header, Header};

		Ok(Response::build()
			.header(Header::new(
				header::ALLOW.as_str(),
				self.0
					.into_iter()
					.fold(Method::Options.to_string(), |s, method| {
						if method != Method::Options {
							s + ", " + method.as_str()
						} else {
							s
						}
					}),
			))
			.status(Status::NoContent)
			.finalize())
	}
}

struct AuthorizationGuard;
#[async_trait]
impl<'r> FromRequest<'r> for AuthorizationGuard {
	type Error = Status;

	async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		use rocket::http::hyper::header;
		use tokio::{fs::File, io::AsyncReadExt};

		if let Ok(mut file) = File::open("./passwd").await {
			let mut passwd = String::new();
			if file.read_to_string(&mut passwd).await.is_ok() {
				return req
					.headers()
					.get_one(header::AUTHORIZATION.as_str())
					.and_then(|creds| {
						use regex::Regex;

						Regex::new(r"^Basic (?P<creds>.+)$")
							.unwrap()
							.captures(creds)
					})
					.and_then(|creds| {
						let creds = String::from_utf8(
							base64::decode(creds.name("creds").unwrap().as_str()).unwrap(),
						)
						.unwrap();
						let creds = creds.split(':').collect::<Vec<_>>();
						(creds.len() == 2
							&& creds[0] == crate::AdminUser::USERNAME
							&& creds[1] == passwd)
							.then(|| Outcome::Success(Self))
					})
					.unwrap_or(Outcome::Failure((
						Status::Unauthorized,
						Status::Unauthorized,
					)));
			}
		}
		Outcome::Failure((Status::InternalServerError, Status::InternalServerError))
	}
}

type Authorization = Result<AuthorizationGuard, Status>;

#[repr(transparent)]
struct AuthorizationResponder(Authorization);
impl<'r> Responder<'r, 'static> for AuthorizationResponder {
	fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
		use rocket::http::Header;

		if let Err(status) = self.0 {
			let mut res = Response::build();
			res.status(status);
			if status == Status::Unauthorized {
				res.header(Header::new("WWW-Authenticate", "Basic"));
			}
			Ok(res.finalize())
		} else {
			Err(Status::ImATeapot)
		}
	}
}

#[async_recursion]
async fn traverse_dir(path: PathBuf) -> io::Result<HashSet<PathBuf>> {
	let mut files = HashSet::new();
	let mut dir = tokio::fs::read_dir(&path).await?;
	loop {
		match dir.next_entry().await {
			Ok(Some(entry)) => {
				if let Ok(file_type) = entry.file_type().await {
					if file_type.is_dir() {
						files.extend(traverse_dir(entry.path()).await?);
					} else {
						files.insert(entry.path());
					}
				}
			}
			Ok(None) => break,
			Err(_) => continue,
		}
	}
	Ok(files)
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub(crate) struct Article {
	pub file: PathBuf,
	pub title: String,
	#[serde(skip_serializing)]
	pub content: String,
}
impl Article {
	pub const STORAGE: &'static str = "./static/articles";

	pub async fn index_all() -> io::Result<HashSet<Self>> {
		use futures::StreamExt;

		let paths = traverse_dir(Self::STORAGE.into()).await?;
		Ok(futures::stream::iter(paths)
			.filter_map(|path| async move {
				use regex::Regex;
				use tokio::{fs::File, io::AsyncReadExt};

				let mut s = String::new();
				File::open(&path)
					.await
					.ok()?
					.read_to_string(&mut s)
					.await
					.ok()?;

				let title_re = Regex::new(r"(?ms)<title>(?P<title>.*)</title>").unwrap();
				let content_re = Regex::new(r"(?ms)<article>(?P<content>.*)</article>").unwrap();
				Some(Self {
					file: path.strip_prefix(Self::STORAGE).unwrap().to_path_buf(),
					title: title_re
						.captures(&s)?
						.name("title")
						.unwrap()
						.as_str()
						.to_string(),
					content: content_re
						.captures(&s)?
						.name("content")
						.unwrap()
						.as_str()
						.to_string(),
				})
			})
			.collect()
			.await)
	}
}
impl PartialEq for Article {
	fn eq(&self, other: &Self) -> bool {
		self.file == other.file
	}
}
impl Hash for Article {
	fn hash<H: Hasher>(&self, hasher: &mut H) {
		self.file.hash(hasher);
	}
}

#[options("/article")]
async fn options_article() -> OptionsResponder<Vec<Method>> {
	use rocket::http::Method;

	OptionsResponder(vec![Method::Get, Method::Post])
}

#[get("/article")]
async fn articles(articles: &State<Mutex<HashSet<Article>>>) -> Json<Vec<Article>> {
	Json(articles.lock().await.iter().cloned().collect())
}

#[post("/article", data = "<article>")]
async fn new_article(
	auth: Authorization,
	articles: &State<Mutex<HashSet<Article>>>,
	article: Json<Article>,
) -> Result<Status, AuthorizationResponder> {
	if auth.is_err() {
		Err(AuthorizationResponder(auth))
	} else {
		let article = article.into_inner();
		let mut path = PathBuf::from(Article::STORAGE).join(&article.file); //NOTE: Path traversal vulnerable
		path.set_extension("html.hbs");
		let mut articles = articles.lock().await;
		Ok(tokio::fs::write(path, format!(//NOTE: DOM injection vulnerable
			r#"<!DOCTYPE html><html><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>{title}</title><link rel="stylesheet" href="/index.css" /></head><body>{{{{> header}}}}<main><article><h1>{title}</h1>{content}</article></main></body></html>"#,
			title = &article.title,
			content = &article.content,
		)).await
			.map(|()| {
				articles.insert(article.clone());
				Status::Created
			})
			.unwrap_or(Status::InternalServerError))
	}
}

#[repr(transparent)]
struct LoginResponder(Session);
impl<'r> Responder<'r, 'static> for LoginResponder {
	fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
		use rocket::http::{Cookie, SameSite};

		let mut cookie = Cookie::new(
			Session::COOKIE,
			serde_json::to_string(&self.0).map_err(|_err| Status::InternalServerError)?,
		);
		cookie.set_path("/");
		cookie.set_same_site(SameSite::Strict);
		cookie.set_secure(true);
		req.cookies().add_private(cookie);

		Redirect::to("/profile").respond_to(req)
	}
}

#[derive(FromForm)]
struct SignForm<'s> {
	username: &'s str,
	password: &'s str,
}

fn print_bytes(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(2 * bytes.len());
	for b in bytes {
		s += &format!("{:x}", *b);
	}
	s
}

#[post("/login", data = "<form>")]
async fn login(
	conn: crate::DbConnection,
	sessions: &State<Mutex<Sessions>>,
	form: Form<SignForm<'_>>,
) -> Result<LoginResponder, Status> {
	use rand::{rngs::OsRng, RngCore};
	use sha2::{Digest, Sha256};

	let username = form.username.to_string();
	let password = {
		let mut hasher = Sha256::default();
		hasher.update(form.password.as_bytes());
		hasher.finalize()
	};
	let username: String = conn
		.run(move |db| {
			db.query_row(
				&format!(
					"SELECT username FROM users WHERE username='{username}' AND password='{password}'", //NOTE: SQL injection vulnerable
					username = username,
					password = print_bytes(password.as_slice()),
				),
				[],
				|row| row.get(0),
			)
		})
		.await
		.map_err(|_err| Status::Unauthorized)?;

	let mut sessions = sessions.lock().await;
	let key = format!("{:x}", OsRng::default().next_u64());
	sessions.insert(key.clone(), username.clone());

	Ok(LoginResponder(Session {
		auth_key: key,
		username,
	}))
}

#[post("/register", data = "<form>")]
async fn register(
	conn: crate::DbConnection,
	sessions: &State<Mutex<Sessions>>,
	form: Form<SignForm<'_>>,
) -> Result<LoginResponder, Status> {
	use sha2::{Digest, Sha256};

	let username = form.username.to_string();
	let password = {
		let mut hasher = Sha256::default();
		hasher.update(form.password.as_bytes());
		hasher.finalize()
	};
	conn.run(move |db| {
		db.execute(
			"INSERT INTO users (username, password) VALUES (?1, ?2)",
			params![username, print_bytes(password.as_slice())],
		)
	})
	.await
	.map_err(|_err| Status::BadRequest)?;
	login(conn, sessions, form).await
}

pub(crate) fn routes() -> Vec<Route> {
	routes![options_article, articles, new_article, register, login]
}
