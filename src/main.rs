#![deny(unused_must_use)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate async_recursion;
use rocket::{
	http::Status,
	request::{FromRequest, Outcome},
	Request,
};
use rocket_sync_db_pools::{database, rusqlite::Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod www {
	mod api;
	mod r#static;

	pub(crate) use api::routes as api_routes;
	pub(crate) use api::Article;
	pub(crate) use r#static::routes as static_routes;
}

#[database("sqlite")]
#[repr(transparent)]
struct DbConnection(Connection);

#[derive(Serialize, Deserialize)]
struct User {
	pub username: String,
}

struct AdminUser;
impl AdminUser {
	pub const USERNAME: &'static str = "admin";
}
#[async_trait]
impl<'r> FromRequest<'r> for AdminUser {
	type Error = ();

	async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		req.guard::<Session>().await.and_then(|session| {
			if session.username == Self::USERNAME {
				Outcome::Success(Self)
			} else {
				Outcome::Failure((Status::Unauthorized, ()))
			}
		})
	}
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Session {
	pub auth_key: String,
	pub username: String,
}
impl Session {
	pub const COOKIE: &'static str = "session";
}
#[async_trait]
impl<'r> FromRequest<'r> for Session {
	type Error = ();

	async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		use rocket::{tokio::sync::Mutex, State};

		if let Some(req_session) = req
			.cookies()
			.get_private(Session::COOKIE)
			.and_then(|cookie| serde_json::from_str::<Session>(cookie.value()).ok())
		{
			let sessions = req
				.guard::<&State<Mutex<Sessions>>>()
				.await
				.unwrap()
				.lock()
				.await;
			if let Some(username) = sessions.get(&req_session.auth_key) {
				if username == &req_session.username {
					return Outcome::Success(req_session);
				}
			}
		}
		Outcome::Failure((Status::Unauthorized, ()))
	}
}

type Sessions = HashMap<String, String>;

#[tokio::main]
async fn main() -> Result<(), rocket::Error> {
	use rocket::{shield::Shield, tokio::sync::Mutex};
	use rocket_dyn_templates::Template;

	let sessions = Sessions::new();
	let articles = www::Article::index_all()
		.await
		.map_err(|err| rocket::Error::from(rocket::error::ErrorKind::Io(err)))?;

	rocket::build()
		.attach(Shield::new())
		.attach(DbConnection::fairing())
		.attach(Template::fairing())
		.manage(Mutex::new(sessions))
		.manage(Mutex::new(articles))
		.mount("/", www::static_routes())
		.mount("/api", www::api_routes())
		.launch()
		.await
}
