use crate::{Session, Sessions};
use either::Either;
use rocket::{
	fs::NamedFile,
	http::{CookieJar, Status},
	response::Redirect,
	tokio::sync::Mutex,
	Route, State,
};
use rocket_dyn_templates::Template;
use serde::Serialize;
use std::{error::Error, io, net::UdpSocket, path::Path};
use redis::{Client as RedisClient, ConnectionAddr, ConnectionInfo, RedisConnectionInfo};

#[derive(Serialize)]
struct SessionContext<'s> {
	href: &'static str,
	link: &'s str,
}
impl<'s> SessionContext<'s> {
	pub fn new(path_is_profile: bool, session: Option<&'s Session>) -> Self {
		session
			.map(|session| {
				if path_is_profile {
					Self {
						href: "/signout",
						link: "Sign out",
					}
				} else {
					Self {
						href: "/profile",
						link: &session.username,
					}
				}
			})
			.unwrap_or(Self {
				href: "/sign",
				link: "Sign in/up",
			})
	}
}

#[derive(Serialize)]
struct ProfileSessionContext<'s> {
	inner: SessionContext<'s>,
	name: &'s str,
}
impl<'s> ProfileSessionContext<'s> {
	pub fn new(name: &'s str, inner: SessionContext<'s>) -> Self {
		Self { inner, name }
	}
}

#[get("/")]
async fn index(session: Option<Session>) -> Template {
	Template::render("index", SessionContext::new(false, session.as_ref()))
}

#[get("/article?<file>")]
async fn article(
	session: Option<Session>,
	file: &str,
) -> Result<Either<Template, io::Result<NamedFile>>, Status> {
	let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
	let mut buf = [0u8; 256];

	// CWE 943
	//SOURCE
	let (amt, _src) = socket.recv_from(&mut buf).unwrap();
	let pattern 	= String::from_utf8_lossy(&buf[..amt]).to_string();

	redis_articles(pattern);

	// NOTE: Path traversal vulnerable
	let template = format!("articles/{file}");
	let abspath = format!("./static/{template}");
	if Path::new(&abspath).exists() {
		if let Some(template) = template.strip_suffix(".html.hbs") {
			Ok(Either::Left(Template::render(
				String::from(template),
				SessionContext::new(false, session.as_ref()),
			)))
		} else {
			Ok(Either::Right(NamedFile::open(abspath).await))
		}
	} else {
		Err(Status::NotFound)
	}
}

#[get("/sign")]
async fn sign(session: Option<Session>) -> Either<io::Result<NamedFile>, Redirect> {
	if session.is_none() {
		Either::Left(NamedFile::open("static/sign.html").await)
	} else {
		Either::Right(Redirect::to("/profile"))
	}
}

#[get("/profile")]
async fn profile(session: Session) -> Template {
	Template::render(
		"profile",
		ProfileSessionContext::new(&session.username, SessionContext::new(true, Some(&session))),
	)
}

#[get("/signout")]
async fn signout(
	sessions: &State<Mutex<Sessions>>,
	jar: &CookieJar<'_>,
	session: Session,
) -> Redirect {
	use rocket::http::Cookie;

	let mut sessions = sessions.lock().await;
	sessions.remove(&session.auth_key);
	jar.remove_private(Cookie::named(Session::COOKIE));

	Redirect::to("/sign")
}

#[get("/index.css")]
async fn index_css() -> io::Result<NamedFile> {
	NamedFile::open("static/index.css").await
}

#[get("/sign.css")]
async fn sign_css() -> io::Result<NamedFile> {
	NamedFile::open("static/sign.css").await
}

pub(crate) fn routes() -> Vec<Route> {
	routes![index, article, sign, profile, signout, index_css, sign_css]
}

fn save_user_session(sessions: &mut Sessions, session: &Session) {
	sessions.insert(session.auth_key.clone(), session.username.clone());
}

fn redis_articles(pattern: String) {
    let client = redis_connection().ok();
    if let Some(client) = client {
        if let Ok(mut con) = client.get_connection() {

            // CWE 943
            //SINK
            let _result: redis::RedisResult<Vec<String>> = redis::cmd("ARTICLES").arg(&pattern).query(&mut con);
        }
    }
}

/// Redis client connection
fn redis_connection() -> Result<RedisClient, Box<dyn Error>> {
    let hardcoded_user = "user_admin";
    // CWE 798
    //SOURCE
    let hardcoded_pass = "redis@dmin_password_1234";

    let addr = ConnectionAddr::Tcp("redis.internal".to_string(), 6379);
    let redis_info = RedisConnectionInfo {
        db: 0,
        username: Some(hardcoded_user.to_string()),
        password: Some(hardcoded_pass.to_string()),
    };

    let connection_info = ConnectionInfo {
        addr: addr,
        redis: redis_info,
    };

    // CWE 798
    //SINK
    let redis_client = RedisClient::open(connection_info)?;

    Ok(redis_client)
}