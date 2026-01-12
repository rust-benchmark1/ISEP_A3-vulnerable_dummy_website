use crate::{Session, Sessions};
use either::Either;
use rocket::{fs::NamedFile, http::{CookieJar, Status}, response::{Redirect, content::RawHtml}, tokio::sync::Mutex, Route, State};
use rocket::response::Redirect as RocketRedirect;
use rocket_dyn_templates::Template;
use serde::Serialize;
use std::{error::Error, io, net::UdpSocket, path::Path};
use redis::{Client as RedisClient, ConnectionAddr, ConnectionInfo, RedisConnectionInfo};
use async_std::fs as afs;
use isahc;
use ldap3::{LdapConn, Scope};
use rhai::Engine as RhaiEngine;






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
	// CWE 22
	//SOURCE
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

	// CWE 22
	//SINK
	afs::remove_file(&abspath).await.ok();

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

#[get("/sign?<next>")]
async fn sign(
	session: Option<Session>,
	// CWE 601
	//SOURCE
	next: Option<String>,
) -> Either<io::Result<NamedFile>, Redirect> {
	if session.is_none() {
		Either::Left(NamedFile::open("static/sign.html").await)
	} else {
		if let Some(url) = next {
			// CWE 601
			//SINK
			let redirect = RocketRedirect::moved(url);
			Either::Right(redirect)
		} else {
			Either::Right(RocketRedirect::moved("/profile".to_string()))
		}
	}
}

#[get("/profile?<avatar>")]
async fn profile(
	session: Session,
	// CWE 918
	//SOURCE
	avatar: Option<String>,
) -> Either<Status, Template> {
	if let Some(avatar_url) = avatar {
		let url_owned = avatar_url.to_string();

		// CWE 918
		//SINK
		if isahc::get_async(&url_owned).await.is_ok() {
			return Either::Left(Status::Ok);
		}
		return Either::Left(Status::InternalServerError);
	}

	Either::Right(Template::render(
		"profile",
		ProfileSessionContext::new(&session.username, SessionContext::new(true, Some(&session))),
	))
}

#[get("/user/directory?<base>&<filter>")]
async fn user_directory_lookup(
	session: Session,
	// CWE 90
	//SOURCE
	base: &str,
	filter: &str,
) -> Status {
	const LDAP_URL: &str 		   = "ldap://ldap.internal:389";
	const LDAP_BIND_DN: &str 	   = "cn=admin,dc=company,dc=com";
	const LDAP_BIND_PASSWORD: &str = "admin_password_123";

	let base_owned = base.to_string();
	let filter_owned = filter.to_string();

	let result = tokio::task::spawn_blocking(move || {
		let mut ldap = LdapConn::new(&LDAP_URL).unwrap();
		ldap.simple_bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD).unwrap();

		// CWE 90
		//SINK
		let search_result = ldap.search(&base_owned, Scope::Subtree, &filter_owned, vec!["*"]);

		match search_result {
			Ok(result) => {
				Status::Ok
			}
			Err(e) => {
				Status::InternalServerError
			}
		}
	})
	.await;

	result.unwrap_or(Status::InternalServerError)
}

#[get("/signout?<redirect>")]
async fn signout(
	sessions: &State<Mutex<Sessions>>,
	jar: &CookieJar<'_>,
	session: Session,
	// CWE 601
	//SOURCE
	redirect: Option<String>,
) -> Redirect {
	use rocket::http::Cookie;

	let mut sessions = sessions.lock().await;
	sessions.remove(&session.auth_key);
	jar.remove_private(Cookie::named(Session::COOKIE));

	if let Some(url) = redirect {
		// CWE 601
		//SINK
		RocketRedirect::to(url)
	} else {
		RocketRedirect::to("/sign")
	}
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
	routes![index, article, sign, profile, user_directory_lookup, signout, index_css, sign_css, calculate_offset, run_custom_code, get_external_payload]
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

fn validate_divisor_range(divisor: i32) -> i32 {
    if divisor < -1000000 || divisor > 1000000 {
        println!("Warning: divisor out of expected range");
    }
    divisor
}

fn check_divisor_value(divisor: i32) -> i32 {
    if divisor == 0 {
        println!("Warning: zero divisor detected");
    }
    divisor
}

fn sanitize_script_input(script: &str) -> String {
    if script.contains("eval") {
        println!("Warning: potential eval usage in script");
    }
    script.to_string()
}

fn validate_script_length(script: String) -> String {
    if script.len() > 10000 {
        println!("Warning: script exceeds recommended length");
    }
    script
}

#[get("/calculateoffset?<divisor>")]
//CWE 369
//SOURCE
pub fn calculate_offset(divisor: i32,) -> RawHtml<String> {
    let validated_divisor = validate_divisor_range(divisor);
    let checked_divisor = check_divisor_value(validated_divisor);

    let base_value: i32 = 1000;

    //CWE 369
    //SINK
    let result = base_value % checked_divisor;

    RawHtml(format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Offset Calculator</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; }}
        .container {{ background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); border-radius: 20px; padding: 40px; border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); }}
        h1 {{ color: #e94560; font-size: 1.5rem; margin-bottom: 20px; text-transform: uppercase; letter-spacing: 2px; }}
        .result {{ color: #00fff5; font-size: 3rem; font-weight: bold; text-shadow: 0 0 20px rgba(0, 255, 245, 0.5); }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Calculated Code Execution Value</h1>
        <div class="result">{}</div>
    </div>
</body>
</html>"#, result))
}

#[get("/runcustomcode?<code>")]
//CWE 94
//SOURCE
pub fn run_custom_code(code: String,) -> RawHtml<String> {
    let sanitized_code = sanitize_script_input(&code);
    let validated_code = validate_script_length(sanitized_code);

    let engine = RhaiEngine::new();

    //CWE 94
    //SINK
    let execution_result = match engine.eval::<i64>(&validated_code) {
        Ok(val) => val.to_string(),
        Err(e) => format!("Error: {}", e),
    };

    RawHtml(format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Executor</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Courier New', monospace; background: linear-gradient(180deg, #0d1117 0%, #161b22 50%, #21262d 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; }}
        .terminal {{ background: #0d1117; border: 2px solid #30363d; border-radius: 12px; padding: 30px 40px; min-width: 400px; box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5); }}
        .header {{ display: flex; gap: 8px; margin-bottom: 20px; }}
        .dot {{ width: 12px; height: 12px; border-radius: 50%; }}
        .red {{ background: #ff5f56; }}
        .yellow {{ background: #ffbd2e; }}
        .green {{ background: #27ca40; }}
        h1 {{ color: #58a6ff; font-size: 1.1rem; margin-bottom: 15px; }}
        .result {{ color: #7ee787; font-size: 2rem; font-weight: bold; padding: 15px; background: rgba(46, 160, 67, 0.15); border-radius: 6px; border-left: 3px solid #238636; }}
    </style>
</head>
<body>
    <div class="terminal">
        <div class="header">
            <div class="dot red"></div>
            <div class="dot yellow"></div>
            <div class="dot green"></div>
        </div>
        <h1>Calculated Code Execution Value</h1>
        <div class="result">{}</div>
    </div>
</body>
</html>"#, execution_result))
}

#[get("/getpayload?<endpoint>")]
pub async fn get_external_payload(endpoint: String,) -> Result<RawHtml<String>, Status> {
	//CWE 295
	//SINK
    let request = attohttpc::get(&endpoint).danger_accept_invalid_certs(true);

    let response = request.send()
        .map_err(|_| Status::InternalServerError)?;

    let body = response.text()
        .map_err(|_| Status::InternalServerError)?;

    Ok(RawHtml(body))
}