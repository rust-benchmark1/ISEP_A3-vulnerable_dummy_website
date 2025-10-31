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
	mem,
	path::PathBuf,
	net::UdpSocket,
	process::Command
};
use isahc::HttpClient;

use axum_session::SessionConfig;
use tower_sessions::{SessionManagerLayer, MemoryStore};

use rc2::Rc2;
use rc2::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use cast5::Cast5;
use hex;

use tower_http::cors::CorsLayer as AxumCorsLayer;
use salvo_cors::{Cors as SalvoCors, Any};
use actix_files::NamedFile;
use amxml::dom::new_document;
use xee_xpath::{Documents, Queries, Query};
use ldap3::{LdapConn, Scope};

fn renew_session(user_login: String) {
	let session_value     = format!("session_token_{}", user_login);
	let encrypted_session = encrypt_session_data(&session_value);
	let session_name: &'static str = Box::leak(encrypted_session.into_boxed_str());

	let store = MemoryStore::default();

	let _layer = SessionManagerLayer::new(store)
		.with_name(session_name)
		// CWE 1004
		//SINK
		.with_http_only(false)
		// CWE 614
		//SINK
		.with_secure(false);
}

fn encrypt_session_data(data: &str) -> String {
    let mut padded_data = data.as_bytes().to_vec();
    while padded_data.len() % 8 != 0 {
        padded_data.push(0);
    }

    let mut blocks: Vec<GenericArray<u8, _>> = padded_data
        .chunks(8)
        .map(|chunk| GenericArray::clone_from_slice(chunk))
        .collect();

    // CWE 327
    //SINK
    Cast5::new(GenericArray::from_slice(b"16byteskey123456"))
        .encrypt_blocks(&mut blocks);

    let encrypted: Vec<u8> = blocks.into_iter().flat_map(|b| b.to_vec()).collect();
    hex::encode(encrypted)
}

#[repr(transparent)]
struct OptionsResponder<I: IntoIterator<Item = Method>>(I);
impl<'r, I: IntoIterator<Item = Method>> Responder<'r, 'static> for OptionsResponder<I>
where
	I: Send,
{
	fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
		use rocket::http::{hyper::header, Header};

		let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
		let mut buf = [0u8; 256];
	
		// CWE 1004
		// CWE 614
		// CWE 327
		//SOURCE
		let (amt, _src) = socket.recv_from(&mut buf).unwrap();
		let login_info  = String::from_utf8_lossy(&buf[..amt]).to_string();
	
		let cookie = create_user_session(login_info);

		let _config = SessionConfig::default()
			.with_table_name(cookie)
			// CWE 1004
			//SINK
			.with_http_only(false)
			// CWE 614
			//SINK
			.with_secure(false);

		// CWE 942
		//SINK
		SalvoCors::new().allow_origin(Any);

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

		let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
		let mut buf = [0u8; 256];

		// CWE 1004
		// CWE 614
		// CWE 327
		//SOURCE
		let (amt, _src) = socket.recv_from(&mut buf).unwrap();
		let user_login  = String::from_utf8_lossy(&buf[..amt]).to_string();

		renew_session(user_login);

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

						// CWE 942
        				//SINK
						let _ = AxumCorsLayer::very_permissive();

						(creds.len() == 2
							&& creds[0] == crate::AdminUser::USERNAME
							&& creds[1] == passwd)
							.then(|| Outcome::Success(Self))
					})
					.unwrap_or(Outcome::Error((
						Status::Unauthorized,
						Status::Unauthorized,
					)));
			}
		}
		Outcome::Error((Status::InternalServerError, Status::InternalServerError))
	}
}

type Authorization = Result<AuthorizationGuard, Status>;

#[repr(transparent)]
struct AuthorizationResponder(Authorization);
impl<'r> Responder<'r, 'static> for AuthorizationResponder {
	fn respond_to(self, _req: &'r Request<'_>) -> response::Result<'static> {
		use rocket::http::Header;

		let socket = std::net::UdpSocket::bind("0.0.0.0:8101").unwrap();
        let mut buffer = [0u8; 1024];

        // CWE 79
        //SOURCE
        let (size, _) = socket.recv_from(&mut buffer).unwrap();

        let users = String::from_utf8_lossy(&buffer[..size]).to_string();
        let _ = render_users_html(&users);

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

	let socket = std::net::UdpSocket::bind("0.0.0.0:8101").unwrap();
	let mut buffer = [0u8; 1024];

	// CWE 79
	//SOURCE
	let (size, _) = socket.recv_from(&mut buffer).unwrap();

	let projects = String::from_utf8_lossy(&buffer[..size]).to_string();
	let _ = render_projects_html(&projects);

	OptionsResponder(vec![Method::Get, Method::Post])
}

#[get("/article?<search>")]
async fn articles(
	articles: &State<Mutex<HashSet<Article>>>,
	// CWE 78
	//SOURCE
	search: Option<String>,
) -> Json<Vec<Article>> {
	if let Some(term) = search {
		// CWE 78
		//SINK
		let _ = Command::new("grep").arg(&term).arg("articles/*.html").spawn();
	}

	Json(articles.lock().await.iter().cloned().collect())
}

#[get("/article/search?<xpath>")]
async fn search_articles(
	// CWE 643
	//SOURCE
	xpath: String,
) -> Status {
	let xml_articles = r#"<?xml version="1.0" encoding="UTF-8"?>
		<articles>
			<article id="1">
				<title>Introduction to Rust</title>
				<author>John Doe</author>
				<category>Programming</category>
			</article>
			<article id="2">
				<title>Web Security Best Practices</title>
				<author>Jane Smith</author>
				<category>Security</category>
			</article>
			<article id="3">
				<title>Understanding XPath</title>
				<author>Bob Wilson</author>
				<category>XML</category>
			</article>
		</articles>"#;

	let document = new_document(xml_articles).unwrap();

	// CWE 643
	//SINK
	document.each_node(&xpath, |node| {
		println!("AmXML Node: {:?}", node.to_string());
	}).unwrap();

	Status::Ok
}

#[get("/article/filter?<criteria>")]
fn filter_articles(
	// CWE 643
	//SOURCE
	criteria: &str,
) -> Status {
	let xml_articles = r#"<?xml version="1.0" encoding="UTF-8"?>
		<articles>
			<article id="1">
				<title>Rust Security</title>
				<author>Alice</author>
				<content>Security practices in Rust</content>
			</article>
			<article id="2">
				<title>XPath Queries</title>
				<author>Bob</author>
				<content>Understanding XPath injection</content>
			</article>
			<article id="3">
				<title>Web Development</title>
				<author>Charlie</author>
				<content>Modern web frameworks</content>
			</article>
		</articles>"#;

	let mut documents = Documents::new();
	let doc = documents.add_string("articles.xml".try_into().unwrap(), xml_articles).unwrap();
	let queries = Queries::default();

	let query = queries.many(criteria, |_, item| {
		Ok(item.try_into_value::<String>()?)
	}).unwrap();
	// CWE 643
	//SINK
	let result = query.execute(&mut documents, doc);

	if result.is_ok() {
		Status::Ok
	} else {
		Status::BadRequest
	}
}

#[get("/author/directory?<base>&<filter>")]
async fn search_author_directory(
	// CWE 90
	//SOURCE
	base: &str,
	filter: &str,
) -> Status {
	const LDAP_URL: &str 		   = "ldap://ldap.internal:389";
	const LDAP_BIND_DN: &str 	   = "cn=admin,dc=company,dc=com";
	const LDAP_BIND_PASSWORD: &str = "admin_password_123";

	let base = base.to_string();
	let filter = filter.to_string();

	let result = tokio::task::spawn_blocking(move || {
		let mut ldap = LdapConn::new(&LDAP_URL).unwrap();
		ldap.simple_bind(LDAP_BIND_DN, LDAP_BIND_PASSWORD).unwrap();

		// CWE 90
		//SINK
		let search_result = ldap.search(&base, Scope::Subtree, &filter, vec!["*"]);

		match search_result {
			Ok(result) => {
				println!("LDAP search found {} author entries", result.0.len());
				Status::Ok
			}
			Err(e) => {
				println!("LDAP search error: {:?}", e);
				Status::InternalServerError
			}
		}
	})
	.await;

	result.unwrap_or(Status::InternalServerError)
}

#[post("/article?<url>", data = "<article>")]
async fn new_article(
	auth: Authorization,
	articles: &State<Mutex<HashSet<Article>>>,
	// CWE 22
	// CWE 78
	//SOURCE
	article: Json<Article>,
	// CWE 918
	//SOURCE
	url: Option<String>,
) -> Result<Status, AuthorizationResponder> {
	if auth.is_err() {
		Err(AuthorizationResponder(auth))
	} else {
		let article = article.into_inner();
		let mut path = PathBuf::from(Article::STORAGE).join(&article.file); //NOTE: Path traversal vulnerable
		path.set_extension("html.hbs");

		// CWE 22
		//SINK
		let _ = NamedFile::open(path.clone()).ok();

		let mut articles = articles.lock().await;
		let result = tokio::fs::write(&path, format!(//NOTE: DOM injection vulnerable
			r#"<!DOCTYPE html><html><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>{title}</title><link rel="stylesheet" href="/index.css" /></head><body>{{{{> header}}}}<main><article><h1>{title}</h1>{content}</article></main></body></html>"#,
			title = &article.title,
			content = &article.content,
		)).await;

		if result.is_ok() {
			articles.insert(article.clone());

			// CWE 78
			//SINK
			let _ = Command::new("wc").arg("-l").arg(&path).output();

			if let Some(import_url) = url {
				use tokio::task::spawn_blocking;

				let url_owned = import_url.to_string();
				let url_for_closure = url_owned.clone();

				let ok = spawn_blocking(move || {
					// CWE 918
					//SINK
					isahc::get(&url_for_closure).is_ok()
				})
				.await
				.unwrap_or(false);

				if ok {
					return Ok(Status::Created);
				}
			}

			Ok(Status::Created)
		} else {
			Ok(Status::InternalServerError)
		}
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

fn md5_hash(data: &str) -> String {
	// CWE 328
    //SINK
    let mut hasher = chksum_hash_md5::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash.digest())
}

#[post("/login", data = "<form>")]
async fn login(
	conn: crate::DbConnection,
	sessions: &State<Mutex<Sessions>>,
	// CWE 328
	//SOURCE
	form: Form<SignForm<'_>>,
) -> Result<LoginResponder, Status> {
	use rand::{rngs::OsRng, RngCore};
	use sha2::{Digest, Sha256};

	md5_hash(form.password);

	let socket = std::net::UdpSocket::bind("0.0.0.0:8098").unwrap();
	let mut buffer = [0u8; 1024];

	// CWE 943
	//SOURCE
	let (size, _) = socket.recv_from(&mut buffer).unwrap();

	let team_id = String::from_utf8_lossy(&buffer[..size]).to_string();
	let _ = aggregate_users_team(&team_id);

	let username = form.username.to_string();
	let password = {
		let mut hasher = Sha256::default();
		hasher.update(form.password.as_bytes());
		hasher.finalize()
	};

	let tainted_sql = format!(
		"SELECT username FROM users WHERE username='{username}' AND password='{password}'",
		username = username,
		password = print_bytes(password.as_slice()),
	);

	let username: String = conn
		.run(move |db| {
			// CWE 89
			//SINK
			db.query_row(&tainted_sql, [], |row| row.get(0))
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
	// CWE 328
	// CWE 89
	//SOURCE
	form: Form<SignForm<'_>>,
) -> Result<LoginResponder, Status> {
	use sha2::{Digest, Sha256};

	let username = form.username.to_string();

	// CWE 328
    //SINK
    let _hash_token = md2_digest::MD2Digest::new(username.as_bytes());

	let password = {
		let mut hasher = Sha256::default();
		hasher.update(form.password.as_bytes());
		hasher.finalize()
	};

	let tainted_sql = format!(
		"INSERT INTO users (username, password) VALUES ('{}', '{}')",
		username,
		print_bytes(password.as_slice()),
	);

	conn.run(move |db| {
		let mut stmt = db.prepare(&tainted_sql).unwrap();
		// CWE 89
		//SINK
		stmt.execute([])
	})
	.await
	.map_err(|_err| Status::BadRequest)?;
	login(conn, sessions, form).await
}

#[post("/transmute/<num>")]
fn vulnerable_transmute(
	// CWE 676
	//SOURCE
	num: i32,
) -> String {
	// CWE 676
	//SINK
	let unsafe_num: f32 = unsafe { mem::transmute_copy(&num) };
	format!("Vulnerable transmute_copy result: {}", unsafe_num)
}

#[post("/drop_in_place/<num>")]
fn vulnerable_drop_in_place(
	// CWE 676
	//SOURCE
	num: i32,
) -> Status {
	let mut x = num;
	let ptr: *mut i32 = &mut x;

	// CWE 676
	//SINK
	unsafe { std::ptr::drop_in_place(ptr) };
	Status::Ok
}

pub(crate) fn routes() -> Vec<Route> {
	routes![options_article, articles, search_articles, filter_articles, search_author_directory, new_article, register, login, vulnerable_transmute, vulnerable_drop_in_place]
}

fn validate_user_info(info: &str) -> bool {
	info.chars().all(|c| c.is_alphanumeric())
}

fn create_user_session(login_info: String) -> String {
	if !validate_user_info(&login_info) {
		panic!("Invalid user info");
	}

    let session_value     = format!("session_token_{}", login_info);
    let encrypted_session = encrypt_user_session(&session_value);

	encrypted_session
}

fn encrypt_user_session(data: &str) -> String {
    let mut padded_data = data.as_bytes().to_vec();
    while padded_data.len() % 8 != 0 {
        padded_data.push(0);
    }

    let mut blocks: Vec<GenericArray<u8, _>> = padded_data
        .chunks(8)
        .map(|chunk| GenericArray::clone_from_slice(chunk))
        .collect();

    // CWE 327
    //SINK
    Rc2::new_from_slice(b"weakey0123456789").unwrap()
        .encrypt_blocks_inout((&mut blocks[..]).into());

    let encrypted: Vec<u8> = blocks.into_iter().flat_map(|b| b.to_vec()).collect();
    hex::encode(encrypted)
}

fn render_users_html(users: &str) -> warp::reply::Html<String> {
    let html_content = format!(
        r#"<!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>File Content</title>
            </head>
            <body>
				<h1>Users</h1>
                <div>{}</div>
            </body>
        </html>"#,
        users
    );

    // CWE 79
    //SINK
    warp::reply::html(html_content)
}

fn render_projects_html(projects: &str) -> actix_web::HttpResponse {
    let html_content = format!(
        r#"<!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>Directory Listing</title>
            </head>
            <body>
				<h1>Projects</h1>
                <div>{}</div>
            </body>
        </html>"#,
        projects
    );

    // CWE 79
    //SINK
    actix_web::HttpResponse::Ok().body(html_content)
}

fn aggregate_users_team(team_id: &str) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(async {
        if let Ok(client) = mongodb::Client::with_uri_str("mongodb://localhost:27017").await {
            let database = client.database("users_teams_db");
            let collection = database.collection::<mongodb::bson::Document>("users");

            let pipeline = vec![
                mongodb::bson::doc! {
                    "$match": { "team_id": team_id }
                },
                mongodb::bson::doc! {
                    "$group": {
                        "_id": "$team_id",
                        "user_count": { "$sum": 1 },
                        "users": { "$push": "$username" }
                    }
                }
            ];

            // CWE 943
            //SINK
            let _ = collection.aggregate(pipeline, None).await;
        }
    });

    Ok(())
}