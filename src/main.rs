#[path = "auth.rs"] mod auth;

extern crate queues;

use queues::*;
use std::{collections::HashMap, str::FromStr, sync::{Arc, Mutex}};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web_actors::ws::{self, WebsocketContext};
use auth::ApplicationAuth;
use chrono::Utc;
use lazy_static::lazy_static;
use actix_web::{cookie::Key, delete, dev::{self, Service, ServiceRequest}, get, http::{header::{self, HeaderName, HeaderValue}, Error, StatusCode}, middleware::{self, ErrorHandlerResponse, ErrorHandlers}, post, put, web::{self, Header}, App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder};
use mongodb::{bson::{doc, document, Bson, Document, RawArray}, options::ClientOptions, Client};
use paris::{error, info}; 
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use actix::{Actor, StreamHandler};

lazy_static! {
  static ref DATABASE_CLIENT: Mutex<Option<Client>> = Mutex::new(None);
  static ref ADMIN_TOKEN: Arc<String> = Arc::new(std::env::var("ADMIN_TOKEN").unwrap());
  static ref PERMISSION: HashMap<u8, String> = HashMap::from([
    (0, "create_one_record".to_string()),
    (1, "read_one_record".to_string()),
    (2, "update_one_record".to_string()),
    (3, "delete_one_record".to_string()),
  ]);
  static ref ACTIVE_SOCKET_CONNECTIONS: Arc<Mutex<i16>> = Arc::new(Mutex::new(0));
  static ref INSERT_HISTORY: Arc<Mutex<Queue<(String, String)>>> = Arc::new(Mutex::new(Queue::new()));
}

#[derive(Deserialize, Serialize)]
struct CreateApplication {
  pub name: String,
  pub permissions: Vec<u8>
}


#[derive(Deserialize, Serialize)]
struct CreatedApplication {
  pub name: String,
  pub application_id: String,
  pub permissions: Vec<u8>
}


#[derive(Deserialize, Serialize, Debug, Clone)]
struct UpdateAtRecord {
  pub updated_at: i64,
  pub data: HashMap<String, Value>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct InsertedData {
  pub application_id: String,
  pub time: i64,
  pub updated_at: Option<i64>,
  pub updated_history: Option<Vec<UpdateAtRecord>>,
  pub id: String,
  pub data: HashMap<String, Value>,
  pub version: i64
}

struct EmitterSocket;

impl Actor for EmitterSocket {
  type Context = ws::WebsocketContext<Self>;
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for EmitterSocket {
  fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
    match msg {
      Ok(ws::Message::Text(text)) => {
        let message = text.to_string();
        let message = message.as_str();

        match message {
          "queue.peek" => {
            let mut peeker = INSERT_HISTORY.lock().unwrap();
            let peek = peeker.peek();

            if peek.is_err() {
              ctx.text(serde_json::to_string(&json!({
                "error": "Not found",
                "message": "Data cannot be peeked"
              })).unwrap());

              return;
            }

            ctx.text(serde_json::to_string(&json!({
              "message": peek.unwrap()
            })).unwrap());

            peeker.remove().unwrap();
          },
          _ => ()
        }
      }
      _ => (),
    }
  }

  fn started(&mut self, ctx: &mut WebsocketContext<EmitterSocket>) {
    info!("New peer connected at '{}'", Utc::now());
    *ACTIVE_SOCKET_CONNECTIONS.lock().unwrap() += 1;
  }

  fn finished(&mut self, ctx: &mut WebsocketContext<EmitterSocket>) {
    info!("Peer disconnected at '{}'", Utc::now());
    *ACTIVE_SOCKET_CONNECTIONS.lock().unwrap() -= 1;
  }

}

impl StreamHandler<Result<ws::CloseReason, ws::ProtocolError>> for EmitterSocket {
  fn handle(&mut self, msg: Result<ws::CloseReason, ws::ProtocolError>, ctx: &mut Self::Context) {
      println!("disconnected: {:?}", msg);
      *ACTIVE_SOCKET_CONNECTIONS.lock().unwrap() -= 1;
  }
}

impl StreamHandler<Result<ws::CloseCode, ws::ProtocolError>> for EmitterSocket {
  fn handle(&mut self, msg: Result<ws::CloseCode, ws::ProtocolError>, ctx: &mut Self::Context) {
      println!("disconnected: {:?}", msg);
      *ACTIVE_SOCKET_CONNECTIONS.lock().unwrap() -= 1;
  }
}

async fn realtime_emitter(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, actix_web::Error> {
  let resp = ws::start(EmitterSocket {}, &req, stream);
  let token = auth::get_bearer_token(req);

  if token.is_none() {
    return Ok(HttpResponse::Unauthorized().body(""));
  }

  resp
}

#[get("/applications")]
async fn get_applications(req: HttpRequest) -> impl Responder {
  let token = auth::get_bearer_token(req);

  if token.is_none() {
    return HttpResponse::Unauthorized().body("");
  }

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();
  
  let database = database.as_ref();
  let database = database.unwrap();

  let mut app_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .find(doc! {})
    .await;

  if app_info.is_err() {
    return HttpResponse::Unauthorized().body("");
  }

  let mut app_list: Vec<CreatedApplication> = Vec::new();

  // Assume `app_info` is initially Some(value), otherwise handle the None case if necessary
  let mut app_info_unwrapped = app_info.unwrap();

  while app_info_unwrapped.advance().await.unwrap() {
    let document = app_info_unwrapped.current();
    
    let permissions = document
      .get("permissions")
      .unwrap();
    
    app_list.push(CreatedApplication {
      name: document.get("name").unwrap().unwrap().as_str().unwrap().to_string(),
      application_id: document.get("application_id").unwrap().unwrap().as_str().unwrap().to_string(),
      permissions: 
        if permissions.is_some() {
          permissions.unwrap().as_array().unwrap().into_iter().map(|x| x.unwrap().as_i32().unwrap_or(-1) as u8).collect()
        } else {
          Vec::new()
        }
    });
  }

  HttpResponse::Ok().json(json!({
    "applications": app_list
  }))
}

#[delete("/application/{id}")]
async fn delete_application(req: HttpRequest, document_id: web::Path<String>) -> impl Responder {
  let token = auth::get_bearer_token(req);

  if token.is_none() {
    return HttpResponse::Unauthorized().body("");
  }

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();
  
  let database = database.as_ref();
  let database = database.unwrap();

  let document_id = document_id.to_string();
  let app_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .delete_one(doc! {
      "application_id": document_id
    })
    .await;

  if app_info.is_err() {
    return HttpResponse::InternalServerError().json(json!({
      "error": "Internal Server Error",
      "message": "Failed to delete application"
    }));
  }

  HttpResponse::Ok().json(json!({
    "message": "Successfully deleted application"
  }))
}

#[post("/application/create")]
async fn create_application(req: HttpRequest, req_data: web::Json<CreateApplication>) -> impl Responder {
  let token = auth::get_bearer_token(req);
  let application_id = Uuid::new_v4();
   
  if token.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Invalid token."
    }))
  }

  if !req_data.permissions.iter().all(|x| PERMISSION.contains_key(x)) {
    return HttpResponse::BadRequest().json(json!({
      "error": "Invalid permissions",
      "message": format!("Permissions must be a subset of [0, 1, 2, 3]. Found: {:?}. Available: {:?}", req_data.permissions, PERMISSION.iter().map(|x| format!("{} {}", x.0, x.1)).collect::<Vec<String>>())
    }));
  }

  let application = ApplicationAuth {
    application_id: application_id.to_string(),
    name: req_data.name.to_string(),
    permissions: req_data.permissions.clone()
  };

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();
  
  let database = database.as_ref();
  let database = database.unwrap();

  info!("Creating application: {:?}", application);

  let app_created_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .insert_one(&application)
    .await;

  if app_created_info.is_ok() {
    return HttpResponse::Created().json(json!({
      "token": auth::create_application_token(application)
    }));
  }
  
  HttpResponse::Conflict().body("")
}

#[post("/data/write")]
async fn write_data(req: HttpRequest, req_data: web::Json<HashMap<String, Value>>) -> impl Responder {
  let token = auth::get_jwt_application_token(req);

  if token.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Invalid token. Please use JWT token for application, not your admin token"
    }));
  }

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();

  let database = database.as_ref();
  let database = database.unwrap();
  
  let app_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .find_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str()
    })
    .await;

  if app_info.is_err() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application can't be found"
    }));
  }

  let app_info = app_info.unwrap();

  if app_info.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application not found"
    }));
  }

  if !app_info.unwrap().permissions.contains(&0) {
    return HttpResponse::Forbidden().json(json!({
      "error": "Forbidden",
      "message": "You don't have permission to write data"
    }));
  }

  let row = InsertedData {
    application_id: token.as_ref().unwrap().get("application_id").unwrap().as_str().to_string(),
    time: Utc::now().timestamp_millis(),
    data: req_data.to_owned(),
    id: Uuid::new_v4().to_string(),
    updated_at: None,
    updated_history: Some(vec![]),
    version: 1
  };

  let insert_data = database
    .database("klerk")
    .collection::<InsertedData>("data")
    .insert_one(&row)
    .await;

  info!("Writing data: {:?}", insert_data);

  let active_connections = ACTIVE_SOCKET_CONNECTIONS.lock().unwrap().abs();

  if active_connections > 0 {
    INSERT_HISTORY.lock().unwrap().add(("insert".to_string(), row.id.clone())).unwrap();
  }

  HttpResponse::Created().json(json!({
    "message": "Data inserted successfully",
    "data": row
  }))
} 

#[get("/data/{id}")]
async fn read_data(req: HttpRequest, document_id: web::Path<String>) -> impl Responder {
  let token = auth::get_jwt_application_token(req);
 
  if token.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Invalid token. Please use JWT token for application, not your admin token"
    }));
  }

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();

  let document_id = document_id.to_string();

  let database = database.as_ref();
  let database = database.unwrap();
  
  let app_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .find_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
    })
    .await;

  if app_info.is_err() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application can't be found"
    }));
  }

  let app_info = app_info.unwrap();

  if app_info.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application not found"
    }));
  }

  if !app_info.unwrap().permissions.contains(&1) {
    return HttpResponse::Forbidden().json(json!({
      "error": "Forbidden",
      "message": "You don't have permission to read data"
    }));
  }

  let data = database
    .database("klerk")
    .collection::<InsertedData>("data")
    .find_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
      "id": document_id
    })
    .await;

  if data.is_err() {
    error!("Error reading data: {:?}", data.unwrap_err().to_string());

    return HttpResponse::NotFound().json(json!({
      "error": "Not found",
      "message": "Data not be found"
    }));
  }

  let data = data.unwrap();

  if data.is_none() {
    return HttpResponse::NotFound().json(json!({
      "error": "Not found",
      "message": "Data not found"
    }));
  }

  HttpResponse::Ok().json(json!({
    "message": "Data read successfully",
    "data": data
  }))
}

#[delete("/data/{id}")]
async fn delete_data(req: HttpRequest, document_id: web::Path<String>) -> impl Responder {
  let token = auth::get_jwt_application_token(req);
  
  if token.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Invalid token. Please use JWT token for application, not your admin token"
    }));
  }

  let document_id = document_id.to_string();

  if Uuid::try_parse(&document_id).is_err() {
    return HttpResponse::BadRequest().json(json!({
      "error": "Invalid document id",
      "message": "Document id must be a valid UUID"
    }));
  }

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();

  let database = database.as_ref();
  let database = database.unwrap();
  
  let app_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .find_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
    })
    .await;

  if app_info.is_err() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application can't be found"
    }));
  }

  let app_info = app_info.unwrap();

  if app_info.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application not found"
    }));
  }

  if !app_info.unwrap().permissions.contains(&3) {
    return HttpResponse::Forbidden().json(json!({
      "error": "Forbidden",
      "message": "You don't have permission to delete data"
    }));
  }

  let delete_data = database
    .database("klerk")
    .collection::<InsertedData>("data")
    .delete_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
      "id": &document_id
    })
    .await;

  if delete_data.is_err() {
    error!("Error deleting data: {:?}", delete_data.unwrap_err().to_string());

    return HttpResponse::NotFound().json(json!({
      "error": "Not found",
      "message": "Data cannot be deleted"
    }));
  }

  let active_connections = ACTIVE_SOCKET_CONNECTIONS.lock().unwrap().abs();

  if active_connections > 0 {
    INSERT_HISTORY.lock().unwrap().add(("delete".to_string(), document_id)).unwrap();
  }

  HttpResponse::Ok().json(json!({
    "message": "Data deleted successfully"
  }))
}

#[put("/data/{id}")]
async fn update_data(req: HttpRequest, document_id: web::Path<String>, req_data: web::Json<Document>) -> impl Responder {
  let token = auth::get_jwt_application_token(req);
  
  if token.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Invalid token. Please use JWT token for application, not your admin token"
    }));
  }
  
  let document_id = document_id.to_string();

  if Uuid::try_parse(&document_id).is_err() {
    return HttpResponse::BadRequest().json(json!({
      "error": "Invalid document id",
      "message": "Document id must be a valid UUID"
    }));
  }

  let database = DATABASE_CLIENT
    .lock()
    .unwrap();

  let database = database.as_ref();
  let database = database.unwrap();
  
  let app_info = database
    .database("klerk")
    .collection::<ApplicationAuth>("applications")
    .find_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
    })
    .await;

  if app_info.is_err() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application can't be found"
    }));
  }

  let app_info = app_info.unwrap();

  if app_info.is_none() {
    return HttpResponse::Unauthorized().json(json!({
      "error": "Unauthorized",
      "message": "Application not found"
    }));
  }

  if !app_info.unwrap().permissions.contains(&2) {
    return HttpResponse::Forbidden().json(json!({
      "error": "Forbidden",
      "message": "You don't have permission to update data"
    }));
  }

  let current_document = database
    .database("klerk")
    .collection::<InsertedData>("data")
    .find_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
      "id": &document_id
    })
    .await;

  if current_document.is_err() {
    error!("Error updating data: {:?}", current_document.unwrap_err().to_string());

    return HttpResponse::NotFound().json(json!({
      "error": "Not found",
      "message": "Data cannot be found"
    }));
  }

  let current_document = current_document.unwrap();

  if current_document.is_none() {
    return HttpResponse::NotFound().json(json!({
      "error": "Not found",
      "message": "Data not found"
    }));
  }

  let current_document = current_document.unwrap();
  let doc = req_data.to_string();
  let doc: HashMap<String, Value> = serde_json::from_str(&doc).unwrap();

  if doc == current_document.data {
    return HttpResponse::Conflict().json(json!({
      "message": "Data is already up to date"
    }));
  }

  let update_data = database
    .database("klerk")
    .collection::<InsertedData>("data")
    .update_one(doc! {
      "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
      "id": &document_id
    }, doc! {
      "$set": {
        "data": req_data.clone()
      },
      "$inc": {
        "version": 1
      }
    })
    .await;

  if update_data.is_err() {
    return HttpResponse::NotFound().json(json!({
      "error": "Not found",
      "message": "Data cannot be updated"
    }));
  }

  if std::env::var("DISABLED_HISTORY") != Ok(String::from("true")) {
    let record = (Utc::now().timestamp_millis(), req_data.clone());

    database
      .database("klerk")
      .collection::<InsertedData>("data")
      .update_one(
        doc! {
          "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
          "id": &document_id
        },
        doc! {
          "$set": {
            "updated_at": Utc::now().timestamp_millis(),
          },
          "$push": {
            "updated_history": {
              "updated_at": record.0,
              "data": record.1
            }
          }
        }
      )
      .await
      .unwrap();
  } else {
    database
      .database("klerk")
      .collection::<InsertedData>("data")
      .update_one(
        doc! {
          "application_id": token.as_ref().unwrap().get("application_id").unwrap().as_str(),
          "id": &document_id
        },
        doc! {
          "$set": {
            "updated_at": Utc::now().timestamp_millis(),
          }
        }
      )
      .await
      .unwrap();
  }

  info!("Updating data in document: {:?}", &document_id);

  let active_connections = ACTIVE_SOCKET_CONNECTIONS.lock().unwrap().abs();

  if active_connections > 0 {
    INSERT_HISTORY.lock().unwrap().add(("update".to_string(), document_id)).unwrap();
  } else {
    drop(document_id);
  }

  HttpResponse::Ok().json(json!({
    "message": "Data updated successfully"
  }))
}

fn add_error_header<B>(mut res: dev::ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>, actix_web::Error> {
  res.response_mut().headers_mut().insert(
    header::CONTENT_TYPE, 
    header::HeaderValue::from_static("application/json; charset=utf-8")
  );

  Ok(ErrorHandlerResponse::Response(res.map_into_left_body()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  dotenv().ok();

  info!("Starting server...");
  let db_uri = std::env::var("MONGODB_URI").unwrap();
  let spawner = ClientOptions::parse(db_uri.as_str()).await.unwrap();
  let client = Client::with_options(spawner).unwrap();
  let mut database = DATABASE_CLIENT.lock().unwrap();

  info!("Connecting to database at '{}'...", db_uri.as_str());
  info!("Creating database client...");
  *database = Some(client.to_owned());

  drop(database);
  drop(client);

  let server = HttpServer::new(|| {
    let error_wrapper = ErrorHandlers::new()
      .handler(StatusCode::INTERNAL_SERVER_ERROR, add_error_header);

    // create cookie based session middleware
    let session_wrapper = SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
        .cookie_secure(false)
        .build();

    let application = App::new()
      .wrap(middleware::DefaultHeaders::new().add(("X-Version", "0.0.1")).add(("X-Engine", "klerk")))
      .wrap(error_wrapper)
      .wrap(session_wrapper)
      .route("/emitter", web::get().to(realtime_emitter))
      .service(read_data)
      .service(write_data)
      .service(delete_data)
      .service(update_data)
      .service(get_applications)
      .service(delete_application)
      .service(create_application);
    
    application
  });

  let address = (
    std::env::var("HOST").unwrap_or("127.0.0.1".to_string()),
    std::env::var("PORT").unwrap_or("12701".to_string()).parse::<u16>().unwrap()
  );

  // let key = auth::create_application_token(
  //   ApplicationAuth {
  //     application_id: String::from("hey")
  //   }
  // );
  // 
  // info!("Application token: {}", key);

  info!("Spawning server at http://{}:{}...", address.0, address.1);
  info!("Welcome to Klerk!");
  info!("For admin routes use admin token: '{}'", ADMIN_TOKEN.as_str());
  
  let _ = server
    .bind(address)?
    .run()
    .await;

  info!("Server stopped");

  Ok(())
}