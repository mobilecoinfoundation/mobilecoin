use rocket::get;

/// temp index route
#[get("/")]
pub fn index() -> &'static str {
    "Hello, world!"
}

/// temp cat route
#[get("/cat")]
pub fn cat() -> &'static str {
    "meow"
}
