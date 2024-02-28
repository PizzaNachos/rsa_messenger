mod server;
mod types;

#[tokio::main]
async fn main() {
    env_logger::init();
    server::start_server().await.expect("What");
}
