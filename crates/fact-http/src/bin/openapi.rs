fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec = fact_http::openapi_spec();
    serde_json::to_writer_pretty(std::io::stdout(), &spec)?;
    println!();
    Ok(())
}
