use once_cell::sync::OnceCell;
use std::env;

static INIT_DOTENV: OnceCell<()> = OnceCell::new();

/// Ensures that the dotenv file is loaded into the environment variables.
///
/// This function checks if the dotenv file has already been loaded using a `OnceCell`.
/// If not, it attempts to load the dotenv file specified by the first command line argument.
/// If no argument is provided, it defaults to loading a file named ".env".
///
/// # Parameters
///
/// This function does not take any parameters.
///
/// # Return
///
/// This function does not return any value. It ensures that the environment variables
/// from the dotenv file are loaded into the process's environment.
pub fn ensure_dotenv_loaded() -> String {
    let dotenv_path = env::args().nth(1).unwrap_or_else(|| ".env".to_string());
    INIT_DOTENV.get_or_init(|| {
        dotenv::from_filename(&dotenv_path).ok();
    });
    dotenv_path
}
